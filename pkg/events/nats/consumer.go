package nats

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// MessageObserver receives per-delivery observability hooks. It is
// invoked by the Consumer after a message is decoded but before the
// handler runs, so the callback can emit consumer-lag metrics, log
// structured delivery records, etc.
//
// Implementations must be safe for concurrent use and must not block
// (the consumer dispatch loop runs synchronously).
type MessageObserver func(stream, subject string, lag time.Duration)

// Consumer wraps a JetStream durable consumer plus a long-running goroutine
// that drives a MessageHandler. It implements events.Subscription.
type Consumer struct {
	client      *Client
	stream      string
	subject     string
	durable     string
	opts        events.SubscribeOptions
	handler     events.MessageHandler
	dlqProducer DLQProducer
	logger      *slog.Logger

	// parentCtx is the long-lived root context used to derive each
	// handler invocation. It is cancelled by Close so in-flight
	// handlers can observe shutdown and abort cleanly. Distinct from
	// the short-lived ctx passed to NewConsumer (which only governs
	// the CreateOrUpdateConsumer setup call).
	parentCtx    context.Context
	parentCancel context.CancelFunc

	observer MessageObserver

	cons jetstream.Consumer
	cc   jetstream.ConsumeContext

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// DLQProducer is implemented by anything that can republish a message onto
// the dead-letter subject. The default Publisher implements this.
type DLQProducer interface {
	PublishToDLQ(ctx context.Context, dlqSubject string, data []byte, headers map[string]string, delivery uint64, cause error) error
}

// NewConsumer creates and starts a durable JetStream consumer.
//
// The subject must already be covered by a stream (see EnsureStream). The
// caller passes the resolved options struct; defaults are not re-applied.
//
// To attach an observer (e.g. for consumer-lag metrics), use
// NewConsumerWithObserver instead.
func NewConsumer(
	ctx context.Context,
	client *Client,
	stream string,
	subject string,
	handler events.MessageHandler,
	dlq DLQProducer,
	resolved events.SubscribeOptions,
	logger *slog.Logger,
) (*Consumer, error) {
	return NewConsumerWithObserver(ctx, client, stream, subject, handler, dlq, resolved, logger, nil)
}

// NewConsumerWithObserver is like NewConsumer but also wires a
// MessageObserver invoked on every successful dispatch. A nil
// observer is equivalent to NewConsumer.
func NewConsumerWithObserver(
	ctx context.Context,
	client *Client,
	stream string,
	subject string,
	handler events.MessageHandler,
	dlq DLQProducer,
	resolved events.SubscribeOptions,
	logger *slog.Logger,
	observer MessageObserver,
) (*Consumer, error) {
	if client == nil {
		return nil, errors.New("nats: client is required")
	}
	if handler == nil {
		return nil, errors.New("nats: handler is required")
	}
	if resolved.Durable == "" {
		return nil, errors.New("nats: durable consumer name is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	js := client.JetStream()
	if js == nil {
		return nil, errors.New("nats: jetstream not connected")
	}

	maxDeliver := resolved.MaxDeliver
	if maxDeliver <= 0 {
		// 0 = unlimited in JetStream; -1 normalises to "no DLQ trigger".
		maxDeliver = -1
	}

	cfg := jetstream.ConsumerConfig{
		Name:          resolved.Durable,
		Durable:       resolved.Durable,
		FilterSubject: pickFilter(subject, resolved.FilterSubject),
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       orDefault(resolved.AckWait, 30*time.Second),
		MaxDeliver:    maxDeliver,
		MaxAckPending: orDefault(resolved.MaxAckPending, 256),
		DeliverPolicy: jetstream.DeliverAllPolicy,
		Description:   "SN360-ES consumer for " + subject,
	}

	cons, err := js.CreateOrUpdateConsumer(ctx, stream, cfg)
	if err != nil {
		return nil, fmt.Errorf("nats: create consumer %s on %s: %w", resolved.Durable, stream, err)
	}

	// Build a dedicated parent context for dispatch. It deliberately
	// does NOT chain off `ctx` because callers cancel ctx after
	// NewConsumer returns; the dispatch loop must outlive that.
	parentCtx, parentCancel := context.WithCancel(context.Background())

	c := &Consumer{
		client:       client,
		stream:       stream,
		subject:      subject,
		durable:      resolved.Durable,
		opts:         resolved,
		handler:      handler,
		dlqProducer:  dlq,
		logger:       logger.With(slog.String("stream", stream), slog.String("durable", resolved.Durable)),
		parentCtx:    parentCtx,
		parentCancel: parentCancel,
		observer:     observer,
		cons:         cons,
	}

	cc, err := cons.Consume(c.dispatch,
		jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
			c.logger.Error("nats: consume error", slog.Any("error", err))
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("nats: start consume: %w", err)
	}
	c.cc = cc

	return c, nil
}

func pickFilter(subject, override string) string {
	if override != "" {
		return override
	}
	return subject
}

// Subject implements events.Subscription.
func (c *Consumer) Subject() string { return c.subject }

// Close stops delivery and waits for in-flight handlers.
//
// Order matters for correctness:
//
//  1. Flip the `closed` flag under the mutex. Dispatch invocations
//     entering after this point check the flag (also under the
//     mutex) and return immediately without calling wg.Add — so
//     wg.Wait below cannot race with a late dispatch incrementing
//     the counter from zero after wg.Wait has already returned.
//  2. parentCancel signals in-flight handlers (whose ctx chains
//     off parentCtx) that shutdown is in progress so they can
//     abort cleanly.
//  3. cc.Stop tells the JetStream library to stop scheduling new
//     dispatch callbacks. After Stop returns, the library still
//     drains any callbacks already in flight; that is what wg.Wait
//     blocks on.
//  4. wg.Wait blocks until every dispatch that had passed the
//     closed-check (and therefore called wg.Add(1)) has returned.
func (c *Consumer) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	if c.parentCancel != nil {
		c.parentCancel()
	}
	if c.cc != nil {
		c.cc.Stop()
	}
	c.wg.Wait()
	return nil
}

// dispatch is called by the JetStream library for every delivery.
//
// The closed-check and wg.Add must happen atomically under c.mu so
// Close() cannot observe a wg.Wait that returns prematurely. The
// JetStream library invokes dispatch from its own goroutine pool, so
// without this guard the sequence (a) library invokes dispatch,
// (b) Close sets closed=true and calls wg.Wait, (c) dispatch then
// calls wg.Add(1) is observable: wg.Wait returns zero while a
// handler is still running.
func (c *Consumer) dispatch(jm jetstream.Msg) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		// The consumer is shutting down. Don't ack — JetStream
		// will redeliver after AckWait expires and the new
		// owner / next session can pick the message up.
		return
	}
	c.wg.Add(1)
	c.mu.Unlock()
	defer c.wg.Done()

	msg := &message{raw: jm}

	// Detect the very last allowable delivery so we route to DLQ ourselves
	// rather than relying on the JetStream advisory subjects (which require
	// an additional listener and complicate testing).
	meta, _ := jm.Metadata()
	delivery := uint64(0)
	var msgTimestamp time.Time
	if meta != nil {
		delivery = meta.NumDelivered
		msgTimestamp = meta.Timestamp
	}

	// Consumer-lag observation: how long the message was sitting on the
	// stream before this consumer picked it up. Emitted before the
	// handler runs so the metric reflects bus latency, not handler
	// latency.
	if c.observer != nil && !msgTimestamp.IsZero() {
		c.observer(c.stream, jm.Subject(), time.Since(msgTimestamp))
	}

	ctx := c.contextFromMessage(msg)
	err := c.handler(ctx, msg)
	if err == nil {
		// Handler is responsible for explicit Ack inside, but most handlers
		// expect us to ack on a nil return.
		if !msg.terminal {
			if ackErr := jm.Ack(); ackErr != nil {
				c.logger.Warn("nats: ack failed",
					slog.Any("error", ackErr),
					slog.String("subject", jm.Subject()))
			}
		}
		return
	}

	// Handler returned an error - decide whether to DLQ or nak for retry.
	if c.opts.MaxDeliver > 0 && int(delivery) >= c.opts.MaxDeliver {
		c.routeToDLQ(ctx, jm, delivery, err)
		return
	}

	// Always negatively-ack so the message is redelivered. We use ackWait
	// scaled by delivery count for a gentle backoff.
	backoff := orDefault(c.opts.AckWait, 30*time.Second) * time.Duration(delivery)
	if nakErr := jm.NakWithDelay(backoff); nakErr != nil {
		c.logger.Warn("nats: nak failed",
			slog.Any("error", nakErr),
			slog.String("subject", jm.Subject()))
	}
}

func (c *Consumer) routeToDLQ(ctx context.Context, jm jetstream.Msg, delivery uint64, cause error) {
	dlqSubject := c.opts.DLQSubject
	if dlqSubject == "" {
		dlqSubject = defaultDLQSubject(jm.Subject())
	}

	if c.dlqProducer != nil {
		hdrs := map[string]string{}
		for k, vs := range jm.Headers() {
			if len(vs) > 0 {
				hdrs[k] = vs[0]
			}
		}
		if err := c.dlqProducer.PublishToDLQ(ctx, dlqSubject, jm.Data(), hdrs, delivery, cause); err != nil {
			c.logger.Error("nats: DLQ publish failed",
				slog.Any("error", err),
				slog.String("dlq_subject", dlqSubject),
				slog.String("origin_subject", jm.Subject()))
			// Don't ack so JetStream keeps trying.
			_ = jm.NakWithDelay(orDefault(c.opts.AckWait, 30*time.Second))
			return
		}
	} else {
		c.logger.Error("nats: no DLQ producer configured; message will be terminated",
			slog.String("dlq_subject", dlqSubject),
			slog.String("origin_subject", jm.Subject()),
			slog.Any("cause", cause))
	}

	// Terminate the message from the original stream so we don't loop.
	if err := jm.TermWithReason(cause.Error()); err != nil {
		c.logger.Warn("nats: term failed", slog.Any("error", err))
	}
}

func defaultDLQSubject(subject string) string {
	parts := splitFirstSegment(subject)
	if parts == "" {
		return subject + ".dlq"
	}
	return parts + ".dlq"
}

// splitFirstSegment returns "es.evaluate" for "es.evaluate.request" so we can
// produce stable DLQ subjects without per-event proliferation.
func splitFirstSegment(subject string) string {
	count := 0
	for i := 0; i < len(subject); i++ {
		if subject[i] == '.' {
			count++
			if count == 2 {
				return subject[:i]
			}
		}
	}
	return ""
}

// contextFromMessage derives a per-delivery context from the
// Consumer's parent context, then attaches the well-known bus
// identifiers (correlation, tenant, message, event-type) and the
// W3C Trace Context propagated through traceparent/tracestate
// headers. Handlers can therefore:
//
//  1. Observe shutdown via ctx.Done() because the context chains off
//     c.parentCtx, which Close cancels.
//  2. Read identifiers via events.CorrelationIDFromContext etc.
//     without re-parsing headers on every call site.
//  3. Start child spans that link back to the publisher's span,
//     completing distributed traces across the bus.
//
// If the message has no traceparent header, the returned context is
// effectively just parentCtx + value bag — no synthetic span is
// fabricated.
func (c *Consumer) contextFromMessage(msg events.Message) context.Context {
	parent := c.parentCtx
	if parent == nil {
		parent = context.Background()
	}
	headers := msg.Headers()

	ctx := parent
	if v := headers[events.HeaderCorrelationID]; v != "" {
		ctx = events.WithCorrelationIDContext(ctx, v)
	}
	if v := headers[events.HeaderTenantID]; v != "" {
		ctx = events.WithTenantIDContext(ctx, v)
	}
	if v := headers[events.HeaderMessageID]; v != "" {
		ctx = events.WithMessageIDContext(ctx, v)
	}
	if v := headers[events.HeaderEventType]; v != "" {
		ctx = events.WithEventTypeContext(ctx, v)
	}
	// Reconstruct the W3C trace context (if any) on top of the
	// values we just stamped. Returns parent unchanged when
	// headers carry no traceparent.
	return events.ExtractTraceContext(ctx, headers)
}

// --- message adapter --------------------------------------------------------

type message struct {
	raw      jetstream.Msg
	terminal bool
}

func (m *message) Data() []byte    { return m.raw.Data() }
func (m *message) Subject() string { return m.raw.Subject() }

func (m *message) Headers() map[string]string {
	out := map[string]string{}
	for k, vs := range m.raw.Headers() {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

func (m *message) Ack() error {
	m.terminal = true
	return m.raw.Ack()
}

func (m *message) Nak(delay time.Duration) error {
	m.terminal = true
	if delay <= 0 {
		return m.raw.Nak()
	}
	return m.raw.NakWithDelay(delay)
}

func (m *message) Metadata() (events.MessageMetadata, error) {
	md, err := m.raw.Metadata()
	if err != nil {
		return events.MessageMetadata{}, err
	}
	headers := m.Headers()
	out := events.MessageMetadata{
		Subject:       m.raw.Subject(),
		MessageID:     headers[events.HeaderMessageID],
		CorrelationID: headers[events.HeaderCorrelationID],
		TenantID:      headers[events.HeaderTenantID],
		EventType:     headers[events.HeaderEventType],
		Source:        headers[events.HeaderSource],
		NumDelivered:  md.NumDelivered,
		Stream:        md.Stream,
		Consumer:      md.Consumer,
		Sequence:      md.Sequence.Stream,
		Timestamp:     md.Timestamp,
	}
	if v := headers[events.HeaderDeliveryCount]; v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			// Prefer header (set on DLQ replays) over server-side counter.
			out.NumDelivered = n
		}
	}
	return out, nil
}
