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

	c := &Consumer{
		client:      client,
		stream:      stream,
		subject:     subject,
		durable:     resolved.Durable,
		opts:        resolved,
		handler:     handler,
		dlqProducer: dlq,
		logger:      logger.With(slog.String("stream", stream), slog.String("durable", resolved.Durable)),
		cons:        cons,
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
func (c *Consumer) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	if c.cc != nil {
		c.cc.Stop()
	}
	c.wg.Wait()
	return nil
}

// dispatch is called by the JetStream library for every delivery.
func (c *Consumer) dispatch(jm jetstream.Msg) {
	c.wg.Add(1)
	defer c.wg.Done()

	msg := &message{raw: jm}

	// Detect the very last allowable delivery so we route to DLQ ourselves
	// rather than relying on the JetStream advisory subjects (which require
	// an additional listener and complicate testing).
	meta, _ := jm.Metadata()
	delivery := uint64(0)
	if meta != nil {
		delivery = meta.NumDelivered
	}

	ctx := contextFromMessage(msg)
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

// contextFromMessage embeds the message's correlation ID etc. into a context
// used by the handler. Right now we just pass through the background ctx;
// future telemetry middleware will replace this.
func contextFromMessage(_ events.Message) context.Context {
	return context.Background()
}

// --- message adapter --------------------------------------------------------

type message struct {
	raw      jetstream.Msg
	terminal bool
}

func (m *message) Data() []byte     { return m.raw.Data() }
func (m *message) Subject() string  { return m.raw.Subject() }

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
