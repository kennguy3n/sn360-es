// Package service hosts higher-level services that compose the pkg/ libraries
// into business operations. This file contains the DLQ processor — a long-
// running consumer that watches the dead-letter stream, logs / counts each
// failed message, and optionally retries it through the regular event bus.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// Action is the disposition the DLQProcessor applies to a failed message.
type Action string

const (
	// ActionLogOnly records the failure but does not retry.
	ActionLogOnly Action = "log_only"
	// ActionRetry republishes the message on its original subject (subject
	// to a max-attempt count carried in the message headers).
	ActionRetry Action = "retry"
	// ActionDrop silently acks the message — used for known-bad payloads.
	ActionDrop Action = "drop"
)

// maxRetryBackoff caps the synchronous time.After wait in retry().
// The Decider field Backoff is honoured up to this ceiling so a
// misconfigured policy (e.g. Backoff: 30*time.Minute on a
// transient-rate-limit decision) cannot pin a DLQ dispatch
// goroutine for an extended period. With a small worker pool, even
// a handful of long-Backoff messages is enough to starve every
// dispatch slot and stop the DLQ consumer from acking anything.
//
// 5s is generous enough for the typical upstream-recovery window
// (rspamd flap, tier1 502, etc.) and short enough that pool
// starvation under load is bounded.
const maxRetryBackoff = 5 * time.Second

// Decision is the per-message verdict from a Decider.
type Decision struct {
	Action  Action
	Reason  string
	Backoff time.Duration
}

// Decider lets callers plug in custom DLQ handling policy. The default is
// always ActionLogOnly which is safe in dev.
type Decider interface {
	Decide(ctx context.Context, msg events.Message) Decision
}

// DeciderFunc is a function adapter for Decider.
type DeciderFunc func(ctx context.Context, msg events.Message) Decision

// Decide implements Decider.
func (f DeciderFunc) Decide(ctx context.Context, msg events.Message) Decision {
	return f(ctx, msg)
}

// Republisher is the contract the processor needs to retry a message. The
// concrete pkg/events.EventService implementation satisfies it.
type Republisher interface {
	Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error
}

// DLQProcessorConfig configures a DLQProcessor.
type DLQProcessorConfig struct {
	// Subjects names the DLQ subject(s) to subscribe to. Defaults to the
	// canonical SN360 DLQ subjects when empty.
	Subjects []string
	// Bus is the event bus instance both subscribed-to and (optionally)
	// republished-to.
	Bus events.EventService
	// Decider is invoked once per message; required.
	Decider Decider
	// Republisher is required only if any decision returns ActionRetry.
	Republisher Republisher
	// MaxRetryAttempts caps how many times a message can be retried before
	// the processor force-acks it. The attempt counter is carried in the
	// HeaderDeliveryCount header.
	MaxRetryAttempts int
	// Group is the durable consumer name to use. Defaults to "dlq-processor".
	Group string
	// Logger is used for structured logging. Defaults to slog.Default.
	Logger *slog.Logger
}

// DefaultSubjects names the DLQ subjects the processor watches by default.
// Dead-letter subjects live under "es.dlq.<domain>" so the DLQ stream's
// subject filter (es.dlq.>) does not overlap with the primary streams'
// wildcards (es.evaluate.>, es.action.>, es.onboarding.>).
var DefaultSubjects = []string{
	"es.dlq.evaluate",
	"es.dlq.action",
	"es.dlq.onboarding",
}

// DLQProcessor consumes the ES_DLQ stream and applies the configured
// disposition (log, retry, drop) to each failed message.
type DLQProcessor struct {
	cfg  DLQProcessorConfig
	log  *slog.Logger
	subs []events.Subscription

	totalSeen    atomic.Uint64
	totalRetried atomic.Uint64
	totalLogged  atomic.Uint64
	totalDropped atomic.Uint64
}

// NewDLQProcessor constructs a processor. It does not subscribe; call Start
// for that.
func NewDLQProcessor(cfg DLQProcessorConfig) (*DLQProcessor, error) {
	if cfg.Bus == nil {
		return nil, errors.New("dlq: event bus is required")
	}
	if cfg.Decider == nil {
		return nil, errors.New("dlq: decider is required")
	}
	if cfg.MaxRetryAttempts <= 0 {
		cfg.MaxRetryAttempts = 3
	}
	if cfg.Group == "" {
		cfg.Group = "dlq-processor"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if len(cfg.Subjects) == 0 {
		cfg.Subjects = append([]string{}, DefaultSubjects...)
	}
	return &DLQProcessor{cfg: cfg, log: cfg.Logger}, nil
}

// Start subscribes to all configured DLQ subjects. The returned context is
// cancelled when Stop is called.
func (p *DLQProcessor) Start(ctx context.Context) error {
	for _, subj := range p.cfg.Subjects {
		sub, err := p.cfg.Bus.Subscribe(ctx, subj, p.handle,
			events.WithDurable(p.cfg.Group),
			events.WithMaxDeliver(p.cfg.MaxRetryAttempts+1),
		)
		if err != nil {
			// Best-effort: close any subs we already created.
			// Log closure failures rather than swallowing them
			// silently so an operator can spot a stuck unsubscribe
			// even when the original subscribe error is what
			// surfaces to the caller.
			if cerr := p.closeAll(); cerr != nil && p.log != nil {
				p.log.Warn("dlq: best-effort close after subscribe failure",
					slog.Any("error", cerr))
			}
			return fmt.Errorf("dlq: subscribe %q: %w", subj, err)
		}
		p.subs = append(p.subs, sub)
	}
	return nil
}

// Stop closes all active subscriptions and waits for in-flight handlers.
func (p *DLQProcessor) Stop() error {
	return p.closeAll()
}

// Metrics returns a snapshot of the cumulative DLQ counters.
type Metrics struct {
	TotalSeen    uint64
	TotalRetried uint64
	TotalLogged  uint64
	TotalDropped uint64
}

// Metrics returns the cumulative counters.
func (p *DLQProcessor) Metrics() Metrics {
	return Metrics{
		TotalSeen:    p.totalSeen.Load(),
		TotalRetried: p.totalRetried.Load(),
		TotalLogged:  p.totalLogged.Load(),
		TotalDropped: p.totalDropped.Load(),
	}
}

// handle is the MessageHandler bound to every DLQ subject.
func (p *DLQProcessor) handle(ctx context.Context, msg events.Message) error {
	p.totalSeen.Add(1)
	dec := p.cfg.Decider.Decide(ctx, msg)
	switch dec.Action {
	case ActionRetry:
		return p.retry(ctx, msg, dec)
	case ActionDrop:
		p.totalDropped.Add(1)
		p.log.Info("dlq: drop", slog.String("reason", dec.Reason), slog.String("subject", msg.Subject()))
		return msg.Ack()
	case ActionLogOnly, "":
		p.totalLogged.Add(1)
		meta, _ := msg.Metadata()
		p.log.Warn("dlq: failed message",
			slog.String("subject", msg.Subject()),
			slog.String("message_id", meta.MessageID),
			slog.String("correlation_id", meta.CorrelationID),
			slog.String("tenant_id", meta.TenantID),
			slog.String("error", msg.Headers()[events.HeaderError]),
			slog.Int("delivery_count", int(meta.NumDelivered)),
			slog.String("reason", dec.Reason),
		)
		return msg.Ack()
	default:
		return fmt.Errorf("dlq: unknown decision action %q", dec.Action)
	}
}

// retry republishes msg onto its origin subject through Republisher.
func (p *DLQProcessor) retry(ctx context.Context, msg events.Message, dec Decision) error {
	if p.cfg.Republisher == nil {
		return errors.New("dlq: cannot retry without Republisher")
	}
	headers := msg.Headers()
	origin := headers[events.HeaderOriginSubject]
	if origin == "" {
		// Without an origin we have nowhere to republish — fall back to log.
		p.totalLogged.Add(1)
		return msg.Ack()
	}
	attempt, _ := strconv.Atoi(headers[events.HeaderDeliveryCount])
	if attempt >= p.cfg.MaxRetryAttempts {
		p.log.Warn("dlq: retry attempts exhausted",
			slog.String("origin", origin),
			slog.Int("attempt", attempt),
			slog.String("reason", dec.Reason))
		p.totalDropped.Add(1)
		return msg.Ack()
	}

	if dec.Backoff > 0 {
		// Block before publishing so the upstream gets a backoff
		// window. The wait is intentionally synchronous so the
		// retry is delivered exactly once per call (no fire-and-
		// forget goroutine that can lose the retry on a crash),
		// but it's capped at maxRetryBackoff so a misconfigured
		// Decider can never stall a consumer dispatch goroutine
		// for minutes at a time — which under load is enough to
		// starve the entire DLQ consumer.
		backoff := dec.Backoff
		if backoff > maxRetryBackoff {
			backoff = maxRetryBackoff
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	opts := []events.PublishOption{
		events.WithHeader(events.HeaderDeliveryCount, strconv.Itoa(attempt+1)),
		events.WithHeader("Retry-Reason", dec.Reason),
	}
	for k, v := range headers {
		switch k {
		case events.HeaderMessageID, events.HeaderError,
			events.HeaderDeliveryCount, events.HeaderOriginSubject:
			continue
		}
		opts = append(opts, events.WithHeader(k, v))
	}
	if err := p.cfg.Republisher.Publish(ctx, origin, msg.Data(), opts...); err != nil {
		return fmt.Errorf("dlq: republish %q: %w", origin, err)
	}
	p.totalRetried.Add(1)
	p.log.Info("dlq: retried",
		slog.String("origin", origin),
		slog.Int("attempt", attempt+1),
		slog.String("reason", dec.Reason))
	return msg.Ack()
}

func (p *DLQProcessor) closeAll() error {
	var (
		wg   sync.WaitGroup
		errs []error
		mu   sync.Mutex
	)
	for _, s := range p.subs {
		wg.Add(1)
		sub := s
		go func() {
			defer wg.Done()
			if err := sub.Close(); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	p.subs = nil
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
