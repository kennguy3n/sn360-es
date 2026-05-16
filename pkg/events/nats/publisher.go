package nats

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// Publisher publishes events to JetStream with retries, dedup, and structured
// headers. It is safe for concurrent use.
type Publisher struct {
	client *Client
	cfg    Config
	source string
}

// NewPublisher returns a Publisher tied to client. The optional source label
// is embedded in every published message header.
func NewPublisher(client *Client, source string) *Publisher {
	return &Publisher{client: client, cfg: client.cfg, source: source}
}

// Publish sends data on subject. It applies retries, dedup IDs, and the
// common SN360-ES headers (correlation/tenant/event-type/source).
func (p *Publisher) Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	if subject == "" {
		return errors.New("nats: subject required")
	}
	resolved := events.ResolvePublishOptions(events.PublishOptions{
		MaxRetries: p.cfg.PublishRetryAttempts,
		RetryDelay: p.cfg.PublishRetryDelay,
		Timeout:    p.cfg.RequestTimeout,
	}, opts...)

	msg := &nats.Msg{
		Subject: subject,
		Data:    data,
		Header:  nats.Header{},
	}

	// Auto-generate a message ID if the caller did not. Dedup at the stream
	// level depends on this header.
	if resolved.MessageID == "" {
		resolved.MessageID = uuid.NewString()
	}
	msg.Header.Set(jetstream.MsgIDHeader, resolved.MessageID)
	msg.Header.Set(events.HeaderMessageID, resolved.MessageID)

	if resolved.CorrelationID != "" {
		msg.Header.Set(events.HeaderCorrelationID, resolved.CorrelationID)
	}
	if resolved.TenantID != "" {
		msg.Header.Set(events.HeaderTenantID, resolved.TenantID)
	}
	if resolved.EventType != "" {
		msg.Header.Set(events.HeaderEventType, resolved.EventType)
	}
	if p.source != "" {
		msg.Header.Set(events.HeaderSource, p.source)
	}
	msg.Header.Set(events.HeaderEnqueuedAt, time.Now().UTC().Format(time.RFC3339Nano))
	for k, v := range resolved.Headers {
		msg.Header.Set(k, v)
	}

	js := p.client.JetStream()
	if js == nil {
		return errors.New("nats: jetstream not connected")
	}

	maxAttempts := resolved.MaxRetries
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	delay := resolved.RetryDelay
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		callCtx := ctx
		if resolved.Timeout > 0 {
			var cancel context.CancelFunc
			callCtx, cancel = context.WithTimeout(ctx, resolved.Timeout)
			_, err := js.PublishMsg(callCtx, msg, jetstream.WithMsgID(resolved.MessageID))
			cancel()
			if err == nil {
				return nil
			}
			lastErr = err
		} else {
			_, err := js.PublishMsg(callCtx, msg, jetstream.WithMsgID(resolved.MessageID))
			if err == nil {
				return nil
			}
			lastErr = err
		}

		// Don't retry context errors or fatal subject mismatches.
		if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
			return lastErr
		}
		if errors.Is(lastErr, jetstream.ErrNoStreamResponse) {
			return lastErr
		}

		if attempt < maxAttempts {
			sleep := delay * time.Duration(1<<(attempt-1))
			timer := time.NewTimer(sleep)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}

	return fmt.Errorf("nats: publish %s: %w", subject, lastErr)
}

// PublishToDLQ republishes msg's payload onto the conventional DLQ subject,
// preserving headers and adding HeaderError + HeaderDeliveryCount metadata.
func (p *Publisher) PublishToDLQ(ctx context.Context, dlqSubject string, data []byte, headers map[string]string, delivery uint64, cause error) error {
	publishOpts := []events.PublishOption{}
	if mid, ok := headers[events.HeaderMessageID]; ok && mid != "" {
		// Re-use the original message ID so DLQ retries don't duplicate.
		publishOpts = append(publishOpts, events.WithMessageID("dlq-"+mid))
	}
	if cid, ok := headers[events.HeaderCorrelationID]; ok {
		publishOpts = append(publishOpts, events.WithCorrelationID(cid))
	}
	if tid, ok := headers[events.HeaderTenantID]; ok {
		publishOpts = append(publishOpts, events.WithTenantID(tid))
	}
	if et, ok := headers[events.HeaderEventType]; ok {
		publishOpts = append(publishOpts, events.WithEventType(et))
	}
	if origin, ok := headers[events.HeaderOriginSubject]; ok && origin != "" {
		publishOpts = append(publishOpts, events.WithHeader(events.HeaderOriginSubject, origin))
	} else {
		// Without an explicit origin, treat the failed subject as the origin.
		publishOpts = append(publishOpts, events.WithHeader(events.HeaderOriginSubject, dlqSubject))
	}
	publishOpts = append(publishOpts, events.WithHeader(events.HeaderDeliveryCount, strconv.FormatUint(delivery, 10)))
	if cause != nil {
		publishOpts = append(publishOpts, events.WithHeader(events.HeaderError, cause.Error()))
	}
	return p.Publish(ctx, dlqSubject, data, publishOpts...)
}
