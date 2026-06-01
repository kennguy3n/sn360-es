package nats

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/events/schema"
)

// Publisher publishes events to JetStream with retries, dedup, and structured
// headers. It is safe for concurrent use.
type Publisher struct {
	client    *Client
	cfg       Config
	source    string
	validator *schema.Validator
	// onSchemaMismatch fires once per rejected publish so the
	// caller can increment the `nats_schema_mismatch_total`
	// counter and emit a structured warning. nil is a no-op.
	onSchemaMismatch func(subject string, result schema.Result)
}

// NewPublisher returns a Publisher tied to client. The optional source label
// is embedded in every published message header.
func NewPublisher(client *Client, source string) *Publisher {
	return &Publisher{client: client, cfg: client.cfg, source: source}
}

// WithSchemaValidator binds a SchemaValidator to the publisher. The
// validator runs against every payload after the v1 stamp pass
// (see [Publisher.Publish]). A nil validator disables the
// validation pass and restores pre-WS-7c behaviour.
func (p *Publisher) WithSchemaValidator(v *schema.Validator) *Publisher {
	p.validator = v
	return p
}

// WithSchemaMismatchHook registers a callback fired once per
// rejected publish. The hook receives the subject and the
// mismatch result so the caller can update Prometheus counters
// without coupling the publisher package to telemetry.
func (p *Publisher) WithSchemaMismatchHook(fn func(subject string, result schema.Result)) *Publisher {
	p.onSchemaMismatch = fn
	return p
}

// Publish sends data on subject. It applies retries, dedup IDs, and the
// common SN360-ES headers (correlation/tenant/event-type/source).
//
// Schema validation (WS-7c): when a SchemaValidator is bound via
// [Publisher.WithSchemaValidator], every payload runs through it
// before the broker call:
//
//  1. If the subject has a registered schema and the payload is
//     missing `schema_version`, the publisher stamps the
//     canonical v1 value into the payload bytes. The wire format
//     is always self-describing regardless of which producer
//     omitted the field.
//  2. If the resolved (subject, version) does not match any
//     registered schema, OR the payload fails the version's
//     shape check, Publish returns a *schema.ValidationError
//     wrapped so callers can `errors.As` it. The broker call is
//     NOT made — the validator is the gatekeeper documented in
//     ARCHITECTURE.md §3 (BatchMessage vs flat EvaluateRequest
//     class of bug).
//
// Publishes onto subjects matching the schema-DLQ prefix
// (`sn360.dlq.schema.>`) and onto subjects with no registered
// schema bypass validation — see DLQSubjectPrefix in
// pkg/events/schema for the contract.
func (p *Publisher) Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	if subject == "" {
		return errors.New("nats: subject required")
	}

	// WS-7c: enforce schema-versioning on the publish path. The
	// stamp+validate pass is a single-pass per Publish call and
	// is cheap (PeekVersion is ~1us; Stamp adds ~10-30us on
	// payloads that need it).
	if p.validator != nil && !strings.HasPrefix(subject, schema.DLQSubjectPrefix+".") {
		if family := p.validator.SubjectFamily(subject); family != "" {
			stamped, _, stampErr := schema.Stamp(data, schema.SchemaVersionV1)
			if stampErr == nil {
				data = stamped
			}
			// stampErr != nil means the payload was not a JSON
			// object — let the validator surface the precise
			// reason. The downstream validator MAY accept
			// non-JSON payloads for some subjects (none do
			// today, but the contract is "ask the validator").
			result := p.validator.Validate(subject, data)
			if result.IsMismatch() {
				if p.onSchemaMismatch != nil {
					p.onSchemaMismatch(subject, result)
				}
				return &schema.ValidationError{
					Subject:         subject,
					ResolvedVersion: result.ResolvedVersion,
					Reason:          result.Reason,
					Cause:           result.Err,
				}
			}
		}
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
	// Header mirror: propagating `schema_version` as a header
	// makes the version visible to a passive observer
	// (`nats consume sn360-events --headers-only`) and lets the
	// schema-mismatch DLQ classify a payload it cannot parse.
	if v := schema.PeekVersion(data); v != "" {
		msg.Header.Set(events.HeaderSchemaVersion, v)
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
