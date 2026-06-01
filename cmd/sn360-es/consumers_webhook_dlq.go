// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/webhooksink"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/sinks/webhook"
)

// WS-5B.2 webhook DLQ consumer.
//
// Subject layout: `sn360.dlq.webhook.<tenant_id>.<sink_id>` (see
// internal/service/webhooksink.DLQSubject). The consumer drains
// the parent `sn360.dlq.webhook.>` wildcard so a single durable
// services every tenant + sink.
//
// Retry schedule: exponential 1s, 5s, 30s, 5m, 1h. Up to 5
// deliveries before the message is dropped + a `dispatch_failed`
// audit row is written. AckWait must comfortably exceed the per-
// publish HTTP budget (publishTimeout ≈ 5s) plus a small
// processing margin so JetStream doesn't redeliver on every slow
// customer endpoint.
const (
	webhookDLQSubject       = "sn360.dlq.webhook.>"
	webhookDLQDurable       = "ws5b2-webhook-dlq-retrier"
	webhookDLQAckWait       = 30 * time.Second
	webhookDLQMaxDeliver    = 5
	webhookDLQMaxAckPending = 64
)

// webhookDLQBackoffs is the per-redelivery wait the consumer
// requests via Nak(delay). Index n is the delay applied AFTER
// the n-th delivery attempt fails (i.e. the wait before the
// (n+1)-th attempt). Length must be >= webhookDLQMaxDeliver-1 so
// every redelivery has a defined wait.
var webhookDLQBackoffs = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
	1 * time.Hour,
}

// startWebhookDLQConsumer subscribes the WS-5B.2 retrier. Called
// from StartConsumers after the dispatcher dependencies (repo,
// encryptor, publisher) are wired.
func (a *application) startWebhookDLQConsumer(ctx context.Context) error {
	if a.eventBus == nil {
		return errors.New("sn360-es: startWebhookDLQConsumer: event bus not wired")
	}
	if a.webhookDispatcher == nil {
		// Memory-only / dev deployments without the
		// WS-5B.2 dispatcher don't need the retrier
		// either. Log so operators notice the missing
		// wiring on startup.
		a.logger.InfoContext(ctx, "sn360-es: startWebhookDLQConsumer: dispatcher not wired — skipping subscription")
		return nil
	}
	if a.repos == nil || a.repos.WebhookSinks == nil {
		a.logger.InfoContext(ctx, "sn360-es: startWebhookDLQConsumer: WebhookSinks repo not wired — skipping subscription")
		return nil
	}
	// Defensive: in current wiring (app.go) the publisher and
	// encryptor are always set together with the dispatcher, but
	// the DLQ handler dereferences both directly. An explicit
	// nil-check here keeps a future wiring refactor from
	// turning the first DLQ message into a NPE panic on the
	// JetStream callback goroutine.
	if a.webhookPublisher == nil {
		a.logger.InfoContext(ctx, "sn360-es: startWebhookDLQConsumer: webhook publisher not wired — skipping subscription")
		return nil
	}
	if a.encryptor == nil {
		a.logger.InfoContext(ctx, "sn360-es: startWebhookDLQConsumer: secret encryptor not wired — skipping subscription")
		return nil
	}
	// Wrap with tenantBoundMessageHandler so handleWebhookDLQ
	// runs against a Postgres connection with the
	// `sn360.tenant_id` GUC pinned to the message's tenant.
	// Without this wrapper, the RLS policy on
	// tenant_webhook_sinks / tenant_webhook_sink_audit
	// (migration 0023) evaluates tenant_id = NULL and silently
	// rejects every GetByID + AppendAudit — the DLQ consumer
	// becomes a no-op that Acks every message as "sink missing".
	// The dispatcher publishes DLQ envelopes with
	// events.WithTenantID(sink.TenantID), so the wrapper reads
	// the tenant from the verified header.
	sub, err := a.eventBus.Subscribe(ctx, webhookDLQSubject,
		a.tenantBoundMessageHandler(a.handleWebhookDLQ),
		events.WithDurable(webhookDLQDurable),
		events.WithAckWait(webhookDLQAckWait),
		events.WithMaxDeliver(webhookDLQMaxDeliver),
		events.WithMaxAckPending(webhookDLQMaxAckPending),
	)
	if err != nil {
		return fmt.Errorf("sn360-es: subscribe %s (%s) failed: %w", webhookDLQSubject, webhookDLQDurable, err)
	}
	a.trackSub(sub)
	a.logger.InfoContext(ctx, "sn360-es: subscribed to webhook DLQ",
		slog.String("durable", webhookDLQDurable),
		slog.Duration("ack_wait", webhookDLQAckWait),
		slog.Int("max_deliver", webhookDLQMaxDeliver))
	return nil
}

// handleWebhookDLQ is the JetStream callback for the
// sn360.dlq.webhook.> stream. The flow is:
//
//  1. Decode envelope.
//  2. Re-fetch sink from repository (so a Disabled / soft-deleted
//     sink stops receiving retries even if its envelope is in
//     flight). If lookup fails or sink is gone: Ack + drop;
//     audit reason "sink missing".
//  3. Re-sign the original envelope body if the sink rotated its
//     HMAC secret between attempts; the body itself is always
//     replayed verbatim in its original format (a format change
//     on the live sink does NOT cause the in-flight envelope to
//     be re-encoded — round-tripping a formatted body back to
//     an Event is format-specific and brittle, see resignDLQEnvelope).
//  4. POST. Success: Ack. PermanentFailure: audit + Ack. Retriable:
//     Nak with the backoff matching the current attempt number.
//  5. On the last delivery (NumDelivered >= MaxDeliver): audit
//     final-fail + Ack so JetStream stops redelivering.
//
// Returning an error from this handler tells the bus to Nak with
// its default backoff — we explicitly Ack / Nak ourselves to
// implement the documented schedule.
func (a *application) handleWebhookDLQ(ctx context.Context, msg events.Message) error {
	env, err := webhook.ParseDLQEnvelope(msg.Data())
	if err != nil {
		a.logger.WarnContext(ctx, "webhook-dlq: malformed envelope; dropping",
			slog.String("subject", msg.Subject()),
			slog.Any("error", err))
		// Bad envelope is unrecoverable; Ack so we don't loop.
		_ = msg.Ack()
		return nil
	}
	meta, _ := msg.Metadata()
	deliveryAttempt := uint64(1)
	if meta.NumDelivered > 0 {
		deliveryAttempt = meta.NumDelivered
	}
	logger := a.logger.With(
		slog.String("tenant_id", env.TenantID),
		slog.String("sink_id", env.SinkID),
		slog.String("sink_name", env.SinkName),
		slog.Uint64("delivery_attempt", deliveryAttempt))

	// Re-fetch the sink. A Disabled / soft-deleted sink must
	// stop receiving retries.
	sink, lookupErr := a.repos.WebhookSinks.GetByID(ctx, env.TenantID, env.SinkID)
	if lookupErr != nil {
		if errors.Is(lookupErr, repository.ErrNotFound) {
			logger.InfoContext(ctx, "webhook-dlq: sink missing or soft-deleted; dropping")
			a.appendDLQAudit(ctx, env, "sink missing or deleted")
			_ = msg.Ack()
			return nil
		}
		// Transient repo error — request another delivery so the
		// envelope survives a Postgres blip. The Nak DOES count
		// against MaxDeliver (JetStream increments NumDelivered on
		// every redelivery regardless of cause); a Postgres outage
		// lasting through all 5 attempts will end up dropping the
		// envelope just like a real customer-endpoint failure.
		// That's acceptable for a best-effort egress path —
		// alternative (infinite redelivery) would let one tenant's
		// flaky DB starve the rest of the stream.
		logger.WarnContext(ctx, "webhook-dlq: sink lookup failed",
			slog.Any("error", lookupErr))
		_ = msg.Nak(webhookDLQBackoffs[0])
		return nil
	}
	if !sink.Enabled {
		logger.InfoContext(ctx, "webhook-dlq: sink disabled; dropping")
		a.appendDLQAudit(ctx, env, "sink disabled")
		_ = msg.Ack()
		return nil
	}

	// Re-sign the original body if the HMAC secret rotated
	// between the initial publish and this retry. The body
	// itself is ALWAYS the original envelope bytes — we never
	// re-encode (see resignDLQEnvelope for rationale) — so the
	// Content-Type / Format must track env.Format, NOT
	// sink.Format. If the operator changed the live sink format
	// between attempts, the in-flight envelope retries in its
	// original format until JetStream gives up; new evaluations
	// pick up the new format on first publish.
	body := env.Body
	signature := env.Signature
	resigned, signErr := a.resignDLQEnvelope(ctx, sink, env)
	if signErr != nil {
		logger.WarnContext(ctx, "webhook-dlq: re-sign failed; replaying original signature",
			slog.Any("error", signErr))
	} else if resigned != "" {
		signature = resigned
	}

	pubCtx, cancel := context.WithTimeout(ctx, webhooksink.DefaultPublishTimeout)
	defer cancel()
	attemptNum := int(deliveryAttempt) + 1 // initial publish was attempt 1; this is the +1th
	req := &webhook.Request{
		SinkID:     sink.ID,
		TenantID:   sink.TenantID,
		SinkName:   sink.Name,
		URL:        sink.URL,
		Format:     env.Format, // mirrors env.Body bytes — NOT sink.Format (see comment above)
		Body:       body,
		Signature:  signature,
		EventType:  env.EventType,
		EventID:    env.EventID,
		OccurredAt: env.OccurredAt,
		Attempt:    attemptNum,
	}
	result, publishErr := a.webhookPublisher.Publish(pubCtx, req)
	if publishErr != nil {
		logger.WarnContext(ctx, "webhook-dlq: publish errored",
			slog.Any("error", publishErr))
	}

	switch result.Outcome {
	case webhook.OutcomeSuccess:
		logger.InfoContext(ctx, "webhook-dlq: retry success",
			slog.Int("http_status", result.HTTPStatus),
			slog.Int64("latency_ms", result.LatencyMS))
		_ = msg.Ack()
		return nil
	case webhook.OutcomePermanentFailure:
		logger.InfoContext(ctx, "webhook-dlq: permanent failure on retry; dropping",
			slog.Int("http_status", result.HTTPStatus),
			slog.String("cause", result.Cause))
		a.appendDLQAudit(ctx, env, "permanent: "+result.Cause)
		_ = msg.Ack()
		return nil
	default: // OutcomeRetriable / OutcomeUnknown
		// We've exhausted the schedule when this is the last
		// delivery JetStream will perform (NumDelivered >=
		// MaxDeliver). Ack the message ourselves and emit the
		// final-fail audit row + metric.
		if int(deliveryAttempt) >= webhookDLQMaxDeliver {
			logger.WarnContext(ctx, "webhook-dlq: final fail after MaxDeliver",
				slog.Int("http_status", result.HTTPStatus),
				slog.String("cause", result.Cause))
			a.appendDLQAudit(ctx, env, "final fail: "+result.Cause)
			_ = msg.Ack()
			return nil
		}
		delay := backoffFor(int(deliveryAttempt))
		logger.InfoContext(ctx, "webhook-dlq: retriable; scheduling next delivery",
			slog.Duration("next_in", delay),
			slog.Int("http_status", result.HTTPStatus),
			slog.String("cause", result.Cause))
		_ = msg.Nak(delay)
		return nil
	}
}

// resignDLQEnvelope re-signs the envelope's body against the
// CURRENT per-sink HMAC secret and returns the new hex signature
// when it differs from env.Signature (i.e. the operator rotated
// the secret between attempts). Returns ("", nil) when the
// signature is unchanged — the caller then replays env.Signature
// verbatim.
//
// Despite the historical "reformat" name (now retired), we DO NOT
// re-encode the body: we only ever have the post-format bytes
// (ECS JSON or CEF pipe-delimited string), not the original Event,
// so round-tripping back to an Event would be format-specific and
// brittle. A live sink-format change between attempts is therefore
// not honoured for in-flight envelopes — they replay in their
// original format until JetStream exhausts MaxDeliver; new
// evaluations pick up the new format on first publish. The
// dispatcher's Content-Type header must always match the bytes on
// the wire, so the caller sets Request.Format = env.Format.
//
// We can't compare secret bytes against the envelope — the
// plaintext key is not carried in the envelope — so we re-sign
// unconditionally and compare the resulting hex against
// env.Signature.
func (a *application) resignDLQEnvelope(ctx context.Context, sink *repository.WebhookSink, env *webhook.DLQEnvelope) (string, error) {
	secret, err := a.encryptor.Decrypt(ctx, sink.TenantID, sink.HMACSecretCiphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	defer zeroBytes(secret)
	resigned, err := webhook.Sign(secret, env.Body)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	if resigned == env.Signature {
		// No secret rotation; caller reuses env.Signature.
		return "", nil
	}
	return resigned, nil
}

// appendDLQAudit writes a dispatch_failed audit row for the
// terminal outcomes of a DLQ envelope (sink-missing / permanent /
// final-fail). Reason is bounded; the secret + body are never
// referenced.
func (a *application) appendDLQAudit(ctx context.Context, env *webhook.DLQEnvelope, reason string) {
	if a.repos == nil || a.repos.WebhookSinks == nil {
		return
	}
	entry := repository.WebhookSinkAuditEntry{
		TenantID: env.TenantID,
		SinkID:   env.SinkID,
		SinkName: env.SinkName,
		Action:   repository.WebhookSinkAuditActionDispatchFailed,
		Reason:   bound("dlq " + reason),
		// Deterministic dedup so JetStream re-delivery of the
		// SAME envelope on the SAME (event, attempt) collapses
		// to one audit row.
		DedupID: env.SinkID + "|" + env.EventID + "|attempt=" + strconv.Itoa(env.Attempt) + "|reason=" + reason,
	}
	if err := a.repos.WebhookSinks.AppendAudit(ctx, entry); err != nil {
		a.logger.WarnContext(ctx, "webhook-dlq: audit append failed",
			slog.String("sink_id", env.SinkID),
			slog.Any("error", err))
	}
}

// backoffFor maps a 1-based delivery attempt to the wait the
// consumer asks JetStream to apply before the NEXT delivery.
// Bounds-clamped so a misconfigured MaxDeliver can't index out
// of webhookDLQBackoffs.
func backoffFor(deliveryAttempt int) time.Duration {
	if deliveryAttempt < 1 {
		deliveryAttempt = 1
	}
	idx := deliveryAttempt - 1
	if idx >= len(webhookDLQBackoffs) {
		idx = len(webhookDLQBackoffs) - 1
	}
	return webhookDLQBackoffs[idx]
}

// bound caps the cause string written to the audit table.
func bound(s string) string {
	const maxLen = 1024
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// zeroBytes overwrites s with zeros. Mirrors the dispatcher's
// helper.
func zeroBytes(s []byte) {
	for i := range s {
		s[i] = 0
	}
}
