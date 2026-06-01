// Package main: WS-7c subscribe-side schema enforcement.
//
// schemaValidatedMessageHandler wraps a downstream MessageHandler
// so every delivery is gated by the WS-7c schema registry
// (pkg/events/schema) before the inner handler runs. A mismatch
// is NOT propagated as a handler error (that would trigger the
// per-handler retry loop and burn deliveries on a payload that
// can never satisfy the registered shape) — instead, the
// wrapper republishes the original payload onto
// `sn360.dlq.schema.<original_subject>`, increments the
// nats_schema_mismatch_total metric, and returns nil so the
// underlying JetStream consumer Acks the message and frees the
// slot.
//
// Backward compat: a payload with no `schema_version` field is
// treated as v1 (see schema.Validate). If the v1 validator
// accepts it, the wrapper passes the delivery through unchanged
// (Reason=missing_version is a tagging-only flag, NOT a DLQ
// event — Result.IsMismatch() returns false). This is what
// keeps the WS-7c rollout from breaking every pre-WS-7c
// publisher still in the field.

package main

import (
	"context"
	"log/slog"
	"strings"

	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/events/schema"
)

// schemaValidatedMessageHandler returns a MessageHandler that
// runs the WS-7c schema validator over msg.Data() and routes
// mismatches to the schema-mismatch DLQ. Returns inner unchanged
// when no validator is wired (legacy / unit-test paths).
//
// The returned wrapper is symmetric with the publish-side
// enforcement on pkg/events/nats.Publisher: a payload that the
// publisher would have rejected at publish time is also rejected
// here, so a producer that bypasses the typed publish path (e.g.
// a hand-rolled `nats publish` from the CLI) cannot smuggle
// a malformed payload past the consumer.
func (a *application) schemaValidatedMessageHandler(inner func(context.Context, events.Message) error) func(context.Context, events.Message) error {
	if a == nil || a.schemaValidator == nil {
		return inner
	}
	return func(ctx context.Context, msg events.Message) error {
		subject := msg.Subject()
		// Do not re-validate messages already on the schema
		// DLQ — otherwise a bad payload republished onto
		// `sn360.dlq.schema.*` would loop straight back into
		// the wrapper, peel one segment off the subject every
		// pass, and either nest forever or fail in a
		// non-obvious way. The schema DLQ namespace is
		// validated-by-construction (operator only) so the
		// passthrough is safe.
		if strings.HasPrefix(subject, schema.DLQSubjectPrefix+".") {
			return inner(ctx, msg)
		}

		result := a.schemaValidator.Validate(subject, msg.Data())
		if !result.IsMismatch() {
			return inner(ctx, msg)
		}

		// Mismatch: increment the metric, log a warn, and
		// route the original payload onto the schema-mismatch
		// DLQ before Acking the source message.
		subjectFamily := result.SubjectMatch
		if subjectFamily == "" {
			subjectFamily = "unknown"
		}
		a.metrics.ObserveSchemaMismatch(subjectFamily, string(result.Reason), "subscribe")
		a.logger.WarnContext(ctx, "sn360-es: schema mismatch on subscribe — routing to schema DLQ",
			slog.String("subject", subject),
			slog.String("subject_family", subjectFamily),
			slog.String("resolved_version", result.ResolvedVersion),
			slog.String("reason", string(result.Reason)),
			slog.Any("validator_error", result.Err))

		dlqSubject := schema.DLQSubject(subject)
		opts := []events.PublishOption{
			events.WithHeader(events.HeaderOriginSubject, subject),
			events.WithHeader(events.HeaderSchemaMismatchReason, string(result.Reason)),
			events.WithHeader(events.HeaderError, schemaMismatchErrorString(result)),
		}
		// Preserve the original message-id / correlation-id /
		// tenant-id / event-type so the operator-side DLQ
		// tooling can correlate the failure back to the
		// originating request. The new dedup id is derived
		// from the schema-DLQ subject + original message-id so
		// a re-delivery of the same bad payload within the
		// 600s dedup window collapses at the broker.
		hdrs := msg.Headers()
		if v := hdrs[events.HeaderMessageID]; v != "" {
			opts = append(opts, events.WithMessageID("schema-"+v))
		}
		if v := hdrs[events.HeaderCorrelationID]; v != "" {
			opts = append(opts, events.WithCorrelationID(v))
		}
		if v := hdrs[events.HeaderTenantID]; v != "" {
			opts = append(opts, events.WithTenantID(v))
		}
		if v := hdrs[events.HeaderEventType]; v != "" {
			opts = append(opts, events.WithEventType(v))
		}
		if v := hdrs[events.HeaderSchemaVersion]; v != "" {
			opts = append(opts, events.WithHeader(events.HeaderSchemaVersion, v))
		}
		if perr := a.eventBus.Publish(ctx, dlqSubject, msg.Data(), opts...); perr != nil {
			a.logger.ErrorContext(ctx, "sn360-es: schema DLQ publish failed",
				slog.String("dlq_subject", dlqSubject),
				slog.String("origin_subject", subject),
				slog.Any("error", perr))
			// Surface a handler error so the broker
			// redelivers and we can try the DLQ publish
			// again — losing the audit trail on a
			// transient broker hiccup is the worse
			// failure mode.
			return perr
		}
		// Ack the original by returning nil — the message has
		// been routed to its terminal queue.
		return nil
	}
}

// validatedTenantBoundHandler is the standard handler chain used
// by every subscribe in cmd/sn360-es/consumers*.go:
//
//	schemaValidatedMessageHandler   (WS-7c: schema validate +
//	                                 schema-mismatch DLQ route)
//	└─ tenantBoundMessageHandler    (RLS: bind Postgres conn
//	                                 to verifiedTenantID)
//	   └─ inner                     (the real domain handler)
//
// The outer schema wrapper runs first so a mismatched payload is
// routed to the schema-mismatch DLQ before we waste a tenant
// conn-pool acquisition on a message that will be rejected
// anyway.
func (a *application) validatedTenantBoundHandler(inner func(context.Context, events.Message) error) func(context.Context, events.Message) error {
	return a.schemaValidatedMessageHandler(a.tenantBoundMessageHandler(inner))
}

// schemaMismatchErrorString renders a structured, single-line
// HeaderError value that the DLQ tooling can parse. Includes the
// reason classification + the underlying validator error string
// when present.
func schemaMismatchErrorString(result schema.Result) string {
	var b strings.Builder
	b.WriteString("schema mismatch: ")
	b.WriteString(string(result.Reason))
	if result.Err != nil {
		b.WriteString(": ")
		b.WriteString(result.Err.Error())
	}
	return b.String()
}
