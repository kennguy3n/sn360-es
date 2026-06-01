// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/escalation"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// bodyTenantHeaderShim is a NATS-header-injecting wrapper. It
// peeks at the IncidentResolved JSON envelope and, if the
// publisher didn't stamp events.HeaderTenantID on the message,
// copies the body's tenant_id field onto the headers BEFORE
// the wrapped tenantBoundMessageHandler runs.
//
// Why this matters: the producer in sn360-security-platform's
// soc-triage emits across a repo boundary. A future producer
// regression (or a legacy publisher build still in flight)
// could publish without the header. Without this shim,
// tenantBoundMessageHandler would fall through with no RLS
// bind, the resolver's evaluation_results reads would return
// zero rows under FORCE ROW LEVEL SECURITY, every event would
// degenerate to a "no evaluation row found" skip, and the
// audit table would fill with skip rows that ops can't
// distinguish from legitimately-missing evaluations.
//
// The body always carries tenant_id (validated by the
// resolver's own validateInput), so deriving from it is
// strictly more defensible than the header-only path. We
// still prefer the header when present so the same payload
// can ride other transports (Redis, in-proc bus) without
// special-casing the SOC subject.
func (a *application) bodyTenantHeaderShim(
	inner func(context.Context, events.Message) error,
) func(context.Context, events.Message) error {
	return func(ctx context.Context, msg events.Message) error {
		headers := msg.Headers()
		if headers[events.HeaderTenantID] != "" {
			return inner(ctx, msg)
		}
		var peek struct {
			TenantID string `json:"tenant_id"`
		}
		// A malformed body is fine here — the inner
		// handler does its own json.Unmarshal and will
		// drop the message at the resolver boundary with
		// a WARN log. We just can't enrich the header in
		// that case.
		if err := json.Unmarshal(msg.Data(), &peek); err == nil && peek.TenantID != "" {
			return inner(ctx, &tenantHeaderMessage{Message: msg, tenantID: peek.TenantID})
		}
		return inner(ctx, msg)
	}
}

// tenantHeaderMessage wraps an events.Message to overlay the
// canonical tenant-id header without mutating the underlying
// transport message. Used by bodyTenantHeaderShim so the
// downstream tenantBoundMessageHandler observes a header even
// when the producer didn't stamp one.
type tenantHeaderMessage struct {
	events.Message
	tenantID string
}

// Headers returns the underlying headers with HeaderTenantID
// overlaid. We allocate a new map per call because the
// downstream wrapper is allowed to read it concurrently with
// other handler invocations on the same Message instance.
func (t *tenantHeaderMessage) Headers() map[string]string {
	src := t.Message.Headers()
	out := make(map[string]string, len(src)+1)
	for k, v := range src {
		out[k] = v
	}
	out[events.HeaderTenantID] = t.tenantID
	return out
}

// socResolutionSubject is the WS-5A.6 wire subject the
// sn360-security-platform soc-triage publisher emits to. Lives
// on the `sn360-platform` JetStream stream with per-subject
// duplicate window of 600s (mirroring the FU-B convention).
const socResolutionSubject = "soc.incident.resolved"

// socResolutionDurable is the WS-5A.6 durable consumer name.
// Stable identifier so a restart re-binds to the same logical
// consumer rather than provisioning a new one (which would
// re-deliver every retained message in the stream).
const socResolutionDurable = "ws5a6-escalation-sync"

// socResolutionAckWait is the maximum time JetStream waits for
// an ack before redelivering. The resolver's hot path makes at
// most ~3 round trips to Postgres (audit dedup probe + eval
// lookup + audit insert) so 30s is several orders of
// magnitude above the expected P99.
const socResolutionAckWait = 30 * time.Second

// socResolutionMaxDeliver is the cap on redelivery attempts
// before the message routes to the DLQ. Set conservatively to
// 5: persistent failures (DB outage, schema drift) should
// surface to ops via DLQ + alerting, not via an infinite
// redelivery loop.
const socResolutionMaxDeliver = 5

// handleSOCIncidentResolved is the JetStream callback for
// `soc.incident.resolved`. It hands the wire envelope to the
// resolver and translates the Outcome into structured logs +
// metrics so ops can observe the bidirectional loop.
//
// Error handling: a non-nil return from this handler tells
// the bus to NACK (so JetStream redelivers up to
// MaxDeliver=5). Any retry-worthy condition (transient DB
// error, NATS timeout) bubbles up; non-retry-worthy
// conditions (malformed payload, invalid resolution string)
// are logged at WARN and the handler returns nil so the
// broker advances past the poison pill.
func (a *application) handleSOCIncidentResolved(ctx context.Context, msg events.Message) error {
	if a.escalationResolver == nil {
		// The resolver hasn't been wired (e.g. repos are
		// in memory-only mode). Drop the message; the
		// audit row would have no durable home. Logged at
		// DEBUG because this is a deployment-shape signal,
		// not an unexpected runtime event.
		a.logger.DebugContext(ctx, "sn360-es: soc.incident.resolved: resolver not wired — dropping",
			slog.Int("payload_bytes", len(msg.Data())))
		return nil
	}
	var env escalation.IncidentResolved
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: soc.incident.resolved: malformed payload — dropping",
			slog.Any("error", err),
			slog.Int("payload_bytes", len(msg.Data())))
		return nil
	}
	if !escalation.IsValidResolution(env.Resolution) {
		a.logger.WarnContext(ctx, "sn360-es: soc.incident.resolved: invalid resolution — dropping",
			slog.String("incident_id", env.IncidentID),
			slog.String("tenant_id", env.TenantID),
			slog.String("resolution", env.Resolution))
		return nil
	}
	outcome, err := a.escalationResolver.Reconcile(ctx, env)
	if err != nil {
		// Surface to JetStream so it redelivers up to
		// MaxDeliver. The resolver only returns errors
		// for transient / retry-worthy conditions; all
		// permanent failures land in the Outcome.Kind
		// taxonomy with a non-empty audit row.
		a.logger.WarnContext(ctx, "sn360-es: soc.incident.resolved: reconcile failed (will retry)",
			slog.Any("error", err),
			slog.String("incident_id", env.IncidentID),
			slog.String("tenant_id", env.TenantID),
			slog.String("dedup_id", env.DedupID))
		return err
	}
	a.logger.InfoContext(ctx, "sn360-es: soc.incident.resolved: reconciled",
		slog.String("incident_id", env.IncidentID),
		slog.String("tenant_id", env.TenantID),
		slog.String("resolution", env.Resolution),
		slog.String("kind", string(outcome.Kind)),
		slog.String("original_verdict", outcome.OriginalVerdict),
		slog.String("new_verdict", outcome.NewVerdict),
		slog.Bool("banner_reopened", outcome.BannerReopened),
		slog.String("audit_id", outcome.AuditID),
		slog.String("dedup_id", env.DedupID))
	return nil
}

// startSOCResolutionConsumer subscribes
// `soc.incident.resolved` with the WS-5A.6 durable consumer
// config. Called from StartConsumers after the dependent
// service objects (escalationResolver, banner reopener) are
// wired by buildEscalationResolver.
func (a *application) startSOCResolutionConsumer(ctx context.Context) error {
	if a.eventBus == nil {
		return errors.New("sn360-es: startSOCResolutionConsumer: event bus not wired")
	}
	if a.escalationResolver == nil {
		// Memory-only deployments (no Postgres) don't get
		// the escalation loop. Logged because this is a
		// non-trivial shape (operators may not realise the
		// WS-5A.6 path is dark).
		a.logger.InfoContext(ctx, "sn360-es: startSOCResolutionConsumer: resolver not wired — skipping subscription")
		return nil
	}
	sub, err := a.eventBus.Subscribe(ctx, socResolutionSubject,
		// Compose: bodyTenantHeaderShim runs first, derives
		// the tenant_id from the JSON body when the producer
		// didn't stamp the header, then
		// tenantBoundMessageHandler binds the RLS GUC. This
		// pairing guarantees the SOC resolver runs inside a
		// tenant-bound DB context even when the cross-repo
		// producer regresses on its header contract.
		a.bodyTenantHeaderShim(
			a.tenantBoundMessageHandler(a.handleSOCIncidentResolved),
		),
		events.WithDurable(socResolutionDurable),
		events.WithAckWait(socResolutionAckWait),
		events.WithMaxDeliver(socResolutionMaxDeliver),
	)
	if err != nil {
		return fmt.Errorf("sn360-es: subscribe %s (%s) failed: %w", socResolutionSubject, socResolutionDurable, err)
	}
	a.trackSub(sub)
	a.logger.InfoContext(ctx, "sn360-es: subscribed to soc.incident.resolved",
		slog.String("durable", socResolutionDurable),
		slog.Duration("ack_wait", socResolutionAckWait),
		slog.Int("max_deliver", socResolutionMaxDeliver))
	return nil
}
