package main

// This file holds the evaluate-domain consumer handlers split out of
// consumers.go. All subscription orchestration (StartConsumers /
// StopConsumers / trackSub) remains there.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

func (a *application) handleEvaluateResult(ctx context.Context, msg events.Message) error {
	if a.repos == nil {
		return nil
	}
	var res dto.EvaluateResult
	if err := json.Unmarshal(msg.Data(), &res); err != nil {
		a.logger.Warn("sn360-es: evaluate.result unmarshal failed", slog.Any("error", err))
		return nil
	}
	row := evaluateResultRow(res, msg)
	if a.repos.EvaluationResults == nil {
		return nil
	}
	if err := a.repos.EvaluationResults.Create(ctx, row); err != nil {
		a.logger.ErrorContext(ctx, "sn360-es: persist evaluate.result failed",
			slog.String("tenant_id", res.TenantID),
			slog.String("message_id", res.MessageID),
			slog.Any("error", err))
		return fmt.Errorf("persist evaluate.result: %w", err)
	}
	return nil
}

// handleEvaluateRequest fans an es.evaluate.request payload through
// the multi-tier evaluator and publishes the verdict on
// `es.evaluate.result`.
func (a *application) handleEvaluateRequest(ctx context.Context, msg events.Message) error {
	if a.evaluator == nil || a.eventBus == nil {
		return nil
	}
	var req dto.EvaluateRequest
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: evaluate.request unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if req.MessageID == "" || req.TenantID == "" {
		a.logger.WarnContext(ctx, "sn360-es: evaluate.request missing identifiers",
			slog.String("tenant_id", req.TenantID),
			slog.String("message_id", req.MessageID))
		return nil
	}
	// Pass the enriched signals as the explicit signals argument so
	// the per-message and batch paths share the same evaluator entry
	// signature AND the same per-relationship view of
	// communication_histories. The producer-supplied req.Signals
	// only carry header-derived state (SenderDomain, IsExternal,
	// auth verdicts, …); the SignalEnricher folds in the
	// per-(tenant, sender, recipient) state at evaluation time so
	// the Tier 0 ATO heuristic and the categoriser see fresh
	// TypicalSendHour, CommunicationFrequency, IsFirstContact, and
	// CurrentHourUTC. a.signalEnricher is always non-nil (the
	// composition root substitutes evaluate.NoopEnricher when the
	// repo or PII hasher is missing), so we can call Enrich
	// unconditionally — the batch orchestrator's run loop
	// (internal/service/evaluate/batch.go) makes the same
	// guarantee, keeping the per-message and batch paths
	// symmetric.
	signals := a.signalEnricher.Enrich(ctx, req, req.Signals)
	result, err := a.evaluator.Evaluate(ctx, req, signals)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}
	dto.BackfillRoutingFields(&result, req)
	// WS-3b: stamp the pseudonymised participant hashes onto the
	// result BEFORE publish so the downstream evaluate.result
	// consumer can persist them on evaluation_results and the
	// investigation API's sender-trail lookup has a hash to index
	// on. The helper reuses the same SignalEnricher.SightingFor
	// the WS-4a sighting publish below calls, so the hashes
	// stamped here are guaranteed identical to the ones the
	// communication_histories row picks up — a divergence would
	// silently break the join the investigation API performs on
	// (tenant_id, sender_hash) across the two tables.
	evaluate.StampResultParticipantHashes(ctx, a.signalEnricher, req, &result)
	payload, err := json.Marshal(result)
	if err != nil {
		a.logger.WarnContext(ctx, "sn360-es: evaluate.result marshal failed",
			slog.Any("error", err))
		return nil
	}
	if err := a.eventBus.Publish(ctx, "es.evaluate.result", payload,
		events.WithMessageID(result.MessageID),
		events.WithCorrelationID(req.CorrelationID),
		events.WithTenantID(req.TenantID),
		events.WithEventType("evaluate.result"),
		events.WithTraceContext(ctx),
	); err != nil {
		// Result publish failed: return so JetStream NAKs and
		// redelivers. We deliberately have NOT yet published the
		// WS-4a sighting — see the contract block immediately
		// below.
		return fmt.Errorf("publish evaluate.result: %w", err)
	}
	// WS-4a hot path: publish the per-message sighting onto
	// es.management.comm_history.update so the management Postgres
	// consumer can atomically increment communication_histories
	// without waiting for the 4-hour relationship_worker cycle.
	//
	// Ordering contract: the sighting publish lives AFTER the
	// evaluate.result publish succeeds, mirroring the batch path's
	// finalisePending tail (internal/service/evaluate/batch.go).
	// Putting the sighting publish here — not before the result —
	// closes the "orphaned sighting" failure mode caught in Devin
	// Review round 2: if the result publish fails, the sighting is
	// never emitted, so JetStream redelivery sees a clean slate and
	// emits the (result, sighting) pair as a unit on retry.
	//
	// The publish itself is best-effort: PublishCommHistoryUpdate
	// swallows every error so a transient management-bus blip after
	// the result has already landed cannot NAK the evaluate-request
	// envelope (which would produce a duplicate evaluate.result on
	// the next redelivery). On the rare case where the sighting is
	// dropped, the relationship_worker's next 4h cycle recomputes
	// counts from persisted rows and recovers the drift.
	a.publishCommHistoryUpdate(ctx, req)
	return nil
}

// handleCommHistoryUpdate is the WS-4a consumer side of the
// incremental-baselines pipeline. It unmarshals a CommHistoryUpdate
// envelope, validates it, and applies it atomically to
// communication_histories via the repository's RecordSighting
// method. Idempotency is upstream (JetStream's dedup window collapses
// redeliveries of the same (tenant, sender_hash, recipient_hash,
// message_id) tuple at the broker); RecordSighting is a best-effort
// monotonic increment, not exactly-once.
//
// Error semantics:
//   - terminal-bad-message (Validate failure, unmarshal error): log
//     and return nil so JetStream does NOT redeliver. The envelope
//     cannot become valid on retry; redelivering would burn the
//     max-deliver budget on a poisoned message.
//   - transient repository error: return the error so JetStream
//     redelivers within the dedup window. After 3 deliveries the
//     consumer abandons the sighting (relationship_worker recovers
//     it on its next 4h cycle).
func (a *application) handleCommHistoryUpdate(ctx context.Context, msg events.Message) error {
	if a.repos == nil || a.repos.CommunicationHistories == nil {
		return nil
	}
	var upd dto.CommHistoryUpdate
	if err := json.Unmarshal(msg.Data(), &upd); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: comm_history.update unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if err := upd.Validate(); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: comm_history.update validate failed",
			slog.String("tenant_id", upd.TenantID),
			slog.String("message_id", upd.MessageID),
			slog.Any("error", err))
		return nil
	}
	sighting := repository.Sighting{
		TenantID:         upd.TenantID,
		SenderHash:       upd.SenderHash,
		RecipientHash:    upd.RecipientHash,
		SenderDomainHash: upd.SenderDomainHash,
		SenderDomain:     upd.SenderDomain,
		SentAt:           upd.SentAt,
	}
	if err := a.repos.CommunicationHistories.RecordSighting(ctx, sighting); err != nil {
		// Surface as a redeliverable error: a Postgres blip
		// should not silently lose the sighting. JetStream
		// honours MaxDeliver=3 and falls back to the DLQ
		// processor on the third failure.
		a.logger.ErrorContext(ctx, "sn360-es: persist comm_history.update failed",
			slog.String("tenant_id", upd.TenantID),
			slog.String("message_id", upd.MessageID),
			slog.Any("error", err))
		return fmt.Errorf("persist comm_history.update: %w", err)
	}
	return nil
}

// publishCommHistoryUpdate is the per-message handler's adapter onto
// the shared WS-4a publisher (evaluate.PublishCommHistoryUpdate). The
// helper lives in the evaluate package so the batch orchestrator
// (internal/service/evaluate/batch.go) can call the same function
// without an import cycle on cmd/sn360-es. Keeping a method here
// preserves the call-site at handleEvaluateRequest and the test seam
// that lets ws4a_round_trip_test.go inject a recording bus and a
// recording enricher behind the same wiring the production path uses.
func (a *application) publishCommHistoryUpdate(ctx context.Context, req dto.EvaluateRequest) {
	if a.signalEnricher == nil || a.eventBus == nil {
		return
	}
	evaluate.PublishCommHistoryUpdate(ctx, a.eventBus, a.signalEnricher, a.logger, req)
}

// evaluateResultRow projects a DTO into the repository row shape.
func evaluateResultRow(res dto.EvaluateResult, msg events.Message) *repository.EvaluationResult {
	tenantID := res.TenantID
	correlationID := res.CorrelationID
	if msg != nil {
		headers := msg.Headers()
		if v := headers[events.HeaderTenantID]; v != "" {
			tenantID = v
		}
		if v := headers[events.HeaderCorrelationID]; v != "" {
			correlationID = v
		}
	}
	secondary := make([]string, 0, len(res.Secondary))
	for _, c := range res.Secondary {
		secondary = append(secondary, string(c))
	}
	reasons := append([]string(nil), res.ReasonCodes...)
	evaluatedAt := res.EvaluatedAt
	if evaluatedAt.IsZero() {
		evaluatedAt = time.Now().UTC()
	}
	return &repository.EvaluationResult{
		TenantID:      tenantID,
		MessageIDHash: []byte(res.MessageID),
		// WS-3b: copy through the participant hashes the producer
		// (per-message or batch path) stamped on the result. The
		// repository Create path NULLs zero-length values so a
		// producer that couldn't derive a hash (NoopEnricher /
		// SightingFor short-circuit) persists SQL NULL rather
		// than the empty-byte sentinel.
		SenderHash:    append([]byte(nil), res.SenderHash...),
		RecipientHash: append([]byte(nil), res.RecipientHash...),
		CorrelationID: correlationID,
		Score:         res.Score,
		Tier:          string(res.Tier),
		Primary:       string(res.Primary),
		Secondary:     secondary,
		ReasonCodes:   reasons,
		Degraded:      res.Degraded,
		EvaluatedAt:   evaluatedAt,
	}
}
