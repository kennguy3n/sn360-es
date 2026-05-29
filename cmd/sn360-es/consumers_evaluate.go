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
	result, err := a.evaluator.Evaluate(ctx, req, a.signalEnricher.Enrich(ctx, req, req.Signals))
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}
	dto.BackfillRoutingFields(&result, req)
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
		return fmt.Errorf("publish evaluate.result: %w", err)
	}
	return nil
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
