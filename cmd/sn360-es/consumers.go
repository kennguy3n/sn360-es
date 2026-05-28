package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/internal/service/education"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// StartConsumers subscribes to the event subjects this binary handles.
// All subscriptions are tracked so StopConsumers can drain them in
// reverse order before the bus closes.
//
// Subscriptions are classified as critical or best-effort:
//
//   - critical: their dependent service is fully wired and we cannot
//     deliver the documented behaviour without them. A critical
//     subscription failure is returned as an error so the binary
//     fails fast instead of pretending to be healthy.
//   - best-effort: their dependent service is missing or the
//     subscription is purely opportunistic (e.g. DLQ log-only). We
//     log a warning and continue.
//
// In practice the management-persist consumer is critical when the
// repository layer is wired, and the education-trigger consumer is
// critical when the micro-lesson service is wired. The DLQ processor
// is always best-effort.
//
// INVARIANT (do not violate when adding new consumers): the three
// es.evaluate.result consumers (management-persist, education-trigger,
// ingestion-action) MUST be created here — before this method returns
// — so that the StreamEvaluateResult interest stream has every
// downstream consumer-group registered before the evaluate-svc
// consumer below starts producing onto es.evaluate.result. Interest
// retention discards messages for which no consumer is currently
// interested, so a publisher that wins the race against any of the
// three result consumers would lose that message permanently. The
// existing top-to-bottom ordering in this function (result consumers
// first, request consumer second) preserves the invariant. If you add
// a new result consumer, put it ABOVE the evaluate-svc subscription;
// if you add a new request consumer, put it AT OR AFTER the existing
// request consumer.
//
// Defense in depth: a fail-fast checkpoint between the result-side
// block and the evaluate-svc block aborts startup with an error
// before any producer is registered if ANY of the result consumer
// subscriptions failed. Without that early return, evaluate-svc
// would bind successfully even when a result consumer had errored
// out, and every message produced during the window between
// evaluate-svc binding and an operator restarting the binary would
// be permanently lost for the missing consumer (the alternative
// "log error and continue" pattern that was here before — and is
// still used for purely best-effort consumers below — is unsafe
// under interest retention). See the checkpoint just before the
// evaluate-svc subscription for the precise semantics.
func (a *application) StartConsumers(ctx context.Context) error {
	if a.eventBus == nil {
		return nil
	}

	// resultConsumerErrs is the narrow bucket that gates the
	// fail-fast checkpoint below: subscription failures on the
	// three es.evaluate.result durables (management-persist,
	// education-trigger, ingestion-action) are the ONLY errors
	// that can cause produce-while-missing-consumer data loss
	// against the ES_EVALUATE_RESULT interest stream. Failures on
	// other consumers (e.g. feedback-persist on the
	// work-queue–retention ES_ACTION stream) are still critical
	// for normal binary startup but cannot cause silent message
	// loss on the result fan-out, so they go into critErrs and
	// surface at the end of StartConsumers instead.
	var resultConsumerErrs []error
	var critErrs []error
	// resultSubsAttached counts the es.evaluate.result durables
	// that subscribed successfully. Used by the operability check
	// just before the evaluate-svc registration: if the evaluator
	// is wired but every result-side durable was either disabled
	// (nil dependency) or failed to subscribe, every result the
	// evaluator publishes will be immediately discarded by the
	// interest stream (no interested consumer to retain it for).
	// Better to refuse to start than to silently drop production
	// traffic.
	resultSubsAttached := 0

	// es.evaluate.result → persist to the management Postgres layer.
	if a.repos != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.result", a.handleEvaluateResult,
			events.WithDurable("management-persist"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe evaluate.result (management-persist) failed",
				slog.Any("error", err))
			resultConsumerErrs = append(resultConsumerErrs, fmt.Errorf("management-persist: %w", err))
		} else {
			a.trackSub(sub)
			resultSubsAttached++
		}
	}

	// es.evaluate.result → trigger contextual micro-lessons.
	if a.microLessonSvc != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.result", a.handleEducationTrigger,
			events.WithDurable("education-trigger"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe evaluate.result (education-trigger) failed",
				slog.Any("error", err))
			resultConsumerErrs = append(resultConsumerErrs, fmt.Errorf("education-trigger: %w", err))
		} else {
			a.trackSub(sub)
			resultSubsAttached++
		}
	}

	// es.action.feedback.> → persist each verified banner click into
	// feedback_events (migration 0002) so the dashboard FeedbackStats
	// aggregate has rows to count. This consumer is on ES_ACTION
	// (work-queue retention) so a subscription failure here cannot
	// cause interest-stream message loss — it just means feedback
	// rows won't be persisted until the binary restarts. We still
	// surface the error at end-of-function (the binary should not
	// silently degrade), but it does NOT gate the evaluate-svc
	// checkpoint below; see the comment block on resultConsumerErrs.
	if a.repos != nil && a.repos.FeedbackEvents != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.feedback.>", a.handleFeedbackPersist,
			events.WithDurable("feedback-persist"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe action.feedback (feedback-persist) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("feedback-persist: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.evaluate.result → ingestion-action chain: render the banner,
	// apply the native tier label, rewrite URLs for risky tiers, and
	// quarantine on Blocked.
	//
	// MUST be registered before the evaluate-svc consumer below so the
	// ES_EVALUATE_RESULT interest stream has all three result-side
	// durables (management-persist, education-trigger,
	// ingestion-action) bound before evaluate-svc starts producing
	// onto es.evaluate.result. See the INVARIANT block at the top of
	// StartConsumers.
	if a.bannerRenderer != nil || a.urlRewriter != nil || a.quarantineSvc != nil || a.labelApplier != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.result", a.handleIngestionAction,
			events.WithDurable("ingestion-action"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe evaluate.result (ingestion-action) failed",
				slog.Any("error", err))
			resultConsumerErrs = append(resultConsumerErrs, fmt.Errorf("ingestion-action: %w", err))
		} else {
			a.trackSub(sub)
			resultSubsAttached++
		}
	}

	// Fail-fast checkpoint — see INVARIANT block at the top of
	// StartConsumers. If ANY of the three wired
	// es.evaluate.result durables (management-persist,
	// education-trigger, ingestion-action) failed to subscribe,
	// we must NOT register evaluate-svc below: doing so would
	// start producing onto the ES_EVALUATE_RESULT interest stream
	// while one of the listed durables is missing. Under
	// InterestPolicy retention, every message produced before the
	// missing durable comes back online is permanently discarded
	// for that consumer; there is no work-queue backlog to replay
	// from once a result is acked by the consumers that DID
	// bind. Returning here trades a noisier startup failure for a
	// silent data-loss window.
	//
	// Note: feedback-persist failures are tracked in critErrs (not
	// resultConsumerErrs) because that durable lives on the
	// work-queue–retention ES_ACTION stream where the interest-loss
	// concern does NOT apply. They normally surface at the
	// end of StartConsumers via the final
	// errors.Join(critErrs...) return — but if we trip the
	// result-consumer checkpoint here we will never reach that
	// return, so we fold critErrs into the checkpoint error too
	// so the operator gets the complete failure picture on the
	// first restart attempt instead of fixing the result-consumer
	// issue and then discovering feedback-persist was also broken.
	//
	// (The Tier-1 batch orchestrator below is also gated by this
	// checkpoint, because it is the alternative producer onto
	// es.evaluate.result.)
	if len(resultConsumerErrs) > 0 {
		allErrs := append([]error(nil), resultConsumerErrs...)
		allErrs = append(allErrs, critErrs...)
		return fmt.Errorf("sn360-es: critical result-consumer subscription failed before evaluate-svc registration; refusing to start producers: %w",
			errors.Join(allErrs...))
	}

	// Operability check: refuse to register the evaluator (or the
	// Tier-1 batch orchestrator) if NO result-side durable would
	// retain the results it produces. Under InterestPolicy
	// retention, every message produced to es.evaluate.result is
	// immediately discarded if there are zero interested
	// consumers — there is no backlog to replay from. Rather than
	// silently dropping every evaluation, fail loudly so the
	// operator wires at least one of:
	//   - repos.* (management-persist)
	//   - microLessonSvc (education-trigger)
	//   - any of bannerRenderer / urlRewriter / quarantineSvc /
	//     labelApplier (ingestion-action)
	if resultSubsAttached == 0 && (a.evaluator != nil || a.batchOrch != nil) {
		return fmt.Errorf("sn360-es: evaluator is wired but no es.evaluate.result durable was attached (management-persist, education-trigger, ingestion-action); refusing to start producers because the ES_EVALUATE_RESULT interest stream would silently discard every result message")
	}

	// es.evaluate.request → the multi-tier detection pipeline.
	// Mutually exclusive with the Tier 1 batch orchestrator.
	//
	// Comes AFTER all three es.evaluate.result consumers above so the
	// interest stream cannot lose a produced result message to a
	// not-yet-bound durable.
	if a.evaluator != nil && a.batchOrch == nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.request", a.handleEvaluateRequest,
			events.WithDurable("evaluate-svc"),
			events.WithMaxDeliver(5))
		if err != nil {
			a.logger.Error("sn360-es: subscribe evaluate.request (evaluate-svc) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("evaluate-svc: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.action.label → apply tier + category native labels.
	if a.labelApplier != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.label", a.handleActionLabel,
			events.WithDurable("action-label"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe action.label (action-label) failed",
				slog.Any("error", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.action.banner → inject pre-rendered banner HTML.
	if a.providers != nil && a.providers.hasAny() {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.banner", a.handleActionBanner,
			events.WithDurable("action-banner"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe action.banner (action-banner) failed",
				slog.Any("error", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.action.url_rewrite → log + observe for now.
	if a.urlRewriter != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.url_rewrite", a.handleActionURLRewrite,
			events.WithDurable("action-url-rewrite"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe action.url_rewrite (action-url-rewrite) failed",
				slog.Any("error", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.action.quarantine → move Blocked-tier messages into the
	// hidden quarantine label / folder.
	if a.quarantineSvc != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.quarantine", a.handleActionQuarantine,
			events.WithDurable("action-quarantine"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe action.quarantine (action-quarantine) failed",
				slog.Any("error", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.education.simulation.send → dispatch a campaign.
	if a.simulationEng != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.education.simulation.send", a.handleSimulationSend,
			events.WithDurable("education-sim"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe education.simulation.send (education-sim) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("education-sim: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.education.simulation.result → record per-user interaction outcomes.
	if a.simulationTracker != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.education.simulation.result", a.handleSimulationResult,
			events.WithDurable("education-sim-track"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Warn("sn360-es: subscribe education.simulation.result (education-sim-track) failed",
				slog.Any("error", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.onboarding.> → onboarding side effects.
	sub, err := a.eventBus.Subscribe(ctx, "es.onboarding.>", a.handleOnboarding,
		events.WithDurable("ingestion-onboard"),
		events.WithMaxDeliver(3))
	if err != nil {
		a.logger.Warn("sn360-es: subscribe onboarding (ingestion-onboard) failed",
			slog.Any("error", err))
	} else {
		a.trackSub(sub)
	}

	// es.action.quarantine.release → user (or AI agent) released a
	// quarantined message.
	if a.releaseSvc != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.quarantine.release", a.handleQuarantineRelease,
			events.WithDurable("quarantine-release"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe quarantine.release (quarantine-release) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("quarantine-release: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// es.action.escalation.> → fan escalation events into EscalationService.
	if a.escalationSvc != nil {
		sub, err := a.eventBus.Subscribe(ctx, "es.action.escalation.>", a.handleEscalation,
			events.WithDurable("escalation"),
			events.WithMaxDeliver(3))
		if err != nil {
			a.logger.Error("sn360-es: subscribe escalation (escalation) failed",
				slog.Any("error", err))
			critErrs = append(critErrs, fmt.Errorf("escalation: %w", err))
		} else {
			a.trackSub(sub)
		}
	}

	// Final fail-fast: if any subscription above (es.action.*,
	// es.education.*, escalation, quarantine-release …) failed,
	// surface the joined error BEFORE we launch the Tier-1 batch
	// orchestrator or DLQ processor. Starting either of those two
	// background services and then returning an error leaves the
	// caller with running goroutines it can only clean up by
	// calling StopConsumers — a subtle lifecycle trap. Doing the
	// gate here means the orchestrator and DLQ are only started
	// once we know StartConsumers will return nil.
	if len(critErrs) > 0 {
		return fmt.Errorf("sn360-es: critical consumer subscriptions failed: %w",
			errors.Join(critErrs...))
	}

	// Optional Tier 1 batch orchestrator.
	if a.batchOrch != nil {
		a.batchOrch.Start(ctx)
		a.logger.Info("sn360-es: tier1 batch orchestrator started")
	}

	// DLQ processor — best-effort.
	dlq, derr := service.NewDLQProcessor(service.DLQProcessorConfig{
		Bus: a.eventBus,
		Decider: service.DeciderFunc(func(_ context.Context, _ events.Message) service.Decision {
			return service.Decision{Action: service.ActionLogOnly, Reason: "default"}
		}),
		Republisher: a.eventBus,
		Logger:      a.logger,
	})
	if derr != nil {
		a.logger.Warn("sn360-es: dlq processor init failed", slog.Any("error", derr))
	} else if serr := dlq.Start(ctx); serr != nil {
		a.logger.Warn("sn360-es: dlq processor start failed", slog.Any("error", serr))
	} else {
		a.dlqProc = dlq
	}

	return nil
}

// StopConsumers closes every subscription previously registered and
// stops the DLQ processor. Errors are logged but never returned.
func (a *application) StopConsumers(logger *slog.Logger) {
	if a.dlqProc != nil {
		if err := a.dlqProc.Stop(); err != nil {
			logger.Warn("sn360-es: dlq processor stop error", slog.Any("error", err))
		}
		a.dlqProc = nil
	}
	if a.batchOrch != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.batchOrch.Stop(stopCtx); err != nil {
			logger.Warn("sn360-es: tier1 batch orchestrator stop error", slog.Any("error", err))
		}
		a.batchOrch = nil
	}
	a.subsMu.Lock()
	subs := a.subs
	a.subs = nil
	a.subsMu.Unlock()
	for i := len(subs) - 1; i >= 0; i-- {
		if err := subs[i].Close(); err != nil {
			logger.Warn("sn360-es: subscription close error", slog.Any("error", err))
		}
	}
}

func (a *application) trackSub(sub events.Subscription) {
	a.subsMu.Lock()
	a.subs = append(a.subs, sub)
	a.subsMu.Unlock()
}

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

// handleFeedbackPersist writes each verified banner click into the
// feedback_events table.
func (a *application) handleFeedbackPersist(ctx context.Context, msg events.Message) error {
	if a.repos == nil || a.repos.FeedbackEvents == nil {
		return nil
	}
	var evt action.FeedbackEvent
	if err := json.Unmarshal(msg.Data(), &evt); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.feedback unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if evt.TenantID == "" || evt.PseudonymizedMessage == "" || !evt.Action.Valid() {
		a.logger.WarnContext(ctx, "sn360-es: action.feedback missing required fields",
			slog.String("tenant_id", evt.TenantID),
			slog.String("action", string(evt.Action)))
		return nil
	}
	occurred := evt.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	row := &repository.FeedbackEvent{
		TenantID:        evt.TenantID,
		PseudoMessageID: evt.PseudonymizedMessage,
		Action:          string(evt.Action),
		Tier:            evt.Tier,
		CorrelationID:   evt.CorrelationID,
		OccurredAt:      occurred,
	}
	if err := a.repos.FeedbackEvents.Create(ctx, row); err != nil {
		return fmt.Errorf("persist action.feedback: %w", err)
	}
	return nil
}

// handleEducationTrigger fans evaluation results out to the
// micro-lesson trigger subject.
func (a *application) handleEducationTrigger(ctx context.Context, msg events.Message) error {
	if a.eventBus == nil {
		return nil
	}
	var res dto.EvaluateResult
	if err := json.Unmarshal(msg.Data(), &res); err != nil {
		return nil
	}
	if !triggersLesson(res) {
		return nil
	}
	trigger := map[string]string{
		"tenant_id": res.TenantID,
		"category":  string(res.Primary),
		"tier":      string(res.Tier),
	}
	data, err := json.Marshal(trigger)
	if err != nil {
		return nil
	}
	opts := []events.PublishOption{
		events.WithTenantID(res.TenantID),
		events.WithCorrelationID(res.CorrelationID),
	}
	if err := a.eventBus.Publish(ctx, "es.education.trigger", data, opts...); err != nil {
		a.logger.ErrorContext(ctx, "sn360-es: education trigger publish failed; lesson trigger dropped",
			slog.String("tenant_id", res.TenantID),
			slog.String("correlation_id", res.CorrelationID),
			slog.String("tier", string(res.Tier)),
			slog.String("category", string(res.Primary)),
			slog.Any("error", err),
		)
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

// actionLabelEnvelope is the wire format published by
// handleIngestionAction on `es.action.label`.
type actionLabelEnvelope struct {
	TenantID      string            `json:"tenant_id"`
	MessageID     string            `json:"message_id"`
	CorrelationID string            `json:"correlation_id"`
	Tier          constant.Tier     `json:"tier"`
	Primary       constant.Category `json:"primary"`
	Email         string            `json:"email"`
}

// actionBannerEnvelope is the wire format published by
// handleIngestionAction on `es.action.banner`.
type actionBannerEnvelope struct {
	TenantID      string        `json:"tenant_id"`
	MessageID     string        `json:"message_id"`
	CorrelationID string        `json:"correlation_id"`
	Tier          constant.Tier `json:"tier"`
	HTML          string        `json:"html"`
	Email         string        `json:"email"`
}

// actionURLRewriteEnvelope is the wire format published by
// handleIngestionAction on `es.action.url_rewrite`.
type actionURLRewriteEnvelope struct {
	TenantID      string        `json:"tenant_id"`
	MessageID     string        `json:"message_id"`
	CorrelationID string        `json:"correlation_id"`
	Tier          constant.Tier `json:"tier"`
	Email         string        `json:"email"`
}

// actionQuarantineEnvelope is the wire format published by
// handleIngestionAction on `es.action.quarantine`.
type actionQuarantineEnvelope struct {
	TenantID      string            `json:"tenant_id"`
	MessageID     string            `json:"message_id"`
	CorrelationID string            `json:"correlation_id"`
	Tier          constant.Tier     `json:"tier"`
	Primary       constant.Category `json:"primary"`
	Score         int               `json:"score"`
	Email         string            `json:"email"`
}

// handleActionLabel applies the tier (and optional category) native
// label via the provider-aware LabelApplier.
func (a *application) handleActionLabel(ctx context.Context, msg events.Message) error {
	if a.labelApplier == nil || a.providers == nil {
		return nil
	}
	var env actionLabelEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.label unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.MessageID == "" || env.Email == "" {
		a.logger.DebugContext(ctx, "sn360-es: action.label missing identifiers",
			slog.String("tenant_id", env.TenantID),
			slog.String("message_id", env.MessageID),
			slog.Bool("has_email", env.Email != ""))
		return nil
	}
	kind := a.providers.resolveKind(env.TenantID)
	if kind == "" {
		a.logger.DebugContext(ctx, "sn360-es: action.label: no provider registered",
			slog.String("tenant_id", env.TenantID))
		return nil
	}
	res, err := a.labelApplier.Apply(ctx, action.LabelApplyRequest{
		Tenant:          env.TenantID,
		Provider:        kind,
		Email:           env.Email,
		MessageID:       env.MessageID,
		NewTier:         env.Tier,
		PrimaryCategory: env.Primary,
	})
	if err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.label: applier failed",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)),
			slog.Any("error", err))
		return nil
	}
	a.logger.DebugContext(ctx, "sn360-es: action.label applied",
		slog.String("tenant_id", env.TenantID),
		slog.String("provider", string(kind)),
		slog.String("tier", string(env.Tier)),
		slog.Bool("category_applied", res.SubCategoryID != ""))
	return nil
}

// handleActionBanner splices the pre-rendered banner HTML into the
// recipient's mailbox.
func (a *application) handleActionBanner(ctx context.Context, msg events.Message) error {
	if a.providers == nil {
		return nil
	}
	var env actionBannerEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.banner unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.MessageID == "" || env.HTML == "" || env.Email == "" {
		return nil
	}
	kind := a.providers.resolveKind(env.TenantID)
	if kind == "" {
		return nil
	}
	inj := a.providers.bannerInjectorFor(env.TenantID, kind)
	if inj == nil {
		return nil
	}
	if err := inj.InjectBanner(ctx, action.BannerInjectRequest{
		Tenant:    env.TenantID,
		Provider:  kind,
		Email:     env.Email,
		MessageID: env.MessageID,
		HTML:      []byte(env.HTML),
	}); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.banner: inject failed",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)),
			slog.Any("error", err))
		return nil
	}
	a.logger.DebugContext(ctx, "sn360-es: action.banner injected",
		slog.String("tenant_id", env.TenantID),
		slog.String("provider", string(kind)),
		slog.Int("html_bytes", len(env.HTML)))
	return nil
}

// handleActionURLRewrite rewrites URLs in the message body.
func (a *application) handleActionURLRewrite(ctx context.Context, msg events.Message) error {
	if a.urlRewriter == nil {
		return nil
	}
	var env actionURLRewriteEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.url_rewrite unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.MessageID == "" || env.Email == "" {
		return nil
	}
	if a.providers == nil {
		return nil
	}

	kind := a.providers.resolveKind(env.TenantID)
	if kind == "" {
		a.logger.DebugContext(ctx, "sn360-es: action.url_rewrite: no provider registered",
			slog.String("tenant_id", env.TenantID))
		return nil
	}

	bw := a.providers.bodyRewriterFor(env.TenantID, kind)
	if bw == nil {
		a.logger.DebugContext(ctx, "sn360-es: action.url_rewrite: no body rewriter for provider",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)))
		return nil
	}

	svc := &action.URLRewriteService{
		Rewriter: a.urlRewriter,
		Logger:   a.logger,
	}
	if err := svc.RewriteBody(ctx, bw, action.BodyRewriteRequest{
		Tenant:    env.TenantID,
		Provider:  kind,
		Email:     env.Email,
		MessageID: env.MessageID,
	}, string(env.Tier)); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.url_rewrite failed",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)),
			slog.Any("error", err))
		return nil
	}
	return nil
}

// handleActionQuarantine moves a Blocked-tier message into the
// hidden quarantine label.
func (a *application) handleActionQuarantine(ctx context.Context, msg events.Message) error {
	if a.quarantineSvc == nil || a.providers == nil {
		return nil
	}
	var env actionQuarantineEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.quarantine unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.MessageID == "" || env.Email == "" {
		return nil
	}
	if env.Tier != constant.TierBlocked {
		return nil
	}
	kind := a.providers.resolveKind(env.TenantID)
	if kind == "" {
		return nil
	}
	if _, err := a.quarantineSvc.Quarantine(ctx, action.QuarantineRequest{
		Tenant:               env.TenantID,
		PseudonymizedMessage: env.MessageID,
		Provider:             kind,
		Email:                env.Email,
		MessageID:            env.MessageID,
		Tier:                 env.Tier,
		Primary:              env.Primary,
	}); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: action.quarantine: quarantine failed",
			slog.String("tenant_id", env.TenantID),
			slog.String("provider", string(kind)),
			slog.Any("error", err))
		return nil
	}
	a.logger.InfoContext(ctx, "sn360-es: action.quarantine applied",
		slog.String("tenant_id", env.TenantID),
		slog.String("provider", string(kind)),
		slog.String("primary", string(env.Primary)),
		slog.Int("score", env.Score))
	return nil
}

// handleIngestionAction renders the banner, rewrites risky URLs, and
// triggers a quarantine reference for Blocked verdicts.
func (a *application) handleIngestionAction(ctx context.Context, msg events.Message) error {
	var res dto.EvaluateResult
	if err := json.Unmarshal(msg.Data(), &res); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: evaluate.result unmarshal failed in ingestion-action",
			slog.Any("error", err))
		return nil
	}
	if res.MessageID == "" || res.TenantID == "" {
		return nil
	}

	// 1. Banner
	if a.bannerRenderer != nil && res.Tier.Valid() && res.Tier != constant.TierTrusted {
		locale := a.cfg.Banner.DefaultLocale
		if locale == "" {
			locale = "en"
		}
		input := action.BannerInput{
			Tier:        res.Tier,
			Primary:     res.Primary,
			Secondary:   res.Secondary,
			ReasonCodes: res.ReasonCodes,
			Locale:      locale,
			Degraded:    res.Degraded,
		}
		if a.jwtIssuer != nil {
			if tok, terr := a.jwtIssuer.Issue(res.TenantID, res.MessageID, privacy.IssueOptions{
				Tier: string(res.Tier),
			}); terr == nil {
				input.ActionToken = tok
			} else {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: issue banner token failed",
					slog.String("tenant_id", res.TenantID),
					slog.Any("error", terr))
			}
		}
		if html, rerr := a.bannerRenderer.Render(input); rerr != nil {
			a.logger.WarnContext(ctx, "sn360-es: ingestion-action: banner render failed",
				slog.String("tenant_id", res.TenantID),
				slog.String("message_id", res.MessageID),
				slog.Any("error", rerr))
		} else {
			bannerEvt := map[string]any{
				"tenant_id":      res.TenantID,
				"message_id":     res.MessageID,
				"correlation_id": res.CorrelationID,
				"tier":           res.Tier,
				"html":           string(html),
				"email":          res.Recipient,
			}
			if blob, merr := json.Marshal(bannerEvt); merr == nil {
				if perr := a.eventBus.Publish(ctx, "es.action.banner", blob,
					events.WithTenantID(res.TenantID),
					events.WithCorrelationID(res.CorrelationID),
					events.WithEventType("action.banner"),
					events.WithTraceContext(ctx),
				); perr != nil {
					a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish banner failed",
						slog.Any("error", perr))
				}
			}
		}
	}

	// 2. URL rewriting
	if a.urlRewriter != nil && (res.Tier == constant.TierBlocked || res.Tier == constant.TierHighRisk) {
		signal := map[string]any{
			"tenant_id":      res.TenantID,
			"message_id":     res.MessageID,
			"correlation_id": res.CorrelationID,
			"tier":           res.Tier,
			"email":          res.Recipient,
		}
		if blob, merr := json.Marshal(signal); merr == nil {
			if perr := a.eventBus.Publish(ctx, "es.action.url_rewrite", blob,
				events.WithTenantID(res.TenantID),
				events.WithCorrelationID(res.CorrelationID),
				events.WithEventType("action.url_rewrite"),
				events.WithTraceContext(ctx),
			); perr != nil {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish url_rewrite signal failed",
					slog.Any("error", perr))
			}
		}
	}

	// 3. Quarantine
	if res.Tier == constant.TierBlocked {
		signal := map[string]any{
			"tenant_id":      res.TenantID,
			"message_id":     res.MessageID,
			"correlation_id": res.CorrelationID,
			"tier":           res.Tier,
			"primary":        res.Primary,
			"score":          res.Score,
			"email":          res.Recipient,
		}
		if blob, merr := json.Marshal(signal); merr == nil {
			if perr := a.eventBus.Publish(ctx, "es.action.quarantine", blob,
				events.WithTenantID(res.TenantID),
				events.WithCorrelationID(res.CorrelationID),
				events.WithEventType("action.quarantine"),
				events.WithTraceContext(ctx),
			); perr != nil {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish quarantine signal failed",
					slog.Any("error", perr))
			}
		}
	}

	// 4. Native label
	if res.Tier.Valid() && res.Tier != constant.TierTrusted {
		signal := map[string]any{
			"tenant_id":      res.TenantID,
			"message_id":     res.MessageID,
			"correlation_id": res.CorrelationID,
			"tier":           res.Tier,
			"primary":        res.Primary,
			"email":          res.Recipient,
		}
		if blob, merr := json.Marshal(signal); merr == nil {
			if perr := a.eventBus.Publish(ctx, "es.action.label", blob,
				events.WithTenantID(res.TenantID),
				events.WithCorrelationID(res.CorrelationID),
				events.WithEventType("action.label"),
				events.WithTraceContext(ctx),
			); perr != nil {
				a.logger.WarnContext(ctx, "sn360-es: ingestion-action: publish label signal failed",
					slog.Any("error", perr))
			}
		}
	}

	return nil
}

// simulationSendEnvelope is the wire format expected on
// `es.education.simulation.send`.
type simulationSendEnvelope struct {
	CampaignID string                         `json:"campaign_id"`
	Targets    []simulationSendTargetEnvelope `json:"targets"`
	Params     map[string]string              `json:"params,omitempty"`
}

type simulationSendTargetEnvelope struct {
	UserHash     string `json:"user_hash"`
	MailboxAlias string `json:"mailbox_alias"`
	DisplayName  string `json:"display_name,omitempty"`
}

// handleSimulationSend dispatches a campaign through SimulationEngine.
func (a *application) handleSimulationSend(ctx context.Context, msg events.Message) error {
	if a.simulationEng == nil {
		return nil
	}
	var env simulationSendEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.CampaignID == "" {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send missing campaign_id")
		return nil
	}
	if len(env.Targets) == 0 {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send dropped: empty targets",
			slog.String("campaign_id", env.CampaignID))
		return nil
	}
	targets := make([]education.SimulationTarget, 0, len(env.Targets))
	for _, t := range env.Targets {
		if t.UserHash == "" || t.MailboxAlias == "" {
			continue
		}
		targets = append(targets, education.SimulationTarget{
			UserHash:     t.UserHash,
			MailboxAlias: t.MailboxAlias,
			DisplayName:  t.DisplayName,
		})
	}
	if len(env.Targets) > 0 && len(targets) == 0 {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send filter dropped all targets",
			slog.String("campaign_id", env.CampaignID),
			slog.Int("raw_targets", len(env.Targets)))
		return nil
	}
	if _, err := a.simulationEng.SendSimulation(ctx, env.CampaignID, targets, env.Params); err != nil {
		return fmt.Errorf("simulation.send: %w", err)
	}
	return nil
}

// handleSimulationResult records an interaction event into the tracker.
func (a *application) handleSimulationResult(ctx context.Context, msg events.Message) error {
	if a.simulationTracker == nil {
		return nil
	}
	var interaction dto.UserInteraction
	if err := json.Unmarshal(msg.Data(), &interaction); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.result unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if interaction.CampaignID == "" || interaction.UserHash == "" || !interaction.Action.Valid() {
		return nil
	}
	if _, err := a.simulationTracker.RecordInteraction(ctx,
		interaction.CampaignID, interaction.UserHash, interaction.Action); err != nil {
		return fmt.Errorf("simulation.result: %w", err)
	}
	return nil
}

// handleOnboarding dispatches by subject suffix.
func (a *application) handleOnboarding(ctx context.Context, msg events.Message) error {
	subject := msg.Subject()
	switch {
	case strings.HasSuffix(subject, ".tenant.created"):
		if a.onboardAgent != nil {
			var env struct {
				TenantID string `json:"tenant_id"`
				Provider string `json:"provider"`
			}
			if err := json.Unmarshal(msg.Data(), &env); err != nil {
				a.logger.WarnContext(ctx, "sn360-es: onboarding.tenant.created unmarshal failed",
					slog.Any("error", err))
				return nil
			}
			if env.TenantID == "" {
				return nil
			}
			p := agent.Provider(env.Provider)
			if !p.Valid() || p == agent.ProviderUnknown {
				a.logger.WarnContext(ctx, "sn360-es: onboarding.tenant.created unknown provider, skipping",
					slog.String("tenant_id", env.TenantID),
					slog.String("provider", env.Provider))
				return nil
			}
			tctx := agent.TenantContext{
				TenantID:  env.TenantID,
				Provider:  p,
				StartedAt: time.Now().UTC(),
			}
			if a.draining.Load() {
				a.logger.WarnContext(ctx, "sn360-es: onboarding.tenant.created rejected (draining)",
					slog.String("tenant_id", env.TenantID))
				return nil
			}
			a.bgWG.Add(1)
			go func() {
				defer a.bgWG.Done()
				bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
				defer cancel()
				if _, err := a.onboardAgent.Onboard(bgCtx, tctx); err != nil {
					a.logger.Error("sn360-es: onboarding agent failed",
						slog.String("tenant_id", env.TenantID),
						slog.Any("error", err))
				}
			}()
		} else {
			a.logger.InfoContext(ctx, "sn360-es: onboarding event received (agent not wired)",
				slog.String("subject", subject))
		}
	case strings.HasSuffix(subject, ".user.created"),
		strings.HasSuffix(subject, ".user.deleted"),
		strings.HasSuffix(subject, ".vendor.seeded"):
		a.logger.InfoContext(ctx, "sn360-es: onboarding event received",
			slog.String("subject", subject),
			slog.Int("bytes", len(msg.Data())))
	default:
		a.logger.DebugContext(ctx, "sn360-es: onboarding event ignored (unknown suffix)",
			slog.String("subject", subject))
	}
	return nil
}

// quarantineReleaseEnvelope is the wire format for the release flow.
type quarantineReleaseEnvelope struct {
	TenantID             string `json:"tenant_id"`
	PseudonymizedMessage string `json:"pseudonymized_message_id"`
	RequestedBy          string `json:"requested_by,omitempty"`
	RestoredBody         string `json:"restored_body,omitempty"`
	CorrelationID        string `json:"correlation_id,omitempty"`
}

// handleQuarantineRelease calls ReleaseService.Release.
func (a *application) handleQuarantineRelease(ctx context.Context, msg events.Message) error {
	if a.releaseSvc == nil {
		return nil
	}
	var env quarantineReleaseEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: quarantine.release unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.TenantID == "" || env.PseudonymizedMessage == "" {
		return nil
	}
	if _, err := a.releaseSvc.Release(ctx, action.ReleaseRequest{
		TenantID:             env.TenantID,
		PseudonymizedMessage: env.PseudonymizedMessage,
		RequestedBy:          env.RequestedBy,
		RestoredBody:         env.RestoredBody,
		CorrelationID:        env.CorrelationID,
	}); err != nil {
		return fmt.Errorf("quarantine.release: %w", err)
	}
	return nil
}

// escalationCreateEnvelope and escalationResolveEnvelope are the wire
// formats for the two escalation subjects.
type escalationCreateEnvelope struct {
	TenantID string                 `json:"tenant_id"`
	Incident dto.EscalationIncident `json:"incident"`
}

type escalationResolveEnvelope struct {
	TicketID     string                `json:"ticket_id"`
	ResolverHash string                `json:"resolver_hash"`
	Outcome      dto.EscalationOutcome `json:"outcome"`
	Notes        string                `json:"notes,omitempty"`
}

// handleEscalation dispatches by subject suffix between Escalate and
// ResolveEscalation.
func (a *application) handleEscalation(ctx context.Context, msg events.Message) error {
	if a.escalationSvc == nil {
		return nil
	}
	subject := msg.Subject()
	switch {
	case strings.HasSuffix(subject, ".created"):
		var env escalationCreateEnvelope
		if err := json.Unmarshal(msg.Data(), &env); err != nil {
			a.logger.WarnContext(ctx, "sn360-es: escalation.created unmarshal failed",
				slog.Any("error", err))
			return nil
		}
		if env.TenantID == "" {
			return nil
		}
		if _, err := a.escalationSvc.Escalate(ctx, env.TenantID, env.Incident); err != nil {
			return fmt.Errorf("escalation.created: %w", err)
		}
	case strings.HasSuffix(subject, ".resolved"):
		var env escalationResolveEnvelope
		if err := json.Unmarshal(msg.Data(), &env); err != nil {
			a.logger.WarnContext(ctx, "sn360-es: escalation.resolved unmarshal failed",
				slog.Any("error", err))
			return nil
		}
		if env.TicketID == "" {
			return nil
		}
		if _, err := a.escalationSvc.ResolveEscalation(ctx, env.TicketID, env.ResolverHash, env.Outcome, env.Notes); err != nil {
			return fmt.Errorf("escalation.resolved: %w", err)
		}
	default:
		a.logger.DebugContext(ctx, "sn360-es: escalation event ignored (unknown suffix)",
			slog.String("subject", subject))
	}
	return nil
}

// triggersLesson reports whether the evaluation tier warrants a
// contextual micro-lesson.
func triggersLesson(res dto.EvaluateResult) bool {
	switch res.Tier {
	case constant.TierWarning, constant.TierHighRisk, constant.TierBlocked:
		return true
	}
	return false
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
