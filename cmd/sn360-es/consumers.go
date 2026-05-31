package main

// consumers.go owns subscription orchestration (StartConsumers /
// StopConsumers / trackSub) and the small set of "non-domain" handlers
// that did not fit into a single bounded context. Domain-specific
// handlers live in:
//
//   - consumers_evaluate.go   evaluate.request + evaluate.result
//   - consumers_action.go     ingestion-action chain + per-action
//                             handlers + quarantine.release
//   - consumers_education.go  education.trigger + simulation.*
//
// Splitting the file is purely structural; the runtime behaviour is
// unchanged.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/pkg/events"
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
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.result", a.tenantBoundMessageHandler(a.handleEvaluateResult),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.result", a.tenantBoundMessageHandler(a.handleEducationTrigger),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.action.feedback.>", a.tenantBoundMessageHandler(a.handleFeedbackPersist),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.result", a.tenantBoundMessageHandler(a.handleIngestionAction),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.evaluate.request", a.tenantBoundMessageHandler(a.handleEvaluateRequest),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.action.label", a.tenantBoundMessageHandler(a.handleActionLabel),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.action.banner", a.tenantBoundMessageHandler(a.handleActionBanner),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.action.url_rewrite", a.tenantBoundMessageHandler(a.handleActionURLRewrite),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.action.quarantine", a.tenantBoundMessageHandler(a.handleActionQuarantine),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.education.simulation.send", a.tenantBoundMessageHandler(a.handleSimulationSend),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.education.simulation.result", a.tenantBoundMessageHandler(a.handleSimulationResult),
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
	// NOTE: handleOnboarding spawns a 10-min background goroutine via
	// context.WithoutCancel, which would inherit (and outlive) any
	// per-message bound conn attached by tenantBoundMessageHandler.
	// Wrapping here would cause the goroutine's DB calls to fail with
	// "conn already closed" once the outer handler returns and the
	// wrapper's defer release() runs. Instead the goroutine acquires
	// its OWN WithTenant binding inside handleOnboarding, which keeps
	// the goroutine's writes under RLS for the full 10-min window
	// without the bound conn being released out from under it. The
	// outer (non-goroutine) path in handleOnboarding does no DB work,
	// so leaving it unbound is safe.
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
		sub, err := a.eventBus.Subscribe(ctx, "es.action.quarantine.release", a.tenantBoundMessageHandler(a.handleQuarantineRelease),
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
		sub, err := a.eventBus.Subscribe(ctx, "es.action.escalation.>", a.tenantBoundMessageHandler(a.handleEscalation),
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
				// Acquire a per-goroutine tenant binding so the
				// onboarding agent's DB writes (PersistDiscoveredUsers,
				// UpdateWeights, Audit.Record, …) run under the RLS
				// policy installed by migration 0018. We MUST bind here
				// rather than rely on the consumer-side wrapper: the
				// wrapper's bound conn is released the instant
				// handleOnboarding returns, which is up to 10 minutes
				// before this goroutine finishes. pgDB == nil in
				// in-memory mode is treated as a no-op (the agent's DB
				// dependencies are also nil in that mode).
				if a.pgDB != nil {
					boundCtx, release, berr := a.pgDB.WithTenant(bgCtx, env.TenantID)
					if berr != nil {
						a.logger.Error("sn360-es: onboarding agent — tenant bind failed",
							slog.String("tenant_id", env.TenantID),
							slog.Any("error", berr))
						return
					}
					defer func() { _ = release() }()
					bgCtx = boundCtx
				}
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

// escalationCreateEnvelope and escalationResolveEnvelope are the wire
// formats for the two escalation subjects.
type escalationCreateEnvelope struct {
	TenantID string                 `json:"tenant_id"`
	Incident dto.EscalationIncident `json:"incident"`
}

type escalationResolveEnvelope struct {
	// TenantID is the canonical tenant scoping for the resolution.
	// The consumer sources tenantID preferentially from the verified
	// message header on the NATS subject (events.HeaderTenantID),
	// falling back to this JSON body field only when the header is
	// absent — a transitional shim for older publishers during the
	// header rollout, see verifiedTenantID. The header path is
	// trusted because the publisher's outbox/middleware stamps it
	// after authentication; the body fallback is less trusted but
	// the downstream store's tenant-scoped LoadForUpdate/Update
	// prevents a crafted body from resolving a different tenant's
	// ticket (the ticket_id+tenant_id composite key would simply
	// fail to match). The field is also kept in the JSON so tests
	// can construct envelopes directly.
	TenantID     string                `json:"tenant_id,omitempty"`
	TicketID     string                `json:"ticket_id"`
	ResolverHash string                `json:"resolver_hash"`
	Outcome      dto.EscalationOutcome `json:"outcome"`
	Notes        string                `json:"notes,omitempty"`
}

// verifiedTenantID returns the tenant_id stamped on the message's
// verified header, falling back to the (less-trusted) JSON body field
// only if the publisher did not stamp a header. This is the trust
// boundary for cross-domain event traffic: the header is set by the
// publisher’s outbox/middleware after authentication; a malformed
// publisher that omits the header but lies in the body should not be
// able to smuggle in a different tenant. The body fallback exists to
// stay compatible with older publishers during a rollout window and is
// safe because the downstream service layer still rejects empty
// tenantIDs.
func verifiedTenantID(msg events.Message, bodyFallback string) string {
	if tid := msg.Headers()[events.HeaderTenantID]; tid != "" {
		return tid
	}
	return bodyFallback
}

// tenantBoundMessageHandler wraps inner so every invocation runs with
// a Postgres conn pinned to the message's tenant — the consumer-side
// analogue of the HTTP TenantConnBinder middleware. This is what
// makes the RLS policy installed in
// `migrations/0018_row_level_security.up.sql` apply to consumer
// writes the same way it applies to HTTP requests.
//
// The tenant id is sourced from the verified NATS header (see
// verifiedTenantID); we deliberately do NOT peek into the JSON body
// here because that would couple this generic wrapper to every
// envelope shape the handlers consume. If the header is missing
// (legacy publisher) the wrapper passes through without binding —
// the downstream handler is then responsible for refusing the
// message via its body-level tenant_id check, just as it does today.
// pgDB == nil (in-memory mode / unit tests) also passes through.
func (a *application) tenantBoundMessageHandler(inner func(context.Context, events.Message) error) func(context.Context, events.Message) error {
	if a == nil || a.pgDB == nil {
		return inner
	}
	return func(ctx context.Context, msg events.Message) error {
		tenantID := msg.Headers()[events.HeaderTenantID]
		if tenantID == "" {
			return inner(ctx, msg)
		}
		boundCtx, release, err := a.pgDB.WithTenant(ctx, tenantID)
		if err != nil {
			a.logger.WarnContext(ctx, "sn360-es: consumer tenant_conn bind failed",
				slog.String("tenant_id", tenantID),
				slog.String("subject", msg.Subject()),
				slog.Any("error", err))
			// Returning the error triggers NATS redelivery; with
			// a transient pool-exhaustion failure that's the
			// right thing (let JetStream's MaxDeliver back-off
			// pace the retry). Permanently-failed binds (e.g.
			// the DB is gone) will exhaust deliveries and end up
			// on the DLQ — explicit signalling, not silent drop.
			return fmt.Errorf("tenant_conn bind: %w", err)
		}
		defer func() {
			if relErr := release(); relErr != nil {
				a.logger.WarnContext(ctx, "sn360-es: consumer tenant_conn release failed",
					slog.String("tenant_id", tenantID),
					slog.String("subject", msg.Subject()),
					slog.Any("error", relErr))
			}
		}()
		return inner(boundCtx, msg)
	}
}

// handleEscalation dispatches by subject suffix between Escalate and
// ResolveEscalation. Both branches source tenantID from the verified
// header in preference to the JSON body — see verifiedTenantID.
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
		tenantID := verifiedTenantID(msg, env.TenantID)
		if tenantID == "" {
			a.logger.WarnContext(ctx, "sn360-es: escalation.created missing tenant_id")
			return nil
		}
		if _, err := a.escalationSvc.Escalate(ctx, tenantID, env.Incident); err != nil {
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
		tenantID := verifiedTenantID(msg, env.TenantID)
		if tenantID == "" {
			a.logger.WarnContext(ctx, "sn360-es: escalation.resolved missing tenant_id",
				slog.String("ticket_id", env.TicketID))
			return nil
		}
		if _, err := a.escalationSvc.ResolveEscalation(ctx, tenantID, env.TicketID, env.ResolverHash, env.Outcome, env.Notes); err != nil {
			return fmt.Errorf("escalation.resolved: %w", err)
		}
	default:
		a.logger.DebugContext(ctx, "sn360-es: escalation event ignored (unknown suffix)",
			slog.String("subject", subject))
	}
	return nil
}
