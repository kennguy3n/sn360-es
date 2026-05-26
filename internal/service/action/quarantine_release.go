package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// QuarantineReevaluator runs a Tier 0 + Tier 1 re-evaluation pass on
// the privacy-safe identifier (pseudonymised message) and returns the
// updated verdict. The release flow uses the returned verdict to
// decide whether to restore the message.
type QuarantineReevaluator interface {
	Reevaluate(ctx context.Context, tenantID, pseudoMessageID string) (dto.EvaluateResult, error)
}

// ReleaseReason enumerates the outcomes of a release request. The
// values are emitted on the release event so downstream analytics can
// trend them over time.
type ReleaseReason string

const (
	// ReleaseAllowed means the verdict no longer warrants blocking
	// and the message was restored to the user's inbox.
	ReleaseAllowed ReleaseReason = "allowed"
	// ReleaseRefused means the message is still blocked after re-
	// evaluation; the original quarantine remains intact.
	ReleaseRefused ReleaseReason = "refused"
	// ReleaseNotFound means the (tenant, message) pair has no
	// matching quarantine record. Callers should treat this as a
	// 404 / no-op.
	ReleaseNotFound ReleaseReason = "not_found"
	// ReleaseAlreadyDone means a concurrent release flow claimed and
	// restored the record before this one could (see ClaimReference
	// fencing). The caller should treat the outcome as a no-op
	// success: the user got the message restored, just by a
	// different flow.
	ReleaseAlreadyDone ReleaseReason = "already_done"
)

// ReleaseOutcome carries the resolved verdict back to the caller.
type ReleaseOutcome struct {
	Reason       ReleaseReason      `json:"reason"`
	Verdict      dto.EvaluateResult `json:"verdict"`
	Original     constant.Tier      `json:"original_tier"`
	Restored     bool               `json:"restored"`
	ReportPath   string             `json:"report_path,omitempty"`
	Explanations []string           `json:"explanations,omitempty"`
	Record       QuarantineRecord   `json:"record,omitempty"`
	OccurredAt   time.Time          `json:"occurred_at"`
}

// ReleaseRequest is the input to ReleaseService.Release. RequestedBy
// is the pseudonymised hash of the user requesting the release so
// audits can join against the support agent's records.
type ReleaseRequest struct {
	TenantID             string
	PseudonymizedMessage string
	RequestedBy          string
	// RestoredBody, when non-empty, is the body the provider will
	// see when the stub is replaced. The caller (usually the AI
	// Support Agent) owns the copy; the release service treats it as
	// opaque.
	RestoredBody string
	// CorrelationID propagates upstream tracing through the release
	// flow. It is forwarded onto the published outcome event so the
	// release can be joined back to the original evaluation (or the
	// HTTP request / bus message that started the release) without
	// needing to round-trip through the quarantine store.
	CorrelationID string
}

// ReleaseConfig wires the release service's dependencies. The
// service depends on a QuarantineService (for the persisted record
// and provider lookup), a re-evaluator, and the event bus publisher.
type ReleaseConfig struct {
	Logger      *slog.Logger
	Quarantine  *QuarantineService
	Reevaluator QuarantineReevaluator
	Publisher   QuarantinePublisher
	// ReleaseSubject is the NATS subject used for release outcomes
	// (default "es.action.quarantine.release").
	ReleaseSubject string
	// MinReleaseTier is the lowest tier severity that still triggers a
	// refusal. Defaults to TierBlocked. The comparison is inclusive: a
	// new verdict whose severity is >= MinReleaseTier.Severity() is
	// refused; verdicts strictly below MinReleaseTier are released.
	//
	// SecOps tighten the gate by configuring a less-severe tier: e.g.
	// MinReleaseTier=TierWarning causes any verdict at Warning, HighRisk,
	// or Blocked to be refused (only Caution / Informational / Trusted
	// release). MinReleaseTier=TierTrusted is technically valid but
	// refuses every release (logged at WARN in NewReleaseService).
	MinReleaseTier constant.Tier
}

// ReleaseService coordinates the release flow: it re-evaluates a
// previously quarantined message, restores it when the verdict
// clears, or refuses with reasons and an FP-report path when it is
// still blocking.
type ReleaseService struct {
	logger         *slog.Logger
	quarantine     *QuarantineService
	reevaluator    QuarantineReevaluator
	publisher      QuarantinePublisher
	subject        string
	minReleaseTier constant.Tier
}

// NewReleaseService validates the config and returns a ReleaseService.
// quarantine and reevaluator are required.
func NewReleaseService(cfg ReleaseConfig) (*ReleaseService, error) {
	if cfg.Quarantine == nil {
		return nil, errors.New("release: quarantine service is required")
	}
	if cfg.Reevaluator == nil {
		return nil, errors.New("release: re-evaluator is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	subject := cfg.ReleaseSubject
	if subject == "" {
		subject = "es.action.quarantine.release"
	}
	minTier := cfg.MinReleaseTier
	if !minTier.Valid() {
		minTier = constant.TierBlocked
	}
	// TierTrusted is severity 0, so isStillBlocked(tier, TierTrusted)
	// is true for every valid tier — every release request is refused.
	// This is rarely intended; surface a one-time warning rather than
	// silently disabling the release flow.
	if minTier == constant.TierTrusted {
		logger.Warn(
			"release: MinReleaseTier is TierTrusted; every release request will be refused. Verify the SecOps configuration.",
		)
	}
	return &ReleaseService{
		logger:         logger,
		quarantine:     cfg.Quarantine,
		reevaluator:    cfg.Reevaluator,
		publisher:      cfg.Publisher,
		subject:        subject,
		minReleaseTier: minTier,
	}, nil
}

// Release runs the full release flow: look up the encrypted record,
// re-evaluate, and either restore or refuse. The outcome is always
// published on the release subject (best-effort).
func (s *ReleaseService) Release(ctx context.Context, req ReleaseRequest) (ReleaseOutcome, error) {
	if req.TenantID == "" || req.PseudonymizedMessage == "" {
		return ReleaseOutcome{}, fmt.Errorf("%w: tenant and pseudonymized_message are required", ErrInvalidInput)
	}

	rec, found, err := s.quarantine.LookupReference(ctx, req.TenantID, req.PseudonymizedMessage)
	if err != nil {
		return ReleaseOutcome{}, fmt.Errorf("release: lookup reference: %w: %w", ErrProviderUnavailable, err)
	}
	if !found {
		outcome := ReleaseOutcome{
			Reason:     ReleaseNotFound,
			OccurredAt: time.Now().UTC(),
		}
		s.publishOutcome(ctx, req, outcome)
		return outcome, nil
	}

	verdict, err := s.reevaluator.Reevaluate(ctx, req.TenantID, req.PseudonymizedMessage)
	if err != nil {
		return ReleaseOutcome{}, fmt.Errorf("release: re-evaluate: %w: %w", ErrProviderUnavailable, err)
	}

	outcome := ReleaseOutcome{
		Verdict:    verdict,
		Original:   rec.OriginalTier,
		Record:     rec,
		OccurredAt: time.Now().UTC(),
	}

	if isStillBlocked(verdict.Tier, s.minReleaseTier) {
		outcome.Reason = ReleaseRefused
		outcome.Explanations = collectReleaseReasons(verdict)
		outcome.ReportPath = "/v1/banner/action"
		s.logger.InfoContext(ctx, "action.quarantine.release refused",
			slog.String("tenant_id", req.TenantID),
			slog.String("tier", string(verdict.Tier)),
		)
		s.publishOutcome(ctx, req, outcome)
		return outcome, nil
	}

	// Verdict cleared; atomically claim the reference before
	// mutating the provider. ClaimReference is the application-
	// layer fencing token that defends against a split-brain Redis
	// lock causing two concurrent release flows to both call
	// RestoreFromQuarantine on the same message. Only one flow
	// wins the GETDEL race; the loser short-circuits with
	// ReleaseAlreadyDone.
	claimedRec, claimed, err := s.quarantine.ClaimReference(ctx, req.TenantID, req.PseudonymizedMessage)
	if err != nil {
		return outcome, fmt.Errorf("release: claim reference: %w: %w", ErrProviderUnavailable, err)
	}
	if !claimed {
		// Another release flow took ownership of this record before
		// we could. The user's intent (restore the message) is
		// already in flight on the winning replica; treat this as a
		// successful no-op so the caller doesn't surface a spurious
		// 4xx/5xx.
		outcome.Reason = ReleaseAlreadyDone
		s.logger.InfoContext(ctx, "action.quarantine.release deduplicated",
			slog.String("tenant_id", req.TenantID),
		)
		s.publishOutcome(ctx, req, outcome)
		return outcome, nil
	}
	// Use the freshly-claimed record so we restore against the
	// provider state captured at claim time, not the pre-Reevaluate
	// state.
	rec = claimedRec
	outcome.Record = rec
	outcome.Original = rec.OriginalTier

	prov, ok := s.quarantine.Provider(rec.Provider)
	if !ok {
		// No provider for the kind we just claimed. Re-persist so the
		// record isn't permanently orphaned and surface the error.
		if rerr := s.quarantine.RestoreReference(ctx, req.TenantID, req.PseudonymizedMessage, rec); rerr != nil {
			s.logger.ErrorContext(ctx, "release: re-persist after no-provider failure",
				slog.Any("error", rerr))
		}
		return outcome, fmt.Errorf("release: no provider registered for %q: %w", rec.Provider, ErrNotFound)
	}
	body := req.RestoredBody
	if body == "" {
		body = defaultRestoredBody(verdict)
	}
	// RestoreFromQuarantine returns the resulting provider-side
	// message ID. For Fastmail/JMAP, restoring rewrites the body and
	// produces a fresh ID; we capture it so subsequent retries (when
	// re-persist is required) reference the latest known message.
	newMessageID, err := prov.RestoreFromQuarantine(ctx, rec.Email, rec.MessageID, rec.LabelID, body)
	if err != nil {
		// The reference is already gone (ClaimReference removed it).
		// Re-persist so a follow-up release call can retry; the
		// reference would otherwise be permanently lost on a transient
		// provider failure. When the provider reports partial progress
		// via newMessageID (e.g. the import succeeded but the destroy
		// failed mid-flight on Fastmail), persist that newer ID so the
		// retry operates on the message that actually exists.
		recForRetry := rec
		if newMessageID != "" {
			recForRetry.MessageID = newMessageID
		}
		if rerr := s.quarantine.RestoreReference(ctx, req.TenantID, req.PseudonymizedMessage, recForRetry); rerr != nil {
			s.logger.ErrorContext(ctx, "release: re-persist after restore failure",
				slog.Any("error", rerr))
		}
		return outcome, fmt.Errorf("release: restore: %w: %w", ErrProviderUnavailable, err)
	}
	outcome.Reason = ReleaseAllowed
	outcome.Restored = true
	s.logger.InfoContext(ctx, "action.quarantine.release allowed",
		slog.String("tenant_id", req.TenantID),
		slog.String("new_tier", string(verdict.Tier)),
		slog.String("primary", string(verdict.Primary)),
		slog.String("restored_message_id", newMessageID),
	)
	s.publishOutcome(ctx, req, outcome)
	return outcome, nil
}

// isStillBlocked reports whether tier is still at or above the
// configured release gate. minTier is inclusive: when the new
// verdict equals minTier the release is refused. SecOps tighten the
// gate by configuring a less-severe minTier (e.g. TierWarning), in
// which case any verdict at Warning or worse continues to be blocked
// and only verdicts strictly below it release. The comparison is
// severity-based and does not depend on whether minTier itself is the
// Blocked tier.
func isStillBlocked(tier, minTier constant.Tier) bool {
	if !tier.Valid() {
		// Be conservative: treat invalid verdicts as still blocked.
		return true
	}
	return tier.Severity() >= minTier.Severity()
}

// defaultRestoredBody is the placeholder body the provider injects
// when the caller did not supply one. It mirrors the original stub's
// tone but communicates the release.
func defaultRestoredBody(v dto.EvaluateResult) string {
	if v.Primary == "" {
		return "SN360 released this message after re-evaluation. The original content has been restored."
	}
	return fmt.Sprintf(
		"SN360 released this message after re-evaluation (now tier %s). The original content has been restored.",
		v.Tier,
	)
}

// collectReleaseReasons surfaces a short list of human-readable
// reasons from the verdict so the support agent can explain a
// refusal.
func collectReleaseReasons(v dto.EvaluateResult) []string {
	out := make([]string, 0, 4)
	if v.Primary != "" {
		out = append(out, string(v.Primary))
	}
	for _, c := range v.Secondary {
		out = append(out, string(c))
		if len(out) >= 4 {
			break
		}
	}
	if len(out) == 0 {
		out = append(out, "verdict still blocking")
	}
	return out
}

// publishOutcome emits the release event on the configured subject.
// Failures are logged but never returned: the user-facing flow has
// already completed.
func (s *ReleaseService) publishOutcome(ctx context.Context, req ReleaseRequest, outcome ReleaseOutcome) {
	if s.publisher == nil {
		return
	}
	envelope := struct {
		TenantID             string        `json:"tenant_id"`
		PseudonymizedMessage string        `json:"pseudonymized_message_id"`
		RequestedBy          string        `json:"requested_by,omitempty"`
		CorrelationID        string        `json:"correlation_id,omitempty"`
		Reason               ReleaseReason `json:"reason"`
		Restored             bool          `json:"restored"`
		Original             constant.Tier `json:"original_tier,omitempty"`
		NewTier              constant.Tier `json:"new_tier,omitempty"`
		Explanations         []string      `json:"explanations,omitempty"`
		OccurredAt           time.Time     `json:"occurred_at"`
	}{
		TenantID:             req.TenantID,
		PseudonymizedMessage: req.PseudonymizedMessage,
		RequestedBy:          req.RequestedBy,
		CorrelationID:        req.CorrelationID,
		Reason:               outcome.Reason,
		Restored:             outcome.Restored,
		Original:             outcome.Original,
		NewTier:              outcome.Verdict.Tier,
		Explanations:         outcome.Explanations,
		OccurredAt:           outcome.OccurredAt,
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		s.logger.WarnContext(ctx, "release: marshal event", slog.Any("error", err))
		return
	}
	// Surface the caller-provided CorrelationID as a canonical bus
	// header so middleware (tracing, replay tooling) can join the
	// release outcome back to the originating evaluation without
	// having to parse the JSON body. Mirrors handleEvaluateRequest's
	// publish at cmd/sn360-es/main.go.
	if err := s.publisher.Publish(ctx, s.subject, payload,
		events.WithEventType("action.quarantine.release"),
		events.WithTenantID(req.TenantID),
		events.WithMessageID(req.PseudonymizedMessage),
		events.WithCorrelationID(req.CorrelationID),
	); err != nil {
		s.logger.WarnContext(ctx, "release: publish", slog.Any("error", err))
	}
}
