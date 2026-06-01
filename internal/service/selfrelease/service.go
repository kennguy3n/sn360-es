// Package selfrelease implements the WS-3a end-user self-service
// quarantine release flow.
//
// Architecture in one paragraph: a recipient receives a banner /
// digest entry containing a pre-baked HTTPS URL with a signed JWT
// action-token (scope=quarantine_release, 24h TTL). When they click
// it, the HTTP handler hands the parsed claims to Service.Release,
// which walks a fixed outcome state machine — tier-2 malicious
// gate → per-recipient rate-limit gate → underlying release-service
// call — writing exactly one audit row per attempt and returning
// the chosen outcome. The service is pure-ish: it has no HTTP
// concerns, returns a structured outcome (not an HTTP status), and
// the handler maps outcome → status code uniformly. This keeps the
// state machine independently testable and the handler responsible
// only for transport.
//
// Invariants:
//   - Every release attempt writes exactly one audit row, including
//     the "auth failed" cases (token_expired / invalid_token) the
//     handler audits before calling Release. The handler is the
//     auditor for auth-failure outcomes because Service.Release is
//     never reached when the token is bad; it does NOT also audit
//     here, otherwise auth failures would double-audit.
//   - Cross-tenant indistinguishability: the not_found outcome
//     covers three on-wire-identical cases (cross-tenant attempt,
//     in-tenant miss, retention-deleted record). Service.Release
//     audits the actual cause for in-tenant SOC review but the
//     handler converts every not_found outcome to the same 404
//     wire body.
//   - The tier-2 block is unconditional: no tenant policy can
//     override it at this layer. SOC override is a separate
//     feature outside the scope of this package.
//   - The rate-limit is per-recipient (keyed by
//     recipient_user_hash), not per-tenant: an abusive recipient
//     can't burn another recipient's quota.
//   - Release operation is idempotent: a re-release attempt
//     against an already-released message yields outcome
//     already_released with no provider mutation. This pattern is
//     preferred over single-use token burn because it survives
//     concurrent clicks without locking and works with edge
//     caching.
package selfrelease

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// ReleaseRunner is the contract Service uses to actually re-deliver
// the message. The production wiring satisfies it with
// *action.ReleaseService (the SOC-operator release path), so the
// self-service flow shares exactly one re-delivery implementation
// with the operator flow. Tests substitute a fake.
type ReleaseRunner interface {
	Release(ctx context.Context, req action.ReleaseRequest) (action.ReleaseOutcome, error)
}

// QuarantineLookup is the slice of *action.QuarantineService the
// self-release flow consumes: a (tenant, pseudoMessage) -> record
// lookup. The third return value is "found"; the second-to-last is
// the record itself. Defined as a narrow interface for test seams.
type QuarantineLookup interface {
	LookupReference(ctx context.Context, tenant, pseudoMessage string) (action.QuarantineRecord, bool, error)
}

// Clock is injectable for deterministic rate-limit tests. Default
// implementation is time.Now.
type Clock func() time.Time

// Config wires the self-release service's dependencies.
type Config struct {
	Logger     *slog.Logger
	Quarantine QuarantineLookup
	Runner     ReleaseRunner
	Audit      repository.QuarantineReleaseAuditRepository
	Policies   repository.TenantReleasePolicyRepository
	Clock      Clock
	// RateLimitWindow is the look-back window for the
	// per-recipient hourly cap. Defaults to one hour. Exposed
	// for tests that want a short window without sleeping.
	RateLimitWindow time.Duration
}

// Service is the WS-3a self-service release coordinator.
type Service struct {
	logger     *slog.Logger
	quarantine QuarantineLookup
	runner     ReleaseRunner
	audit      repository.QuarantineReleaseAuditRepository
	policies   repository.TenantReleasePolicyRepository
	now        Clock
	rateWindow time.Duration
}

// NewService validates the config and returns a Service. All four of
// quarantine, runner, audit, policies are required — there is no
// "degraded" mode that skips any of them in production. Tests can
// hand in in-memory implementations.
func NewService(cfg Config) (*Service, error) {
	if cfg.Quarantine == nil {
		return nil, errors.New("selfrelease: quarantine lookup is required")
	}
	if cfg.Runner == nil {
		return nil, errors.New("selfrelease: runner is required")
	}
	if cfg.Audit == nil {
		return nil, errors.New("selfrelease: audit repository is required")
	}
	if cfg.Policies == nil {
		return nil, errors.New("selfrelease: policy repository is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Clock
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	window := cfg.RateLimitWindow
	if window <= 0 {
		window = time.Hour
	}
	return &Service{
		logger:     logger,
		quarantine: cfg.Quarantine,
		runner:     cfg.Runner,
		audit:      cfg.Audit,
		policies:   cfg.Policies,
		now:        now,
		rateWindow: window,
	}, nil
}

// Request is the input to Service.Release. The handler is responsible
// for verifying the JWT, decoding the recipient-user hash, and
// passing the validated claims here. The service does not touch the
// JWT — it trusts these inputs.
type Request struct {
	TenantID          string
	PseudoMessageID   string
	RecipientUserHash []byte
	CorrelationID     string
}

// Result is Service.Release's output: the outcome plus the audit
// entry that was written. The handler maps Outcome → HTTP status
// code; it does NOT inspect AuditEntry for response synthesis (the
// audit row's purpose is forensic, not user-visible).
type Result struct {
	Outcome    repository.QuarantineReleaseOutcome
	AuditEntry repository.QuarantineReleaseAuditEntry
	// Restored is true when the underlying release runner restored
	// the message on the provider side. Always false for any
	// non-`released` outcome.
	Restored bool
	// Reason is the same `reason` string written to the audit row,
	// intended for ops debugging. The wire response does NOT
	// surface this to the client.
	Reason string
}

// Release walks the WS-3a state machine. Exactly one audit row is
// written per call (the handler is responsible for the
// auth-failure rows; this function handles every post-auth
// outcome). Errors returned indicate genuine infrastructure
// failures (Postgres down, runner crash) — they are NOT a normal
// path through the state machine. Outcomes like rate_limited or
// tier2_blocked return (Result, nil) with the corresponding
// Outcome populated.
func (s *Service) Release(ctx context.Context, req Request) (Result, error) {
	if req.TenantID == "" {
		return Result{}, errors.New("selfrelease: tenant_id is required")
	}
	if req.PseudoMessageID == "" {
		return Result{}, errors.New("selfrelease: pseudo_message_id is required")
	}
	if len(req.RecipientUserHash) == 0 {
		return Result{}, errors.New("selfrelease: recipient_user_hash is required")
	}

	requestedAt := s.now()

	// 1. Lookup the quarantine record FIRST so the not_found
	//    branch returns an audit row keyed by the same
	//    pseudo_message_id the client claimed (cross-tenant
	//    indistinguishability: we audit "miss" without
	//    differentiating between in-tenant miss and cross-tenant
	//    attempt; both flow to the same 404 wire body).
	rec, found, err := s.quarantine.LookupReference(ctx, req.TenantID, req.PseudoMessageID)
	if err != nil {
		// Infrastructure error reading from the quarantine
		// store. We do NOT audit this case — the audit row
		// must not be a side-channel for "Redis is down".
		// Bubble the error to the handler which returns 503.
		return Result{}, fmt.Errorf("selfrelease: lookup: %w", err)
	}
	if !found {
		return s.audited(ctx, req, requestedAt,
			repository.QuarantineReleaseOutcomeNotFound,
			"no quarantine record for (tenant, pseudo_message_id)",
			false), nil
	}

	// 2. Tier-2 malicious gate. Unconditional — no tenant policy
	//    can override at this layer. Tier-2 is the deepest
	//    classifier in the stack; a one-click recipient release
	//    on a tier-2 malicious verdict would defeat the safety
	//    stack, so we never let it through the self-service
	//    path.
	if rec.Tier2Malicious {
		return s.audited(ctx, req, requestedAt,
			repository.QuarantineReleaseOutcomeTier2Blocked,
			"tier-2 SLM classified message as malicious",
			false), nil
	}

	// 3. Per-recipient rate-limit gate. We count EVERY recent
	//    audit row, not just successes, so a client repeatedly
	//    hitting the endpoint with bad inputs still consumes
	//    their hourly budget (an abuse-resistance choice — see
	//    repository.QuarantineReleaseAuditRepository.CountRecentByRecipient
	//    for the full rationale).
	policy, err := s.policies.Get(ctx, req.TenantID)
	if err != nil {
		return Result{}, fmt.Errorf("selfrelease: load policy: %w", err)
	}
	if policy.QuarantineSelfReleasePerHour == 0 {
		// Tenant has explicitly disabled self-service. Audit
		// the attempt as rate_limited (same outcome the
		// "exceeded cap" case writes) so the SOC view of
		// "this recipient hit the endpoint" stays uniform.
		// Reason field distinguishes "disabled" from
		// "exceeded" for in-tenant ops review.
		return s.audited(ctx, req, requestedAt,
			repository.QuarantineReleaseOutcomeRateLimited,
			"tenant has self-release disabled (per-hour cap is 0)",
			false), nil
	}
	count, err := s.audit.CountRecentByRecipient(ctx, req.TenantID, req.RecipientUserHash, requestedAt.Add(-s.rateWindow))
	if err != nil {
		return Result{}, fmt.Errorf("selfrelease: count audit: %w", err)
	}
	if count >= policy.QuarantineSelfReleasePerHour {
		return s.audited(ctx, req, requestedAt,
			repository.QuarantineReleaseOutcomeRateLimited,
			fmt.Sprintf("recipient exceeded %d releases / %s window (observed %d)",
				policy.QuarantineSelfReleasePerHour, s.rateWindow, count),
			false), nil
	}

	// 4. Hand off to the shared release runner (production: the
	//    SOC-operator ReleaseService). The runner does the
	//    re-evaluation, claim/restore atomicity, and provider
	//    re-injection; we just translate its ReleaseReason
	//    output into a self-release Outcome.
	outcome, err := s.runner.Release(ctx, action.ReleaseRequest{
		TenantID:             req.TenantID,
		PseudonymizedMessage: req.PseudoMessageID,
		RequestedBy:          hex.EncodeToString(req.RecipientUserHash),
		CorrelationID:        req.CorrelationID,
	})
	if err != nil {
		// Runner-level error (provider unreachable, store
		// crash). Surface so the handler returns 503 without
		// audit-mutating the row count. We do still log it
		// at WARN with the tenant_id so SOC can correlate.
		s.logger.WarnContext(ctx, "selfrelease: runner failed",
			slog.String("tenant_id", req.TenantID),
			slog.Any("error", err))
		return Result{}, fmt.Errorf("selfrelease: runner: %w", err)
	}
	return s.fromRunnerOutcome(ctx, req, requestedAt, outcome), nil
}

// fromRunnerOutcome maps a *action.ReleaseService outcome onto a
// self-release Outcome and writes the audit row.
func (s *Service) fromRunnerOutcome(ctx context.Context, req Request, requestedAt time.Time, outcome action.ReleaseOutcome) Result {
	switch outcome.Reason {
	case action.ReleaseAllowed:
		return s.auditedWithRestored(ctx, req, requestedAt,
			repository.QuarantineReleaseOutcomeReleased,
			fmt.Sprintf("re-evaluation cleared verdict to tier %s", outcome.Verdict.Tier),
			outcome.Restored)
	case action.ReleaseAlreadyDone:
		// Idempotent re-release of an already-released
		// message: the user's intent succeeded (the message
		// is in their inbox) but we did nothing this call.
		// Audit the no-op and surface it to the client so
		// they see "already released" instead of a 5xx.
		return s.audited(ctx, req, requestedAt,
			repository.QuarantineReleaseOutcomeAlreadyReleased,
			"message was already released by a concurrent flow",
			false)
	case action.ReleaseNotFound:
		// Race window: lookup succeeded above but by the
		// time the runner claimed the reference, the record
		// was gone. Same wire outcome as the lookup miss.
		return s.audited(ctx, req, requestedAt,
			repository.QuarantineReleaseOutcomeNotFound,
			"quarantine record disappeared between lookup and claim",
			false)
	case action.ReleaseRefused:
		// Re-evaluation came back still-blocking. The
		// recipient sees a 403 (same as Tier2Blocked) but
		// the audit row is recorded under
		// `release_refused`, NOT `tier2_blocked`: the
		// runner's refusal can be for any reason the safety
		// stack carries (tier-1 score still above threshold,
		// fresh tier-2 verdict differing from the persisted
		// bit, policy gate, …), and tagging all of them as
		// `tier2_blocked` would overload the column —
		// operators querying `WHERE outcome =
		// 'tier2_blocked'` expect ONLY true tier-2 verdicts
		// caught at lookup time. The `reason` field carries
		// the runner's explanations for SOC drill-down.
		reason := "re-evaluation refused release"
		if len(outcome.Explanations) > 0 {
			reason = fmt.Sprintf("re-evaluation refused release: %v", outcome.Explanations)
		}
		return s.audited(ctx, req, requestedAt,
			repository.QuarantineReleaseOutcomeReleaseRefused,
			reason, false)
	default:
		// Unknown reason from the runner is treated as
		// infrastructure error path for audit purposes.
		// Logged separately so a future runner enum
		// extension surfaces visibly rather than silently
		// auditing as not_found.
		s.logger.ErrorContext(ctx, "selfrelease: unrecognised runner reason",
			slog.String("tenant_id", req.TenantID),
			slog.String("reason", string(outcome.Reason)))
		return s.audited(ctx, req, requestedAt,
			repository.QuarantineReleaseOutcomeNotFound,
			fmt.Sprintf("unknown runner reason %q", outcome.Reason),
			false)
	}
}

// audited records the audit row and returns a Result. Audit-write
// failures are logged but NOT returned as errors: the user's
// release attempt has already happened (or been refused) and the
// caller-visible response should not be a 5xx because we
// couldn't append to the audit table.
func (s *Service) audited(
	ctx context.Context,
	req Request,
	requestedAt time.Time,
	outcome repository.QuarantineReleaseOutcome,
	reason string,
	restored bool,
) Result {
	return s.auditedWithRestored(ctx, req, requestedAt, outcome, reason, restored)
}

// auditedWithRestored is the canonical audit path that captures the
// Restored bit too. Separate from audited only so the
// `auditedWithRestored` signature is explicit at the one call site
// (Release-allowed) that surfaces a non-default Restored value.
func (s *Service) auditedWithRestored(
	ctx context.Context,
	req Request,
	requestedAt time.Time,
	outcome repository.QuarantineReleaseOutcome,
	reason string,
	restored bool,
) Result {
	entry := repository.QuarantineReleaseAuditEntry{
		TenantID:          req.TenantID,
		PseudoMessageID:   req.PseudoMessageID,
		RecipientUserHash: append([]byte(nil), req.RecipientUserHash...),
		Outcome:           outcome,
		Reason:            reason,
		CorrelationID:     req.CorrelationID,
		RequestedAt:       requestedAt,
	}
	written, err := s.audit.Record(ctx, entry)
	if err != nil {
		s.logger.WarnContext(ctx, "selfrelease: audit write failed",
			slog.String("tenant_id", req.TenantID),
			slog.String("outcome", string(outcome)),
			slog.Any("error", err))
	} else {
		entry = written
	}
	return Result{
		Outcome:    outcome,
		AuditEntry: entry,
		Restored:   restored,
		Reason:     reason,
	}
}

// AuditAuthFailure is the entry point the handler calls when token
// validation fails — i.e. before Release is reached. The handler
// owns this so Release stays a pure post-auth state machine
// (otherwise auth failures would double-audit).
//
// outcome must be one of QuarantineReleaseOutcomeTokenExpired or
// QuarantineReleaseOutcomeInvalidToken; any other value is treated
// as InvalidToken (with the original outcome string recorded in
// the reason for forensics).
func (s *Service) AuditAuthFailure(
	ctx context.Context,
	tenantID, pseudoMessageID string,
	recipientUserHash []byte,
	correlationID string,
	outcome repository.QuarantineReleaseOutcome,
	reason string,
) (repository.QuarantineReleaseAuditEntry, error) {
	switch outcome {
	case repository.QuarantineReleaseOutcomeTokenExpired,
		repository.QuarantineReleaseOutcomeInvalidToken:
		// allowed
	default:
		reason = fmt.Sprintf("coerced outcome %q -> invalid_token: %s", outcome, reason)
		outcome = repository.QuarantineReleaseOutcomeInvalidToken
	}
	// Auth failure entries permit a zero recipient_user_hash —
	// the token may have been so corrupt that no recipient
	// identity is recoverable. We write a single zero byte in
	// that case so the BYTEA NOT NULL constraint on the audit
	// table is satisfied; the SOC view treats the magic value
	// as "auth failure, no recipient binding."
	if len(recipientUserHash) == 0 {
		recipientUserHash = []byte{0x00}
	}
	if tenantID == "" {
		// We do not have a tenant binding to attribute the
		// audit to. Skip the audit write rather than fabricate
		// one — this is the one case where we leave no audit
		// row, because the alternative is a row that lies.
		// The handler still returns 401 to the client.
		return repository.QuarantineReleaseAuditEntry{}, nil
	}
	if pseudoMessageID == "" {
		pseudoMessageID = "<unknown>"
	}
	entry := repository.QuarantineReleaseAuditEntry{
		TenantID:          tenantID,
		PseudoMessageID:   pseudoMessageID,
		RecipientUserHash: append([]byte(nil), recipientUserHash...),
		Outcome:           outcome,
		Reason:            reason,
		CorrelationID:     correlationID,
		RequestedAt:       s.now(),
	}
	written, err := s.audit.Record(ctx, entry)
	if err != nil {
		s.logger.WarnContext(ctx, "selfrelease: audit auth-failure write failed",
			slog.String("tenant_id", tenantID),
			slog.String("outcome", string(outcome)),
			slog.Any("error", err))
		return entry, err
	}
	return written, nil
}
