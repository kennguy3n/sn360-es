package evaluate

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

// Tier0Gate is the contract the orchestrator expects from the Tier 0
// classifier. internal/service/tier0.Gate satisfies it.
//
// Signals are passed as a separate parameter (rather than via
// req.Signals) so the per-message and batch evaluation paths share
// the same call shape. The previous wiring used a per-call adapter
// to copy signals onto req before invoking the gate; threading them
// explicitly removes that adapter and makes signal provenance
// visible at every call site.
type Tier0Gate interface {
	Apply(req dto.EvaluateRequest, signals dto.RiskSignals) dto.Tier0Outcome
	// ApplyWithContext is the context-aware variant used by the
	// ti_match threat-intel hook. Implementations that don't
	// need a context (e.g. the in-memory fake used in tests)
	// MAY forward to Apply, discarding ctx.
	ApplyWithContext(ctx context.Context, req dto.EvaluateRequest, signals dto.RiskSignals) dto.Tier0Outcome
}

// Tier1Client invokes the Tier 1 (encoder) inference service. The actual
// HTTP client lives in internal/service/tier1; this interface keeps the
// orchestrator decoupled from transport details so tests can swap a
// fake in.
type Tier1Client interface {
	Evaluate(ctx context.Context, req dto.EvaluateRequest) (dto.Tier1Outcome, error)
}

// Tier2Client invokes the Tier 2 (LLM/SLM) inference service.
type Tier2Client interface {
	Evaluate(ctx context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error)
}

// RspamdClient invokes Rspamd.
type RspamdClient interface {
	Score(ctx context.Context, req dto.EvaluateRequest) (dto.RspamdOutcome, error)
}

// Categorizer maps the verdict + risk signals to (primary, secondaries).
// The orchestrator depends only on this interface so the rule-based
// categorizer can be swapped independently.
type Categorizer interface {
	Categorise(res dto.EvaluateResult, sig dto.RiskSignals) (primary constant.Category, secondary []constant.Category, reasons []string)
}

// TierDecider turns (score, tier-overrides) into a final Tier label. The
// concrete implementation lives in internal/service/action.
type TierDecider interface {
	Decide(score int, primary constant.Category, signals dto.RiskSignals) constant.Tier
}

// TenantScoringConfig is the per-tenant projection of score_engine
// the evaluator consults at decision time. The shape matches the four
// scoring columns + the two Tier-1 threshold columns; the evaluator
// uses it to override its static defaults so persisted-by-tuning
// values actually influence verdicts.
//
// `Weights` defaults to its zero value when unset; an all-zero
// `Weights.Total()==0` is treated as "fall back to static Weights"
// (an all-zero set has no useful evaluator meaning).
//
// The two threshold fields are pointer-typed so the loader can
// distinguish "not configured" (nil — fall back to static defaults)
// from a deliberately-configured value of zero (a non-nil pointer to
// 0). Plain `int` with a `> 0` sentinel would silently swallow the
// edge case where the tuning agent emits PassBelow=0 (forcing every
// message into the escalation/flag band), which the DB CHECK
// constraint and clampThresholds both allow.
//
// The adapter populating this struct (cmd/sn360-es/adapters.go:
// tenantScoringConfigAdapter) is responsible for translating DB
// integers into the renormalised [0, 1] weight range and for leaving
// the threshold pointers nil when no row exists for the tenant.
type TenantScoringConfig struct {
	Weights            Weights
	Tier1PassThreshold *int
	Tier1FlagThreshold *int
}

// TenantScoringConfigLoader returns the per-tenant scoring config
// the evaluator should apply for the given tenant. Implementations
// must be safe for concurrent use across many goroutines. Returning
// (zero TenantScoringConfig, nil) is equivalent to "no per-tenant
// override; use the static defaults from Config" — callers MUST NOT
// treat a zero return as an error. A non-nil error is logged at
// warn level and the evaluator falls back to the static defaults so
// a transient DB blip never blocks verdict emission.
type TenantScoringConfigLoader interface {
	LoadTenantScoringConfig(ctx context.Context, tenantID string) (TenantScoringConfig, error)
}

// Config bundles the inputs the orchestrator needs at construction time.
type Config struct {
	Tier0       Tier0Gate
	Tier1       Tier1Client
	Tier2       Tier2Client
	Rspamd      RspamdClient
	Categorizer Categorizer
	TierDecider TierDecider
	Weights     Weights

	// CB is the set of circuit breakers, one per downstream. Any of them
	// may be nil; nil means "no breaker, call directly".
	CB BreakerSet

	// Timeouts overrides the default 5s / 30s / 5s timeouts.
	Tier1Timeout  time.Duration
	Tier2Timeout  time.Duration
	RspamdTimeout time.Duration

	// PassThreshold and FlagThreshold are the Tier 1 thresholds applied
	// when the per-tenant value is not set.
	Tier1PassThreshold int
	Tier1FlagThreshold int

	// Tier1SuppressPartner is the (typically negative) offset applied
	// to PassBelow / FlagAbove for senders flagged as Partner or
	// Customer (see tier1.Thresholds.AdjustForRelationship). It is
	// kept on Config rather than TenantScoringConfig because it is a
	// platform-wide relationship-aware adjustment, not a per-tenant
	// tuned knob — the tuning agent never writes it.
	//
	// NewEvaluator does NOT apply a zero-sentinel default here: 0 is
	// a legitimate operator-chosen value meaning "do not apply any
	// relationship-aware tightening" and it must round-trip
	// untouched through construction. The platform default (-10,
	// matching tier1.DefaultThresholds()) is applied one layer up
	// in internal/config/config.go — TIER1_SUPPRESS_PARTNER falls
	// back to -10 there when unset — so by the time we reach
	// NewEvaluator the field carries either that operator-explicit
	// value or the platform default, and either way Evaluator
	// trusts what it received. See
	// TestNewEvaluator_SuppressPartnerZeroIsRespected for the
	// regression guard.
	Tier1SuppressPartner int

	// TenantConfig is the per-tenant scoring config override source.
	// When non-nil, Evaluate consults it at the top of each call and
	// uses the returned (Weights, Tier1Pass/FlagThreshold) instead of
	// the static fields above. Nil falls back to the static defaults,
	// which keeps existing tests and dev configurations untouched.
	//
	// This is what makes the tuning agent's persisted score_engine
	// row actually flow into evaluation: without it, the tuning
	// agent's UpdateWeights / UpdateThresholds writes never reach
	// the verdict path.
	TenantConfig TenantScoringConfigLoader

	Logger *slog.Logger

	// Observer receives per-tier latency and outcome metrics. Nil falls
	// back to a no-op observer so existing tests don't need wiring.
	Observer telemetry.PipelineObserver
}

// BreakerSet groups the three breakers the evaluator needs.
type BreakerSet struct {
	Tier1  *CircuitBreaker
	Tier2  *CircuitBreaker
	Rspamd *CircuitBreaker
}

// tier1ChanResult and rspamdChanResult are the messages each fan-out
// goroutine writes to its 1-buffered channel. Carrying the outcome
// alongside the latency and error means the main goroutine has
// everything it needs to publish onto the result struct, emit metrics,
// and decide degraded status without taking a mutex.
type tier1ChanResult struct {
	outcome dto.Tier1Outcome
	latency time.Duration
	err     error
}

type rspamdChanResult struct {
	outcome dto.RspamdOutcome
	latency time.Duration
	err     error
}

// Evaluator is the multi-tier evaluation orchestrator. It is safe for
// concurrent use; the only mutable state is via the circuit breakers.
type Evaluator struct {
	cfg Config
	log *slog.Logger
}

// NewEvaluator returns a configured Evaluator. Required fields are
// Config.Tier0; everything else may be nil and the evaluator will
// degrade gracefully.
func NewEvaluator(cfg Config) *Evaluator {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Observer == nil {
		cfg.Observer = telemetry.NoopPipelineObserver()
	}
	if cfg.Tier1Timeout <= 0 {
		cfg.Tier1Timeout = 5 * time.Second
	}
	if cfg.Tier2Timeout <= 0 {
		cfg.Tier2Timeout = 30 * time.Second
	}
	if cfg.RspamdTimeout <= 0 {
		cfg.RspamdTimeout = 5 * time.Second
	}
	if cfg.Tier1PassThreshold == 0 {
		cfg.Tier1PassThreshold = 20
	}
	if cfg.Tier1FlagThreshold == 0 {
		cfg.Tier1FlagThreshold = 60
	}
	// Intentionally no zero-sentinel default for Tier1SuppressPartner.
	// `0` is a legitimate operator-chosen value meaning "do not apply
	// any relationship-aware tightening for Partner / Customer
	// senders" (see .env.example: "Must be <= 0"). Treating 0 as
	// "unset" here would force -10 onto operators who deliberately
	// set TIER1_SUPPRESS_PARTNER=0, and it would not be applied by
	// the symmetric BatchOrchestrator path (which only zero-defaults
	// the whole tier1.Thresholds struct, not individual fields).
	// Source of the platform default (currently -10, see
	// tier1.DefaultThresholds()) is internal/config/config.go where
	// TIER1_SUPPRESS_PARTNER falls back to -10 when unset — by the
	// time we reach NewEvaluator the field carries either that
	// operator-explicit value or the platform default.
	if cfg.Weights.Total() == 0 {
		cfg.Weights = DefaultWeights()
	}
	return &Evaluator{cfg: cfg, log: cfg.Logger}
}

// Evaluate runs the full pipeline on req with the supplied risk
// signals. The returned EvaluateResult is always populated, even when
// downstream services fail — Degraded reports whether any service was
// unavailable.
//
// Signals are an explicit parameter (not read from req.Signals) so the
// per-message and batch evaluation paths share an identical entry
// signature. The previous wiring required a fallbackEvaluatorAdapter
// to copy signals onto req before invoking Evaluate; threading them
// directly removes that adapter and makes the signal source visible
// at every call site.
func (e *Evaluator) Evaluate(ctx context.Context, req dto.EvaluateRequest, signals dto.RiskSignals) (dto.EvaluateResult, error) {
	evalStart := time.Now()
	res := dto.EvaluateResult{
		MessageID:     req.MessageID,
		TenantID:      req.TenantID,
		CorrelationID: req.CorrelationID,
		EvaluatedAt:   time.Now().UTC(),
	}
	defer func() {
		e.cfg.Observer.ObserveEvaluate(string(res.Tier), time.Since(evalStart))
	}()

	// 0. Per-tenant scoring config. When the tuning agent has
	// persisted weights or thresholds for this tenant, they override
	// the static cfg.Weights / cfg.Tier1*Threshold defaults. Failures
	// fall back to the static config so a Postgres blip never blocks
	// verdict emission.
	//
	// AdjustForRelationship is applied after resolution so Partner /
	// Customer / FirstTimeExternal senders get the same
	// relationship-aware threshold shift the batch path applies —
	// without it, this per-message path was silently stricter (or
	// more lenient) than batch for the same input.
	weights, baseThresholds := e.resolveTenantConfig(ctx, req.TenantID)
	adjustedThresholds := baseThresholds.AdjustForRelationship(signals.RelationshipCategory)
	passThreshold := adjustedThresholds.PassBelow
	flagThreshold := adjustedThresholds.FlagAbove

	// 1. Tier 0 gate.
	if e.cfg.Tier0 == nil {
		return res, errors.New("evaluate: Tier0 gate is required")
	}
	tier0 := e.cfg.Tier0.ApplyWithContext(ctx, req, signals)
	res.Tier0 = &tier0
	if tier0.Bypass || tier0.SkipML || tier0.RspamdOnly {
		reason := tier0.Reason
		if reason == "" {
			switch {
			case tier0.Bypass:
				reason = "unknown_bypass"
			case tier0.RspamdOnly:
				reason = "rspamd_only"
			case tier0.SkipML:
				reason = "skip_ml"
			}
		}
		e.cfg.Observer.ObserveTier0(reason)
	} else {
		e.cfg.Observer.ObserveTier0("none")
	}

	if tier0.Bypass {
		// Short-circuit straight to verdict.
		res.Primary = tier0.ForcedCategory
		res.Tier = ForcedTierFor(tier0.ForcedCategory)
		res.Score = 0
		if tier0.Reason != "" {
			res.ReasonCodes = append(res.ReasonCodes, tier0.Reason)
		}
		return res, nil
	}

	// 2. Fan-out: run downstreams in parallel. Each goroutine writes its
	// outcome to a 1-buffered channel and the main goroutine merges them
	// into `res` sequentially after wg.Wait(). Channels replace the prior
	// shared-mutex pattern so there is no longer any concurrent write
	// to the result struct, regardless of which downstream goroutines
	// fan out today or tomorrow.
	var wg sync.WaitGroup
	var (
		tier1Ch  = make(chan tier1ChanResult, 1)
		rspamdCh = make(chan rspamdChanResult, 1)
	)
	var degraded []string

	// Rspamd runs on every non-bypassed message.
	if e.cfg.Rspamd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, e.cfg.RspamdTimeout)
			defer cancel()
			start := time.Now()
			outcome, err := e.runRspamd(cctx, req)
			rspamdCh <- rspamdChanResult{outcome: outcome, latency: time.Since(start), err: err}
		}()
	} else {
		close(rspamdCh)
	}

	// Tier 1 only runs if Tier 0 did not say "RspamdOnly" or "SkipML".
	tier1Skipped := tier0.SkipML || tier0.RspamdOnly
	if !tier1Skipped && e.cfg.Tier1 != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, e.cfg.Tier1Timeout)
			defer cancel()
			start := time.Now()
			outcome, err := e.runTier1(cctx, req)
			tier1Ch <- tier1ChanResult{outcome: outcome, latency: time.Since(start), err: err}
		}()
	} else {
		close(tier1Ch)
	}
	wg.Wait()

	// Drain Rspamd channel. A nil-out channel (closed because Rspamd was
	// not configured) yields the zero value, which we detect via the
	// receive-ok form.
	if rs, ok := <-rspamdCh; ok {
		if rs.err != nil {
			degraded = append(degraded, "rspamd")
			e.cfg.Observer.ObserveRspamd("error", rs.latency)
			e.cfg.Observer.ObserveDegraded("rspamd")
			e.log.Warn("evaluate: rspamd unavailable",
				slog.String("message_id", req.MessageID),
				slog.Any("error", rs.err))
		} else {
			e.cfg.Observer.ObserveRspamd("ok", rs.latency)
			outcome := rs.outcome
			res.Rspamd = &outcome
		}
	}

	// Drain Tier 1 channel and apply pass/flag thresholds before
	// publishing the outcome onto res.
	if t1, ok := <-tier1Ch; ok {
		if t1.err != nil {
			degraded = append(degraded, "tier1")
			e.cfg.Observer.ObserveTier1("error", t1.latency)
			e.cfg.Observer.ObserveDegraded("tier1")
			e.log.Warn("evaluate: tier1 unavailable",
				slog.String("message_id", req.MessageID),
				slog.Any("error", t1.err))
		} else {
			outcome := t1.outcome
			pass := passThreshold
			if tier0.Tier1ThresholdOverride > 0 {
				pass = tier0.Tier1ThresholdOverride
			}
			flag := flagThreshold
			// Use the same tier1.Thresholds.Decision routine the
			// batch orchestrator uses. Previously this branch used
			// `score >= flag` while Decision uses `score > flag`,
			// so a message with score == FlagAbove was Flagged in
			// the per-message path but Escalated in the batch path.
			// Routing the decision through Decision() eliminates
			// the boundary divergence at the source — both paths
			// now share a single implementation.
			verdict := tier1.Thresholds{PassBelow: pass, FlagAbove: flag}.Decision(outcome.Score)
			outcome.Pass = verdict == tier1.VerdictPass
			outcome.Flag = verdict == tier1.VerdictFlag
			outcome.Escalate = verdict == tier1.VerdictEscalate
			// tier1.Verdict is a string newtype with values "pass" /
			// "flag" / "escalate" — same labels the metrics observer
			// expects, so the conversion is a direct cast (no switch
			// translation needed).
			e.cfg.Observer.ObserveTier1(string(verdict), t1.latency)
			// Surface the encoder's reason codes on the top-level
			// result so the Categorizer can rule on them (its
			// keyword weights look at res.ReasonCodes) and so
			// audit / banner / dashboard consumers see the full
			// set, not just the categoriser-derived ones. The
			// batch path does the equivalent at batch.go:327.
			// Now that this runs on the main goroutine after the
			// fan-out completes, the append needs no mutex.
			if len(outcome.ReasonCodes) > 0 {
				res.ReasonCodes = append(res.ReasonCodes, outcome.ReasonCodes...)
			}
			res.Tier1 = &outcome
		}
	}

	// 3. Tier 2 escalation. We run Tier 2 sequentially after Tier 1 because
	//    its decision depends on Tier 1's verdict (escalate vs pass vs flag)
	//    and we never want to pay LLM cost when Tier 1 already says PASS.
	if e.shouldRunTier2(tier0, res.Tier1) && e.cfg.Tier2 != nil {
		cctx, cancel := context.WithTimeout(ctx, e.cfg.Tier2Timeout)
		hint := dto.Tier1Outcome{}
		if res.Tier1 != nil {
			hint = *res.Tier1
		}
		start := time.Now()
		outcome, err := e.runTier2(cctx, req, hint)
		cancel()
		if err != nil {
			degraded = append(degraded, "tier2")
			e.cfg.Observer.ObserveTier2("error", time.Since(start))
			e.cfg.Observer.ObserveDegraded("tier2")
			e.log.Warn("evaluate: tier2 unavailable",
				slog.String("message_id", req.MessageID),
				slog.Any("error", err))
		} else {
			e.cfg.Observer.ObserveTier2(tier2OutcomeLabel(outcome), time.Since(start))
			res.Tier2 = &outcome
		}
	}

	// 4. Aggregate using the per-tenant weights resolved at step 0.
	res.Score = ScoreWithAvailability(FromResultEx(&res), weights)
	if e.cfg.Categorizer != nil {
		primary, secondary, reasons := e.cfg.Categorizer.Categorise(res, signals)
		res.Primary = primary
		res.Secondary = secondary
		res.ReasonCodes = append(res.ReasonCodes, reasons...)
	}
	if e.cfg.TierDecider != nil {
		res.Tier = e.cfg.TierDecider.Decide(res.Score, res.Primary, signals)
	}

	if len(degraded) > 0 {
		res.Degraded = true
		res.DegradedServices = degraded
	}
	return res, nil
}

// runTier1 wraps the Tier 1 call in the configured breaker.
func (e *Evaluator) runTier1(ctx context.Context, req dto.EvaluateRequest) (dto.Tier1Outcome, error) {
	var out dto.Tier1Outcome
	op := func(ctx context.Context) error {
		var err error
		out, err = e.cfg.Tier1.Evaluate(ctx, req)
		return err
	}
	if e.cfg.CB.Tier1 != nil {
		return out, e.cfg.CB.Tier1.Do(ctx, op)
	}
	return out, op(ctx)
}

// runTier2 wraps the Tier 2 call in the configured breaker.
func (e *Evaluator) runTier2(ctx context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	var out dto.Tier2Outcome
	op := func(ctx context.Context) error {
		var err error
		out, err = e.cfg.Tier2.Evaluate(ctx, req, hint)
		return err
	}
	if e.cfg.CB.Tier2 != nil {
		return out, e.cfg.CB.Tier2.Do(ctx, op)
	}
	return out, op(ctx)
}

// runRspamd wraps the Rspamd call in the configured breaker.
func (e *Evaluator) runRspamd(ctx context.Context, req dto.EvaluateRequest) (dto.RspamdOutcome, error) {
	var out dto.RspamdOutcome
	op := func(ctx context.Context) error {
		var err error
		out, err = e.cfg.Rspamd.Score(ctx, req)
		return err
	}
	if e.cfg.CB.Rspamd != nil {
		return out, e.cfg.CB.Rspamd.Do(ctx, op)
	}
	return out, op(ctx)
}

// shouldRunTier2 decides whether to escalate to the LLM based on Tier 0
// and Tier 1 signals.
func (e *Evaluator) shouldRunTier2(tier0 dto.Tier0Outcome, t1 *dto.Tier1Outcome) bool {
	if tier0.SkipML || tier0.RspamdOnly {
		return false
	}
	if tier0.ForceEscalate {
		return true
	}
	if t1 == nil {
		// Tier 1 unavailable — escalate everything per PROPOSAL.md Section 3.
		return true
	}
	return t1.Escalate || t1.Flag
}

// tier2OutcomeLabel maps a Tier 2 result to a fixed, low-cardinality
// label suitable for Prometheus. There are 16+ distinct category
// constants and Tier 2 returns them by name, so using the raw category
// string as a metric label would balloon the time-series cardinality
// on sn360_es_tier2_escalations_total. Bucket into ok / flagged so the
// label set stays bounded; if dashboards need per-category breakdowns
// the categorizer's own counters provide that detail.
func tier2OutcomeLabel(out dto.Tier2Outcome) string {
	if len(out.Categories) == 0 {
		return "ok"
	}
	return "flagged"
}

// resolveTenantConfig returns the (weights, thresholds) pair the
// evaluator should apply for tenantID, exactly mirroring
// BatchOrchestrator.resolveTenantConfig so both evaluation paths
// produce identical verdicts for the same input.
//
// The returned thresholds carry the per-tenant PassBelow / FlagAbove
// overrides (when the loader has them) on top of the static
// SuppressPartner. SuppressPartner is deliberately preserved from the
// static config because it is a relationship-aware adjustment, not a
// per-tenant tuned value. Callers MUST follow up with
// thresholds.AdjustForRelationship(signals.RelationshipCategory) so
// Partner / Customer / FirstTimeExternal senders get the same
// tightened thresholds the batch path applies.
//
// Override semantics:
//   - Weights: an all-zero set is "not configured"; any non-zero sum
//     wins over the static defaults.
//   - Tier1PassThreshold / Tier1FlagThreshold: a nil pointer is "not
//     configured"; any non-nil pointer wins over the static default,
//     including a pointer to 0. This is what makes
//     clampThresholds-emitted PassBelow=0 visible to the verdict
//     path.
//
// Loader errors are downgraded to a warn log + static fallback so
// any transient DB blip (Postgres recycle, connection-pool churn)
// never blocks verdict emission. The error is not surfaced upstream
// because the evaluator's correctness contract is "always produce a
// verdict"; a tenant whose tuned config is briefly unavailable still
// gets evaluated against the platform defaults.
func (e *Evaluator) resolveTenantConfig(ctx context.Context, tenantID string) (Weights, tier1.Thresholds) {
	weights := e.cfg.Weights
	thresholds := tier1.Thresholds{
		PassBelow:       e.cfg.Tier1PassThreshold,
		FlagAbove:       e.cfg.Tier1FlagThreshold,
		SuppressPartner: e.cfg.Tier1SuppressPartner,
	}
	if e.cfg.TenantConfig == nil || tenantID == "" {
		return weights, thresholds
	}
	tc, err := e.cfg.TenantConfig.LoadTenantScoringConfig(ctx, tenantID)
	if err != nil {
		e.log.Warn("evaluate: tenant scoring config unavailable; using static defaults",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		return weights, thresholds
	}
	if tc.Weights.Total() > 0 {
		weights = tc.Weights
	}
	if tc.Tier1PassThreshold != nil {
		thresholds.PassBelow = *tc.Tier1PassThreshold
	}
	if tc.Tier1FlagThreshold != nil {
		thresholds.FlagAbove = *tc.Tier1FlagThreshold
	}
	return weights, thresholds
}

// ForcedTierFor maps the categories the Tier 0 gate may force into
// the matching tier label. Exported so the batch-orchestrator wiring
// in cmd/sn360-es/main.go can reuse the same mapping without
// maintaining a hand-synced duplicate.
func ForcedTierFor(c constant.Category) constant.Tier {
	switch c {
	case constant.CategoryInternalTrusted, constant.CategoryVendorTrusted:
		return constant.TierTrusted
	case constant.CategoryNewsletter:
		return constant.TierInformational
	default:
		return constant.TierTrusted
	}
}
