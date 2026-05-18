package evaluate

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

// Tier0Gate is the contract the orchestrator expects from the Tier 0
// classifier. internal/service/tier0.Gate satisfies it.
type Tier0Gate interface {
	Apply(req dto.EvaluateRequest) dto.Tier0Outcome
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
// Phase 5 implements the real one; the orchestrator only depends on the
// interface so it can be developed independently.
type Categorizer interface {
	Categorise(res dto.EvaluateResult, sig dto.RiskSignals) (primary constant.Category, secondary []constant.Category, reasons []string)
}

// TierDecider turns (score, tier-overrides) into a final Tier label. The
// concrete implementation lives in internal/service/action.
type TierDecider interface {
	Decide(score int, primary constant.Category, signals dto.RiskSignals) constant.Tier
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
	if cfg.Weights.Total() == 0 {
		cfg.Weights = DefaultWeights()
	}
	return &Evaluator{cfg: cfg, log: cfg.Logger}
}

// Evaluate runs the full pipeline on req. The returned EvaluateResult is
// always populated, even when downstream services fail — Degraded reports
// whether any service was unavailable.
func (e *Evaluator) Evaluate(ctx context.Context, req dto.EvaluateRequest) (dto.EvaluateResult, error) {
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

	// 1. Tier 0 gate.
	if e.cfg.Tier0 == nil {
		return res, errors.New("evaluate: Tier0 gate is required")
	}
	tier0 := e.cfg.Tier0.Apply(req)
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

	// 2. Fan-out: run downstreams in parallel.
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		degraded []string
	)
	markDegraded := func(svc string) {
		mu.Lock()
		degraded = append(degraded, svc)
		mu.Unlock()
	}

	// Rspamd runs on every non-bypassed message.
	if e.cfg.Rspamd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, e.cfg.RspamdTimeout)
			defer cancel()
			start := time.Now()
			outcome, err := e.runRspamd(cctx, req)
			if err != nil {
				markDegraded("rspamd")
				e.cfg.Observer.ObserveRspamd("error", time.Since(start))
				e.cfg.Observer.ObserveDegraded("rspamd")
				e.log.Warn("evaluate: rspamd unavailable",
					slog.String("message_id", req.MessageID),
					slog.Any("error", err))
				return
			}
			e.cfg.Observer.ObserveRspamd("ok", time.Since(start))
			res.Rspamd = &outcome
		}()
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
			if err != nil {
				markDegraded("tier1")
				e.cfg.Observer.ObserveTier1("error", time.Since(start))
				e.cfg.Observer.ObserveDegraded("tier1")
				e.log.Warn("evaluate: tier1 unavailable",
					slog.String("message_id", req.MessageID),
					slog.Any("error", err))
				return
			}
			// Apply pass/flag thresholds.
			pass := e.cfg.Tier1PassThreshold
			if tier0.Tier1ThresholdOverride > 0 {
				pass = tier0.Tier1ThresholdOverride
			}
			flag := e.cfg.Tier1FlagThreshold
			outcome.Pass = outcome.Score < pass
			outcome.Flag = outcome.Score >= flag
			outcome.Escalate = !outcome.Pass && !outcome.Flag
			verdict := "escalate"
			switch {
			case outcome.Pass:
				verdict = "pass"
			case outcome.Flag:
				verdict = "flag"
			}
			e.cfg.Observer.ObserveTier1(verdict, time.Since(start))
			// Surface the encoder's reason codes on the top-level
			// result so the Categorizer can rule on them (its
			// keyword weights look at res.ReasonCodes) and so audit
			// / banner / dashboard consumers see the full set, not
			// just the categoriser-derived ones. The batch path
			// does the equivalent at batch.go:327; without this
			// copy the per-message path produced verdicts with
			// strictly fewer reason codes than the batch path for
			// the same encoder response.
			//
			// RACE SAFETY: today the Rspamd goroutine only writes
			// res.Rspamd (a distinct struct field) and never touches
			// res.ReasonCodes, so this append is technically race-
			// free under Go's struct-field-write model. But that
			// invariant is fragile — if anyone later adds a second
			// writer (e.g. Rspamd surfacing its own symbol names as
			// reason codes) the race becomes silent and corrupting.
			// Re-use the existing `mu` mutex (it already guards
			// `degraded`) to make the write explicit. The cost is
			// negligible: at most one uncontended Lock/Unlock per
			// evaluation.
			if len(outcome.ReasonCodes) > 0 {
				mu.Lock()
				res.ReasonCodes = append(res.ReasonCodes, outcome.ReasonCodes...)
				mu.Unlock()
			}
			res.Tier1 = &outcome
		}()
	}
	wg.Wait()

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
			markDegraded("tier2")
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

	// 4. Aggregate.
	res.Score = Score(FromResult(&res), e.cfg.Weights)
	if e.cfg.Categorizer != nil {
		primary, secondary, reasons := e.cfg.Categorizer.Categorise(res, req.Signals)
		res.Primary = primary
		res.Secondary = secondary
		res.ReasonCodes = append(res.ReasonCodes, reasons...)
	}
	if e.cfg.TierDecider != nil {
		res.Tier = e.cfg.TierDecider.Decide(res.Score, res.Primary, req.Signals)
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
