package tier0

import (
	"context"
	"log/slog"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// GateConfig controls which Tier 0 short-circuit paths are enabled. The
// values come from the application Config.Tier0 sub-struct and can be
// overridden per-tenant via Redis at runtime.
type GateConfig struct {
	SkipInternal         bool
	SkipVendor           bool
	SkipRecurring        bool
	HighVolumeRspamdOnly bool

	// Tier1PartnerThreshold is the Tier 1 PASS threshold to use when the
	// sender is a known partner/customer (i.e. relationship category lowers
	// the bar). Zero means no override.
	Tier1PartnerThreshold int
}

// DefaultGateConfig returns the recommended defaults used in dev. Production
// deployments load values from the environment via internal/config.
func DefaultGateConfig() GateConfig {
	return GateConfig{
		SkipInternal:          true,
		SkipVendor:            true,
		SkipRecurring:         true,
		HighVolumeRspamdOnly:  true,
		Tier1PartnerThreshold: 30,
	}
}

// Gate applies the Tier 0 classification rules to an EvaluateRequest. It
// is stateless and safe for concurrent use.
type Gate struct {
	cfg       GateConfig
	recurring *RecurringDetector
	ato       *ATOHeuristic
	// ti is the optional threat-intel lookup hook. nil means
	// "no ti_match path"; callers can also set TIChecker to
	// NoopTIChecker to render the field non-nil without paying
	// the cost of a real lookup.
	ti TIChecker
	// metrics is the optional metrics observer for the ti_match
	// path. nil means "do not emit ti_match counters".
	metrics TIObserver
	logger  *slog.Logger
}

// TIObserver is the slim metrics surface the gate uses to record
// ti_match observations. The cmd/sn360-es wiring layer adapts
// pkg/telemetry into this interface so the tier0 package stays
// telemetry-free.
type TIObserver interface {
	// ObserveLookup records a lookup outcome: "hit", "miss",
	// "skipped", "error".
	ObserveLookup(outcome string)
	// ObserveMatch records a match's severity tier: "block",
	// "quarantine", "flag".
	ObserveMatch(tier string)
}

// NewGate constructs a Gate with the given configuration. A nil recurring
// detector falls back to NewRecurringDetector(). A nil ATO heuristic
// falls back to NewATOHeuristic(DefaultATOHeuristicConfig()).
func NewGate(cfg GateConfig, recurring *RecurringDetector) *Gate {
	if recurring == nil {
		recurring = NewRecurringDetector()
	}
	return &Gate{
		cfg:       cfg,
		recurring: recurring,
		ato:       NewATOHeuristic(DefaultATOHeuristicConfig()),
	}
}

// NewGateWithATO is like NewGate but accepts a custom ATOHeuristic.
func NewGateWithATO(cfg GateConfig, recurring *RecurringDetector, ato *ATOHeuristic) *Gate {
	g := NewGate(cfg, recurring)
	if ato != nil {
		g.ato = ato
	}
	return g
}

// WithTIChecker installs the threat-intel lookup hook. Optional —
// the gate works without it (no ti_match reason code emitted).
// Returns the receiver for chaining.
func (g *Gate) WithTIChecker(ti TIChecker) *Gate {
	g.ti = ti
	return g
}

// WithTIObserver installs the metrics observer for the ti_match path.
// Optional. Returns the receiver for chaining.
func (g *Gate) WithTIObserver(o TIObserver) *Gate {
	g.metrics = o
	return g
}

// WithLogger overrides the logger used for ti_match diagnostics.
func (g *Gate) WithLogger(l *slog.Logger) *Gate {
	g.logger = l
	return g
}

// Apply runs the gate on req using the supplied signals and returns
// the structured Tier0Outcome. It does not mutate req. The outcome's
// Bypass field is the canonical signal to skip downstream ML.
//
// Signals are passed in explicitly (rather than read from req.Signals)
// so the batch and per-message paths share the same call shape: both
// callers compute signals once (cheap stuff in the per-message path,
// pulled from the batch envelope in the batch path) and then thread
// them through every layer of the evaluator without writing back into
// req. This eliminates the prior tier0BatchAdapter / fallbackEvaluator
// adapter pair, whose only job was to mutate req.Signals before
// calling the gate.
func (g *Gate) Apply(req dto.EvaluateRequest, signals dto.RiskSignals) dto.Tier0Outcome {
	return g.ApplyWithContext(context.Background(), req, signals)
}

// ApplyWithContext is Apply with an explicit context. The ti_match
// path uses the context for its DB / cache lookup; the existing
// reason-code paths do not.
func (g *Gate) ApplyWithContext(ctx context.Context, req dto.EvaluateRequest, signals dto.RiskSignals) dto.Tier0Outcome {
	out := dto.Tier0Outcome{}

	// 0. Threat-intel lookup runs FIRST so a high-severity IOC hit
	//    overrides every relationship-based bypass below. A vendor
	//    whose domain just landed on URLhaus should NOT be bypassed
	//    as "vendor_trusted" — they should be quarantined.
	//
	//    The lookup is best-effort: if the store / cache fails the
	//    gate logs and falls through to the heuristic path. The
	//    fallthrough is required because Tier 0 is hot — a DB
	//    outage cannot block evaluation entirely.
	if tiOut, applied := g.applyTIMatch(ctx, req, signals); applied {
		return tiOut
	}

	// 1. Internal-trusted bypass — guarded by ATO heuristic.
	if g.cfg.SkipInternal && signals.IsInternal {
		atoResult := g.ato.Check(req, signals)
		if atoResult.Flagged {
			out.Bypass = false
			out.ForceEscalate = true
			out.Reason = "internal_ato_suspected"
			return out
		}
		out.Bypass = true
		out.SkipML = true
		out.Reason = "internal_trusted"
		out.ForcedCategory = constant.CategoryInternalTrusted
		return out
	}

	// 2. Vendor-trusted bypass — guarded by vendor-compromise heuristic.
	if g.cfg.SkipVendor && signals.IsFromVendor {
		if signals.LooksLikeVendorCompromise {
			out.Bypass = false
			out.ForceEscalate = true
			out.Reason = "vendor_compromise_suspected"
			return out
		}
		out.Bypass = true
		out.SkipML = true
		out.Reason = "vendor_trusted"
		out.ForcedCategory = constant.CategoryVendorTrusted
		return out
	}

	// 3. Recurring service bypass — either signalled by the prefilter or
	//    detected by pattern-match here.
	if g.cfg.SkipRecurring && (signals.IsRecurringService || g.recurring.IsRecurring(req.Sender)) {
		out.Bypass = true
		out.SkipML = true
		out.Reason = "recurring_service"
		out.ForcedCategory = constant.CategoryNewsletter
		return out
	}

	// 4. High-volume sender — skip ML, defer to Rspamd-only path.
	if g.cfg.HighVolumeRspamdOnly && signals.IsHighVolumeSender {
		out.SkipML = true
		out.RspamdOnly = true
		out.Reason = "high_volume_sender"
		return out
	}

	// 5. Relationship-category modifiers don't bypass; they tune the
	//    downstream pipeline. The reason string mirrors the actual
	//    relationship category so audit logs and metrics keep the
	//    correct escalation cause (FirstTimeExternal vs LapsedContact
	//    are both ATO-relevant but for different reasons).
	if signals.ForceEscalate() {
		out.ForceEscalate = true
		switch signals.RelationshipCategory {
		case dto.RelationshipLapsedContact:
			out.Reason = "lapsed_contact"
		default:
			out.Reason = "first_time_external"
		}
	}
	if signals.LowerTier1Threshold() && g.cfg.Tier1PartnerThreshold > 0 {
		out.Tier1ThresholdOverride = g.cfg.Tier1PartnerThreshold
		if out.Reason == "" {
			out.Reason = "partner_or_customer"
		}
	}
	return out
}

// applyTIMatch issues a threat-intel lookup and returns an outcome
// when the strongest match has severity >= 50 (quarantine threshold).
// Lower severity returns (zero, false) so the caller continues
// through the relationship-based bypass path AND keeps the
// ti_match reason code attached to the Tier0Outcome.
//
// The (Tier0Outcome, true) return shape is reserved for the
// short-circuit case: the match was severe enough to overwrite
// every downstream classification. Lower-severity matches don't
// short-circuit — they are folded into a downstream-only reason
// code addition (the caller drops the outcome on the floor and we
// rely on the Tier0Outcome.TIMatch field being attached for the
// flag-only case via the surrounding caller).
//
// In practice the caller (ApplyWithContext) only treats applied=true
// as "skip the heuristic gates". When the match is flag-only (<50)
// we still want the reason code captured, so applied=false is
// paired with a non-nil Tier0Outcome that the caller MERGES into
// its accumulating outcome. See the explicit merge in
// ApplyWithContext for the contract.
func (g *Gate) applyTIMatch(ctx context.Context, req dto.EvaluateRequest, signals dto.RiskSignals) (dto.Tier0Outcome, bool) {
	if g.ti == nil {
		return dto.Tier0Outcome{}, false
	}
	matches, err := g.ti.Check(ctx, req, signals)
	if err != nil {
		// Soft-fail: log, count "error", do not affect outcome.
		if g.logger != nil {
			g.logger.Warn("tier0: ti_match lookup failed",
				slog.Any("error", err),
				slog.String("message_id", req.MessageID))
		}
		if g.metrics != nil {
			g.metrics.ObserveLookup("error")
		}
		return dto.Tier0Outcome{}, false
	}
	if len(matches) == 0 {
		if g.metrics != nil {
			g.metrics.ObserveLookup("miss")
		}
		return dto.Tier0Outcome{}, false
	}
	if g.metrics != nil {
		g.metrics.ObserveLookup("hit")
	}

	strongest, otherFeeds := PickStrongest(matches)
	tim := &dto.TIMatch{
		Indicator:       strongest.Indicator,
		IndicatorType:   string(strongest.IndicatorType),
		FeedID:          strongest.FeedID,
		FeedName:        strongest.FeedName,
		Severity:        strongest.Severity,
		Tags:            strongest.Tags,
		AdditionalFeeds: otherFeeds,
	}
	cat, bypass := SeverityTier(strongest.Severity)
	out := dto.Tier0Outcome{
		Reason:  "ti_match",
		TIMatch: tim,
	}
	switch {
	case bypass && (cat == constant.CategoryLikelyPhishing):
		// >=75: block-equivalent. Bypass ML; the action layer
		// maps LikelyPhishing to a block disposition.
		out.Bypass = true
		out.SkipML = true
		out.ForcedCategory = cat
		if g.metrics != nil {
			g.metrics.ObserveMatch("block")
		}
		return out, true
	case bypass:
		// 50-74: quarantine-equivalent. Bypass ML and force
		// the SuspiciousURL category which the downstream
		// provider integration maps to a quarantine action.
		out.Bypass = true
		out.SkipML = true
		out.ForcedCategory = cat
		if g.metrics != nil {
			g.metrics.ObserveMatch("quarantine")
		}
		return out, true
	default:
		// <50: flag-only. Force escalation to Tier 2 so the
		// LLM can corroborate, but keep the ML pipeline live.
		out.ForceEscalate = true
		if g.metrics != nil {
			g.metrics.ObserveMatch("flag")
		}
		return out, true
	}
}
