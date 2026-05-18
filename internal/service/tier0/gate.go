package tier0

import (
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

// Apply runs the gate on req and returns the structured Tier0Outcome. It
// does not mutate req. The outcome's Bypass field is the canonical signal
// to skip downstream ML.
func (g *Gate) Apply(req dto.EvaluateRequest) dto.Tier0Outcome {
	out := dto.Tier0Outcome{}

	// 1. Internal-trusted bypass — guarded by ATO heuristic.
	if g.cfg.SkipInternal && req.Signals.IsInternal {
		atoResult := g.ato.Check(req)
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

	// 2. Vendor-trusted bypass. We also defer to the explicit recurring
	//    detector below in case the vendor uses a "noreply@" mailbox.
	if g.cfg.SkipVendor && req.Signals.IsFromVendor {
		out.Bypass = true
		out.SkipML = true
		out.Reason = "vendor_trusted"
		out.ForcedCategory = constant.CategoryVendorTrusted
		return out
	}

	// 3. Recurring service bypass — either signalled by the prefilter or
	//    detected by pattern-match here.
	if g.cfg.SkipRecurring && (req.Signals.IsRecurringService || g.recurring.IsRecurring(req.Sender)) {
		out.Bypass = true
		out.SkipML = true
		out.Reason = "recurring_service"
		out.ForcedCategory = constant.CategoryNewsletter
		return out
	}

	// 4. High-volume sender — skip ML, defer to Rspamd-only path.
	if g.cfg.HighVolumeRspamdOnly && req.Signals.IsHighVolumeSender {
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
	if req.Signals.ForceEscalate() {
		out.ForceEscalate = true
		switch req.Signals.RelationshipCategory {
		case dto.RelationshipLapsedContact:
			out.Reason = "lapsed_contact"
		default:
			out.Reason = "first_time_external"
		}
	}
	if req.Signals.LowerTier1Threshold() && g.cfg.Tier1PartnerThreshold > 0 {
		out.Tier1ThresholdOverride = g.cfg.Tier1PartnerThreshold
		if out.Reason == "" {
			out.Reason = "partner_or_customer"
		}
	}
	return out
}
