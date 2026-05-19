package constant

// Tier is the user-facing severity bucket applied to an evaluated message.
// The six tiers map to the banner / label flavours documented in
// ARCHITECTURE.md Section 8.2.
type Tier string

const (
	TierBlocked       Tier = "Blocked"
	TierHighRisk      Tier = "HighRisk"
	TierWarning       Tier = "Warning"
	TierCaution       Tier = "Caution"
	TierInformational Tier = "Informational"
	TierTrusted       Tier = "Trusted"
)

// AllTiers lists every tier from most-severe to least-severe.
var AllTiers = []Tier{
	TierBlocked,
	TierHighRisk,
	TierWarning,
	TierCaution,
	TierInformational,
	TierTrusted,
}

// Severity returns an ordinal where 0 == least severe (Trusted) and 5 ==
// most severe (Blocked). Useful for monotonic comparisons.
func (t Tier) Severity() int {
	switch t {
	case TierBlocked:
		return 5
	case TierHighRisk:
		return 4
	case TierWarning:
		return 3
	case TierCaution:
		return 2
	case TierInformational:
		return 1
	case TierTrusted:
		return 0
	default:
		return -1
	}
}

// IsBlocking reports whether messages at this tier should be quarantined
// rather than delivered. Currently only Blocked qualifies.
func (t Tier) IsBlocking() bool {
	return t == TierBlocked
}

// AllowsURLRewrite reports whether links in the message body should be
// rewritten through the interstitial. HighRisk and Blocked qualify.
func (t Tier) AllowsURLRewrite() bool {
	return t == TierBlocked || t == TierHighRisk
}

// AllowsMarkSafe reports whether the banner should offer a "Mark Safe" /
// "Trust Sender" button. Tiers above Warning hide the button so users
// don't accidentally whitelist a real threat.
func (t Tier) AllowsMarkSafe() bool {
	return t == TierWarning || t == TierCaution || t == TierInformational
}

// LabelName returns the canonical Gmail label / Outlook category for the
// tier. Used by the label applier.
func (t Tier) LabelName() string {
	return "SN360 / " + string(t)
}

// Valid reports whether t is one of the well-known tiers.
func (t Tier) Valid() bool {
	for _, known := range AllTiers {
		if t == known {
			return true
		}
	}
	return false
}
