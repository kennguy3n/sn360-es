package evaluate

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// TestForcedTierFor locks in the mapping the Tier 0 short-circuit
// uses to turn a forced category into a verdict tier. The threat-
// intel gate (WS-5B.3) added two new forced categories
// (CategoryLikelyPhishing for the >=75 block-equivalent path,
// CategorySuspiciousURL for the 50-74 quarantine-equivalent path);
// without this test, regressing the mapping would silently demote an
// IOC-confirmed phishing domain to TierTrusted and the action layer
// would deliver it as safe.
func TestForcedTierFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		category constant.Category
		want     constant.Tier
	}{
		// Trusted gates produced by sender_internal /
		// vendor_trusted bypasses.
		{"internal_trusted", constant.CategoryInternalTrusted, constant.TierTrusted},
		{"vendor_trusted", constant.CategoryVendorTrusted, constant.TierTrusted},
		// Newsletter gate (existing).
		{"newsletter", constant.CategoryNewsletter, constant.TierInformational},
		// Threat-intel gate (WS-5B.3). The mapping MUST keep
		// block-equivalent IOC matches in TierBlocked and
		// quarantine-equivalent matches in TierHighRisk —
		// downstream isTerminalTier and quarantine routing keys
		// off these tiers, so demoting either to a non-terminal
		// tier reintroduces the WS-5B.3 silent-bypass bug.
		{"ti_block", constant.CategoryLikelyPhishing, constant.TierBlocked},
		{"ti_quarantine", constant.CategorySuspiciousURL, constant.TierHighRisk},
		// Unknown categories MUST fall through to TierTrusted —
		// the gate never emits these, and this empty-string case
		// is the same shape the evaluator sees when
		// ForcedCategory is left zero-valued by a non-bypassing
		// gate (the caller never reads the result in that
		// path).
		{"empty_default", constant.Category(""), constant.TierTrusted},
		{"unknown_default", constant.Category("UNKNOWN_CATEGORY"), constant.TierTrusted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ForcedTierFor(tc.category); got != tc.want {
				t.Errorf("ForcedTierFor(%q) = %q; want %q",
					tc.category, got, tc.want)
			}
		})
	}
}
