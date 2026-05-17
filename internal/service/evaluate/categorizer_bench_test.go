package evaluate_test

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
)

// BenchmarkRuleCategorizer_HighSignal measures the worst-case path
// through Decide: every threat signal set and Tier 2 categories
// populated, so every branch fires.
func BenchmarkRuleCategorizer_HighSignal(b *testing.B) {
	c := evaluate.NewRuleCategorizer()
	res := dto.EvaluateResult{
		Score:       86,
		ReasonCodes: []string{"phish_lex", "bec_imperson", "credential_form"},
		Tier2: &dto.Tier2Outcome{
			Categories: []constant.Category{
				constant.CategoryCredentialHarvesting,
				constant.CategoryLikelyPhishing,
			},
		},
	}
	sig := dto.RiskSignals{
		IsExternal:                true,
		HasLookalikeDomain:        true,
		HasSuspiciousURL:          true,
		HasSuspiciousAttachment:   true,
		HasQRCode:                 true,
		HasInvoiceHint:            true,
		HasCredentialLex:          true,
		AuthFailed:                true,
		LooksLikeAccountTakeover:  true,
		LooksLikeVendorCompromise: true,
		RelationshipCategory:      dto.RelationshipFirstTimeExternal,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Decide(res, sig)
	}
}

// BenchmarkRuleCategorizer_LowSignal measures a benign message — no
// signals fire, so the categoriser hits the "FirstContactExternal"
// fallback path.
func BenchmarkRuleCategorizer_LowSignal(b *testing.B) {
	c := evaluate.NewRuleCategorizer()
	res := dto.EvaluateResult{Score: 8}
	sig := dto.RiskSignals{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Decide(res, sig)
	}
}

// BenchmarkRuleCategorizer_AllSignals iterates over a small fixed set
// of representative signal combinations to amortise per-message cost
// across the realistic mix of inputs the categoriser sees.
func BenchmarkRuleCategorizer_AllSignals(b *testing.B) {
	c := evaluate.NewRuleCategorizer()
	mix := []dto.RiskSignals{
		{IsInternal: true},
		{IsFromVendor: true},
		{IsRecurringService: true},
		{HasLookalikeDomain: true, HasInvoiceHint: true},
		{HasSuspiciousURL: true, HasCredentialLex: true},
		{AuthFailed: true, HasFailedAuth: true},
		{HasQRCode: true, HasSuspiciousURL: true},
		{LooksLikeAccountTakeover: true, IsExternal: true},
	}
	res := dto.EvaluateResult{Score: 65}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Decide(res, mix[i%len(mix)])
	}
}

// BenchmarkRuleCategorizer_Categorise measures the interface entry
// point (Categorise) which is the one the evaluator actually invokes
// at runtime. It allocates a reasons slice on every call, so this
// benchmark also surfaces allocation regressions.
func BenchmarkRuleCategorizer_Categorise(b *testing.B) {
	c := evaluate.NewRuleCategorizer()
	res := dto.EvaluateResult{
		Score: 78,
		Tier2: &dto.Tier2Outcome{
			Categories: []constant.Category{constant.CategoryLikelyPhishing},
		},
	}
	sig := dto.RiskSignals{
		HasLookalikeDomain: true,
		HasSuspiciousURL:   true,
		HasCredentialLex:   true,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.Categorise(res, sig)
	}
}
