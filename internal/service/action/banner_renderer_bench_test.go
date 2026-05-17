package action_test

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BenchmarkBannerRenderer_HighRisk measures the cost of rendering the
// HighRisk banner in English. This is the most common path in
// production traffic (English is the dominant locale).
func BenchmarkBannerRenderer_HighRisk(b *testing.B) {
	r := mustBenchRenderer(b)
	in := action.BannerInput{
		Tier:        constant.TierHighRisk,
		Primary:     constant.CategoryLikelyPhishing,
		Secondary:   []constant.Category{constant.CategoryCredentialHarvesting},
		ReasonCodes: []string{"phish_lex", "lookalike_domain"},
		Locale:      "en",
		ActionToken: "tok-bench-high",
		SenderAuth:  action.AuthFailed,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Render(in); err != nil {
			b.Fatalf("render: %v", err)
		}
	}
}

// BenchmarkBannerRenderer_AllTiers cycles through every tier so we
// pay the cost of switching between templates on each iteration.
// This exposes regressions that only show up when locale + tier
// combinations vary (e.g. template-cache misses).
func BenchmarkBannerRenderer_AllTiers(b *testing.B) {
	r := mustBenchRenderer(b)
	tiers := []constant.Tier{
		constant.TierBlocked,
		constant.TierHighRisk,
		constant.TierWarning,
		constant.TierCaution,
		constant.TierInformational,
		constant.TierTrusted,
	}
	primary := []constant.Category{
		constant.CategoryLikelyPhishing,
		constant.CategoryBECImpersonation,
		constant.CategorySuspiciousURL,
		constant.CategoryFirstContactExternal,
		constant.CategoryNewsletter,
		constant.CategoryInternalTrusted,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % len(tiers)
		in := action.BannerInput{
			Tier:        tiers[idx],
			Primary:     primary[idx],
			Locale:      "en",
			ActionToken: "tok-bench-all",
			SenderAuth:  action.AuthVerified,
		}
		if _, err := r.Render(in); err != nil {
			b.Fatalf("render: %v", err)
		}
	}
}

// BenchmarkBannerRenderer_RTL measures the cost of rendering in an
// RTL locale (Arabic). The RTL path activates the dir="rtl" injection
// in the template, so this benchmark surfaces cost regressions in the
// per-locale code path.
func BenchmarkBannerRenderer_RTL(b *testing.B) {
	r := mustBenchRenderer(b)
	in := action.BannerInput{
		Tier:        constant.TierHighRisk,
		Primary:     constant.CategoryBECImpersonation,
		Locale:      "ar",
		ActionToken: "tok-bench-rtl",
		SenderAuth:  action.AuthFailed,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Render(in); err != nil {
			b.Fatalf("render: %v", err)
		}
	}
}

func mustBenchRenderer(b *testing.B) *action.BannerRenderer {
	b.Helper()
	cat, err := action.DefaultBannerCatalog()
	if err != nil {
		b.Fatalf("default catalog: %v", err)
	}
	r, err := action.NewBannerRenderer(cat)
	if err != nil {
		b.Fatalf("renderer: %v", err)
	}
	return r
}
