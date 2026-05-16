package action

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestDefaultTierThresholdsValidates(t *testing.T) {
	if err := DefaultTierThresholds().Validate(); err != nil {
		t.Fatalf("default thresholds should validate: %v", err)
	}
}

func TestTierThresholdsValidateRejectsNonMonotone(t *testing.T) {
	cases := []TierThresholds{
		{Blocked: 50, HighRisk: 60, Warning: 40, Caution: 30, Informational: 20, FirstContactFloor: constant.TierInformational},
		{Blocked: 90, HighRisk: 80, Warning: 80, Caution: 30, Informational: 20, FirstContactFloor: constant.TierInformational},
		{Blocked: 101, HighRisk: 70, Warning: 50, Caution: 30, Informational: 15, FirstContactFloor: constant.TierInformational},
		{Blocked: 90, HighRisk: 70, Warning: 50, Caution: 30, Informational: -1, FirstContactFloor: constant.TierInformational},
		{Blocked: 85, HighRisk: 70, Warning: 50, Caution: 30, Informational: 15, FirstContactFloor: constant.Tier("Bogus")},
	}
	for i, tc := range cases {
		if err := tc.Validate(); err == nil {
			t.Errorf("case %d should have failed validation", i)
		}
	}
}

func mustDecider(t *testing.T) *TierDecider {
	t.Helper()
	d, err := NewTierDecider(TierThresholds{})
	if err != nil {
		t.Fatalf("decider: %v", err)
	}
	return d
}

func TestTierDeciderScoreThresholds(t *testing.T) {
	d := mustDecider(t)
	cases := []struct {
		score int
		want  constant.Tier
	}{
		{0, constant.TierTrusted},
		{14, constant.TierTrusted},
		{15, constant.TierInformational},
		{29, constant.TierInformational},
		{30, constant.TierCaution},
		{49, constant.TierCaution},
		{50, constant.TierWarning},
		{69, constant.TierWarning},
		{70, constant.TierHighRisk},
		{84, constant.TierHighRisk},
		{85, constant.TierBlocked},
		{100, constant.TierBlocked},
	}
	for _, tc := range cases {
		got := d.Decide(dto.EvaluateResult{Score: tc.score, Primary: constant.CategoryLikelyPhishing})
		if got != tc.want {
			t.Errorf("score=%d: got %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestTierDeciderCategoryOverridesBeatScore(t *testing.T) {
	d := mustDecider(t)
	for _, cat := range []constant.Category{constant.CategoryInternalTrusted, constant.CategoryVendorTrusted} {
		got := d.Decide(dto.EvaluateResult{Score: 99, Primary: cat})
		if got != constant.TierTrusted {
			t.Errorf("category %s should pin Trusted, got %s", cat, got)
		}
	}
	got := d.Decide(dto.EvaluateResult{Score: 99, Primary: constant.CategoryNewsletter})
	if got != constant.TierInformational {
		t.Errorf("Newsletter should pin Informational, got %s", got)
	}
}

func TestTierDeciderTier0BypassReadsForcedCategory(t *testing.T) {
	d := mustDecider(t)
	r := dto.EvaluateResult{
		Score:   42,
		Primary: constant.CategoryFirstContactExternal,
		Tier0:   &dto.Tier0Outcome{Bypass: true, ForcedCategory: constant.CategoryInternalTrusted},
	}
	if got := d.Decide(r); got != constant.TierTrusted {
		t.Errorf("Tier0 bypass with InternalTrusted should pin Trusted, got %s", got)
	}
}

func TestTierDeciderFirstContactFloor(t *testing.T) {
	d := mustDecider(t)
	r := dto.EvaluateResult{Score: 5, Primary: constant.CategoryFirstContactExternal}
	if got := d.Decide(r); got != constant.TierInformational {
		t.Errorf("first-contact floor should pin Informational, got %s", got)
	}
}
