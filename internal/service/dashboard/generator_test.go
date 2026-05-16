package dashboard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

type fakeSource struct {
	emails int
	tiers  []dto.TierCount
	cats   []dto.CategoryCount
	fb     dto.FeedbackStats
	qu     dto.QuarantineStats
	sim    dto.SimulationStats
	fp, fn int
	err    error
}

func (f *fakeSource) EmailsProcessed(_ context.Context, _ string, _ dto.TimeRange) (int, error) {
	return f.emails, f.err
}
func (f *fakeSource) ThreatsByTier(_ context.Context, _ string, _ dto.TimeRange) ([]dto.TierCount, error) {
	return f.tiers, f.err
}
func (f *fakeSource) ThreatsByCategory(_ context.Context, _ string, _ dto.TimeRange) ([]dto.CategoryCount, error) {
	return f.cats, f.err
}
func (f *fakeSource) Feedback(_ context.Context, _ string, _ dto.TimeRange) (dto.FeedbackStats, error) {
	return f.fb, f.err
}
func (f *fakeSource) Quarantine(_ context.Context, _ string, _ dto.TimeRange) (dto.QuarantineStats, error) {
	return f.qu, f.err
}
func (f *fakeSource) Simulation(_ context.Context, _ string, _ dto.TimeRange) (dto.SimulationStats, error) {
	return f.sim, f.err
}
func (f *fakeSource) FalseRates(_ context.Context, _ string, _ dto.TimeRange) (int, int, error) {
	return f.fp, f.fn, f.err
}

type fakeNarrative struct{ out string; err error }

func (f *fakeNarrative) Generate(_ context.Context, _ dto.DashboardSummary) (string, error) {
	return f.out, f.err
}

func TestDashboard_GenerateSummary_Aggregates(t *testing.T) {
	src := &fakeSource{
		emails: 1234,
		tiers: []dto.TierCount{
			{Tier: "trusted", Count: 1000},
			{Tier: "warning", Count: 50},
			{Tier: "high_risk", Count: 20},
		},
		cats: []dto.CategoryCount{
			{Category: "BEC_Suspect", Count: 30},
			{Category: "Phishing_Likely", Count: 50},
		},
		fb: dto.FeedbackStats{ReportedPhishing: 10},
		qu: dto.QuarantineStats{Quarantined: 5, Released: 1},
		fp: 2, fn: 1,
	}
	gen, err := NewDashboardGenerator(DashboardGeneratorConfig{
		Source: src,
		Clock:  func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewDashboardGenerator: %v", err)
	}
	out, err := gen.GenerateSummary(context.Background(), "acme", dto.TimeRange{})
	if err != nil {
		t.Fatalf("GenerateSummary: %v", err)
	}
	if out.EmailsProcessed != 1234 {
		t.Fatalf("emails: %d", out.EmailsProcessed)
	}
	if len(out.ThreatsByTier) == 0 || out.ThreatsByTier[0].Tier != "trusted" {
		t.Fatalf("tiers not sorted by count: %+v", out.ThreatsByTier)
	}
	if len(out.ThreatsByCat) == 0 || out.ThreatsByCat[0].Category != "Phishing_Likely" {
		t.Fatalf("cats not sorted by count: %+v", out.ThreatsByCat)
	}
	if out.Narrative == "" {
		t.Fatal("expected narrative")
	}
	// 70 threats = 50 warning + 20 high_risk. Asserting the count is
	// present in the narrative catches future regressions of the tier
	// matching logic in DeterministicNarrative (which previously
	// silently dropped canonical PascalCase tiers).
	if !strings.Contains(out.Narrative, "70 as Warning+") {
		t.Fatalf("narrative missing threat count %q: %q", "70 as Warning+", out.Narrative)
	}
}

// TestDashboard_DeterministicNarrative_CanonicalTiers exercises
// DeterministicNarrative against the canonical PascalCase constant.Tier
// values that the production MetricsSource emits. The previous version
// of the function only matched lowercase / snake_case variants, so
// production traffic collapsed the threat count to 0. Keeping this
// test alongside the snake_case case above prevents regression in
// either direction.
func TestDashboard_DeterministicNarrative_CanonicalTiers(t *testing.T) {
	src := &fakeSource{
		emails: 500,
		tiers: []dto.TierCount{
			{Tier: "Trusted", Count: 400},
			{Tier: "Warning", Count: 40},
			{Tier: "HighRisk", Count: 25},
			{Tier: "Blocked", Count: 5},
		},
		cats: []dto.CategoryCount{
			{Category: "BEC_Suspect", Count: 70},
		},
	}
	gen, _ := NewDashboardGenerator(DashboardGeneratorConfig{
		Source: src,
		Clock:  func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	})
	out, err := gen.GenerateSummary(context.Background(), "acme", dto.TimeRange{})
	if err != nil {
		t.Fatalf("GenerateSummary: %v", err)
	}
	// Warning (40) + HighRisk (25) + Blocked (5) = 70 threats.
	if !strings.Contains(out.Narrative, "70 as Warning+") {
		t.Fatalf("narrative missing canonical-tier threat count: %q", out.Narrative)
	}
}

func TestDashboard_RequiresTenant(t *testing.T) {
	gen, _ := NewDashboardGenerator(DashboardGeneratorConfig{Source: &fakeSource{}})
	if _, err := gen.GenerateSummary(context.Background(), "", dto.TimeRange{}); err == nil {
		t.Fatal("expected error for empty tenant")
	}
}

func TestDashboard_BadRange(t *testing.T) {
	gen, _ := NewDashboardGenerator(DashboardGeneratorConfig{Source: &fakeSource{}})
	r := dto.TimeRange{Start: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := gen.GenerateSummary(context.Background(), "acme", r); err == nil {
		t.Fatal("expected error for inverted range")
	}
}

func TestDashboard_PropagatesSourceError(t *testing.T) {
	src := &fakeSource{err: errors.New("db down")}
	gen, _ := NewDashboardGenerator(DashboardGeneratorConfig{Source: src})
	if _, err := gen.GenerateSummary(context.Background(), "acme", dto.TimeRange{}); err == nil {
		t.Fatal("expected error from source")
	}
}

func TestDashboard_UsesAINarrativeWhenWired(t *testing.T) {
	gen, _ := NewDashboardGenerator(DashboardGeneratorConfig{
		Source:    &fakeSource{emails: 10},
		Narrative: &fakeNarrative{out: "AI: 10 messages reviewed."},
	})
	out, _ := gen.GenerateSummary(context.Background(), "acme", dto.TimeRange{})
	if !strings.Contains(out.Narrative, "AI: 10 messages reviewed.") {
		t.Fatalf("narrative: %q", out.Narrative)
	}
}

func TestDashboard_NoDataNarrative(t *testing.T) {
	gen, _ := NewDashboardGenerator(DashboardGeneratorConfig{Source: &fakeSource{}})
	out, _ := gen.GenerateSummary(context.Background(), "acme", dto.TimeRange{})
	if !strings.Contains(out.Narrative, "no email traffic") {
		t.Fatalf("narrative: %q", out.Narrative)
	}
}
