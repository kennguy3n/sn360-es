package education

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// analyticsFixture builds an AnalyticsService backed by in-memory stores
// and the default template catalog, with a deterministic clock.
type analyticsFixture struct {
	svc          *AnalyticsService
	campaigns    *MemoryCampaignStore
	interactions *MemoryInteractionStore
	now          time.Time
}

func newAnalyticsFixture(t *testing.T) *analyticsFixture {
	t.Helper()
	templates, err := LoadDefaultTemplates()
	if err != nil {
		t.Fatalf("LoadDefaultTemplates: %v", err)
	}
	campaigns := NewMemoryCampaignStore()
	interactions := NewMemoryInteractionStore()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	scorer := NewResilienceScorer(ResilienceScorerConfig{Clock: func() time.Time { return now }})
	svc, err := NewAnalyticsService(AnalyticsConfig{
		Campaigns:    campaigns,
		Interactions: interactions,
		Templates:    templates,
		Scorer:       scorer,
		Clock:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAnalyticsService: %v", err)
	}
	return &analyticsFixture{svc: svc, campaigns: campaigns, interactions: interactions, now: now}
}

func (f *analyticsFixture) addCampaign(t *testing.T, c dto.Campaign) {
	t.Helper()
	if err := f.campaigns.SaveCampaign(context.Background(), c); err != nil {
		t.Fatalf("SaveCampaign: %v", err)
	}
}

func (f *analyticsFixture) record(t *testing.T, campaignID, user string, action dto.UserInteractionType, at time.Time) {
	t.Helper()
	err := f.interactions.Append(context.Background(), dto.UserInteraction{
		CampaignID: campaignID,
		UserHash:   user,
		Action:     action,
		OccurredAt: at,
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
}

func TestNewAnalyticsService_RequiresDeps(t *testing.T) {
	templates, _ := LoadDefaultTemplates()
	cases := []struct {
		name string
		cfg  AnalyticsConfig
	}{
		{"no campaigns", AnalyticsConfig{Interactions: NewMemoryInteractionStore(), Templates: templates}},
		{"no interactions", AnalyticsConfig{Campaigns: NewMemoryCampaignStore(), Templates: templates}},
		{"no templates", AnalyticsConfig{Campaigns: NewMemoryCampaignStore(), Interactions: NewMemoryInteractionStore()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAnalyticsService(tc.cfg); err == nil {
				t.Fatal("expected error for missing dependency")
			}
		})
	}
}

func TestComputeAnalytics_Validation(t *testing.T) {
	f := newAnalyticsFixture(t)
	if _, err := f.svc.ComputeAnalytics(context.Background(), "", dto.TimeRange{}); err == nil {
		t.Fatal("expected error for empty tenant_id")
	}
	// End before start should fail.
	bad := dto.TimeRange{Start: f.now, End: f.now.Add(-time.Hour)}
	if _, err := f.svc.ComputeAnalytics(context.Background(), "t1", bad); err == nil {
		t.Fatal("expected error for end<=start")
	}
}

func TestComputeAnalytics_EmptyTenant(t *testing.T) {
	f := newAnalyticsFixture(t)
	got, err := f.svc.ComputeAnalytics(context.Background(), "t1", dto.TimeRange{})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}
	if len(got.CampaignCompletionRates) != 0 || len(got.ClickRatesByAttackType) != 0 {
		t.Errorf("expected empty series, got %+v", got)
	}
	// Regulatory map should still carry a stable row per regime at 0.
	for _, cat := range dto.AllRegulatoryCategories {
		if v, ok := got.RegulatoryCompletion[string(cat)]; !ok || v != 0 {
			t.Errorf("regulatory %q = %v, ok=%v; want 0", cat, v, ok)
		}
	}
}

func TestComputeAnalytics_ClickRatesAndCompletion(t *testing.T) {
	f := newAnalyticsFixture(t)
	start := f.now.Add(-30 * 24 * time.Hour)
	created := f.now.Add(-10 * 24 * time.Hour)

	// Campaign A: bec/easy, 4 targets. 4 delivered, 1 clicked, 2 reported.
	f.addCampaign(t, dto.Campaign{
		CampaignID: "campA", TenantID: "t1", TemplateID: "bec.easy.ceo_gift_card",
		Difficulty: dto.DifficultyEasy, Status: dto.CampaignCompleted,
		CreatedAt: created, TargetCount: 4,
	})
	for _, u := range []string{"u1", "u2", "u3", "u4"} {
		f.record(t, "campA", u, dto.InteractionDelivered, created)
	}
	f.record(t, "campA", "u1", dto.InteractionClickedLink, created.Add(time.Hour))
	f.record(t, "campA", "u2", dto.InteractionReportedPhishing, created.Add(time.Hour))
	f.record(t, "campA", "u3", dto.InteractionReportedPhishing, created.Add(time.Hour))

	got, err := f.svc.ComputeAnalytics(context.Background(), "t1", dto.TimeRange{Start: start, End: f.now})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}

	// Click rate by attack type: 1 click / 4 delivered = 0.25.
	if len(got.ClickRatesByAttackType) != 1 {
		t.Fatalf("expected 1 attack-type rate, got %d", len(got.ClickRatesByAttackType))
	}
	if got.ClickRatesByAttackType[0].AttackType != dto.AttackTypeBEC {
		t.Errorf("attack type = %q", got.ClickRatesByAttackType[0].AttackType)
	}
	if got.ClickRatesByAttackType[0].ClickRate != 0.25 {
		t.Errorf("click rate = %v, want 0.25", got.ClickRatesByAttackType[0].ClickRate)
	}

	// Completion: decided = {u1 clicked, u2, u3 reported} = 3 / target 4 = 0.75.
	if len(got.CampaignCompletionRates) != 1 {
		t.Fatalf("expected 1 completion date, got %d", len(got.CampaignCompletionRates))
	}
	if got.CampaignCompletionRates[0].Rate != 0.75 {
		t.Errorf("completion rate = %v, want 0.75", got.CampaignCompletionRates[0].Rate)
	}

	// Top clicked: campA template with 1 click.
	if len(got.TopClickedTemplates) != 1 || got.TopClickedTemplates[0].ClickCount != 1 {
		t.Errorf("top clicked = %+v", got.TopClickedTemplates)
	}
}

func TestComputeAnalytics_RegulatoryCompletion(t *testing.T) {
	f := newAnalyticsFixture(t)
	created := f.now.Add(-5 * 24 * time.Hour)

	// HIPAA campaign using a regulatory template: 2 targets, 1 completes.
	f.addCampaign(t, dto.Campaign{
		CampaignID: "hip", TenantID: "t1", TemplateID: "hipaa.easy.phi_email",
		Difficulty: dto.DifficultyEasy, Status: dto.CampaignCompleted,
		CreatedAt: created, TargetCount: 2,
	})
	f.record(t, "hip", "u1", dto.InteractionDelivered, created)
	f.record(t, "hip", "u2", dto.InteractionDelivered, created)
	f.record(t, "hip", "u1", dto.InteractionReportedPhishing, created.Add(time.Hour))

	got, err := f.svc.ComputeAnalytics(context.Background(), "t1", dto.TimeRange{End: f.now})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}
	if got.RegulatoryCompletion["hipaa"] != 0.5 {
		t.Errorf("hipaa completion = %v, want 0.5", got.RegulatoryCompletion["hipaa"])
	}
	if got.RegulatoryCompletion["pci_dss"] != 0 || got.RegulatoryCompletion["sox"] != 0 {
		t.Errorf("expected 0 for pci/sox, got %+v", got.RegulatoryCompletion)
	}
}

func TestComputeAnalytics_WindowFiltersOldCampaigns(t *testing.T) {
	f := newAnalyticsFixture(t)
	// Campaign well outside the 90d window.
	old := f.now.Add(-200 * 24 * time.Hour)
	f.addCampaign(t, dto.Campaign{
		CampaignID: "old", TenantID: "t1", TemplateID: "bec.easy.ceo_gift_card",
		Difficulty: dto.DifficultyEasy, CreatedAt: old, TargetCount: 1,
	})
	f.record(t, "old", "u1", dto.InteractionClickedLink, old)

	got, err := f.svc.ComputeAnalytics(context.Background(), "t1", dto.TimeRange{End: f.now})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}
	if len(got.ClickRatesByAttackType) != 0 {
		t.Errorf("expected old campaign excluded, got %+v", got.ClickRatesByAttackType)
	}
}

func TestComputeAnalytics_ResilienceTrend(t *testing.T) {
	f := newAnalyticsFixture(t)
	created := f.now.Add(-20 * 24 * time.Hour)
	f.addCampaign(t, dto.Campaign{
		CampaignID: "c1", TenantID: "t1", TemplateID: "bec.easy.ceo_gift_card",
		Difficulty: dto.DifficultyEasy, CreatedAt: created, TargetCount: 2,
	})
	f.record(t, "c1", "u1", dto.InteractionDelivered, created)
	f.record(t, "c1", "u1", dto.InteractionReportedPhishing, created.Add(time.Hour))

	got, err := f.svc.ComputeAnalytics(context.Background(), "t1", dto.TimeRange{End: f.now})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}
	if len(got.ResilienceTrend) == 0 {
		t.Fatal("expected non-empty resilience trend")
	}
	for _, p := range got.ResilienceTrend {
		if p.Score < 0 || p.Score > 100 {
			t.Errorf("score %v out of range at %s", p.Score, p.Date)
		}
	}
}

func TestComputeAnalytics_NilScorerSkipsTrend(t *testing.T) {
	templates, _ := LoadDefaultTemplates()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	campaigns := NewMemoryCampaignStore()
	interactions := NewMemoryInteractionStore()
	svc, err := NewAnalyticsService(AnalyticsConfig{
		Campaigns: campaigns, Interactions: interactions, Templates: templates,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAnalyticsService: %v", err)
	}
	created := now.Add(-2 * 24 * time.Hour)
	_ = campaigns.SaveCampaign(context.Background(), dto.Campaign{
		CampaignID: "c1", TenantID: "t1", TemplateID: "bec.easy.ceo_gift_card",
		Difficulty: dto.DifficultyEasy, CreatedAt: created, TargetCount: 1,
	})
	_ = interactions.Append(context.Background(), dto.UserInteraction{
		CampaignID: "c1", UserHash: "u1", Action: dto.InteractionClickedLink, OccurredAt: created,
	})
	got, err := svc.ComputeAnalytics(context.Background(), "t1", dto.TimeRange{End: now})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}
	if len(got.ResilienceTrend) != 0 {
		t.Errorf("expected empty trend with nil scorer, got %d points", len(got.ResilienceTrend))
	}
}

func TestComputeAnalytics_TenantIsolation(t *testing.T) {
	f := newAnalyticsFixture(t)
	created := f.now.Add(-3 * 24 * time.Hour)
	f.addCampaign(t, dto.Campaign{
		CampaignID: "c1", TenantID: "t1", TemplateID: "bec.easy.ceo_gift_card",
		Difficulty: dto.DifficultyEasy, CreatedAt: created, TargetCount: 1,
	})
	f.record(t, "c1", "u1", dto.InteractionClickedLink, created)

	// A different tenant must see nothing.
	got, err := f.svc.ComputeAnalytics(context.Background(), "t2", dto.TimeRange{End: f.now})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}
	if len(got.ClickRatesByAttackType) != 0 || len(got.TopClickedTemplates) != 0 {
		t.Errorf("tenant t2 leaked t1 data: %+v", got)
	}
}

// TestComputeAnalytics_TopClickedDistinctAcrossCampaigns guards the
// "distinct users" contract on TemplateClickCount: a user who clicks the
// same template in two separate campaigns must be counted once, not
// twice.
func TestComputeAnalytics_TopClickedDistinctAcrossCampaigns(t *testing.T) {
	f := newAnalyticsFixture(t)
	created := f.now.Add(-5 * 24 * time.Hour)
	const tmpl = "bec.easy.ceo_gift_card"
	for _, cid := range []string{"q1", "q2"} {
		f.addCampaign(t, dto.Campaign{
			CampaignID: cid, TenantID: "t1", TemplateID: tmpl,
			Difficulty: dto.DifficultyEasy, CreatedAt: created, TargetCount: 2,
		})
		// Same two users delivered in both campaigns.
		f.record(t, cid, "u1", dto.InteractionDelivered, created)
		f.record(t, cid, "u2", dto.InteractionDelivered, created)
	}
	// u1 clicks the template in BOTH campaigns; u2 clicks in one.
	f.record(t, "q1", "u1", dto.InteractionClickedLink, created.Add(time.Hour))
	f.record(t, "q2", "u1", dto.InteractionClickedLink, created.Add(time.Hour))
	f.record(t, "q2", "u2", dto.InteractionClickedLink, created.Add(time.Hour))

	got, err := f.svc.ComputeAnalytics(context.Background(), "t1", dto.TimeRange{End: f.now})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}
	if len(got.TopClickedTemplates) != 1 {
		t.Fatalf("expected 1 template row, got %+v", got.TopClickedTemplates)
	}
	// Distinct clickers across both campaigns = {u1, u2} = 2 (not 3).
	if got.TopClickedTemplates[0].ClickCount != 2 {
		t.Errorf("click_count = %d, want 2 (distinct users u1,u2)", got.TopClickedTemplates[0].ClickCount)
	}
}

// TestComputeAnalytics_ResilienceTrendDistinctDates guards the
// one-point-per-date contract of the resilience trend. When the range
// isn't a clean multiple of the bucket step, the last loop-generated
// bucket and the always-appended range end can land on the same
// calendar day; the series must collapse them to a single point.
func TestComputeAnalytics_ResilienceTrendDistinctDates(t *testing.T) {
	f := newAnalyticsFixture(t)
	// 36h range with a 24h step yields bucket ends at start+24h and the
	// appended end (start+36h) — both on the same calendar date.
	start := time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC)
	end := start.Add(36 * time.Hour) // 2026-06-01 12:00 UTC
	const tmpl = "bec.easy.ceo_gift_card"
	f.addCampaign(t, dto.Campaign{
		CampaignID: "c1", TenantID: "t1", TemplateID: tmpl,
		Difficulty: dto.DifficultyEasy, CreatedAt: start.Add(6 * time.Hour),
		TargetCount: 1,
	})
	// Deliver before the first bucket so both buckets have a sent user.
	f.record(t, "c1", "u1", dto.InteractionDelivered, start.Add(6*time.Hour))

	got, err := f.svc.ComputeAnalytics(context.Background(), "t1", dto.TimeRange{Start: start, End: end})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}
	if len(got.ResilienceTrend) == 0 {
		t.Fatalf("expected a non-empty resilience trend")
	}
	seen := map[string]struct{}{}
	for _, p := range got.ResilienceTrend {
		if _, dup := seen[p.Date]; dup {
			t.Errorf("duplicate resilience-trend date %q in %+v", p.Date, got.ResilienceTrend)
		}
		seen[p.Date] = struct{}{}
	}
}

// noBatchInteractionStore wraps MemoryInteractionStore but deliberately
// forwards only the InteractionStore interface (Append + ListByCampaign),
// NOT ListByCampaigns. Both production stores implement the batch fast
// path, so this is the only shape that drives loadInteractions down its
// per-campaign fallback branch — the path a third-party store without a
// batch method would hit. The fields use value receivers so the batch
// method is never promoted.
type noBatchInteractionStore struct{ inner *MemoryInteractionStore }

func (s noBatchInteractionStore) Append(ctx context.Context, i dto.UserInteraction) error {
	return s.inner.Append(ctx, i)
}

func (s noBatchInteractionStore) ListByCampaign(ctx context.Context, campaignID string) ([]dto.UserInteraction, error) {
	return s.inner.ListByCampaign(ctx, campaignID)
}

// TestComputeAnalytics_FallbackInteractionLister exercises the
// per-campaign fallback in loadInteractions, which is otherwise dead in
// tests because both concrete stores satisfy batchInteractionLister.
func TestComputeAnalytics_FallbackInteractionLister(t *testing.T) {
	templates, err := LoadDefaultTemplates()
	if err != nil {
		t.Fatalf("LoadDefaultTemplates: %v", err)
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	store := noBatchInteractionStore{inner: NewMemoryInteractionStore()}
	// Guard: if the wrapper ever satisfies the batch interface, the test
	// would silently stop covering the fallback it exists to cover.
	if _, ok := interface{}(store).(batchInteractionLister); ok {
		t.Fatal("wrapper must NOT implement batchInteractionLister, else the fallback is not exercised")
	}
	campaigns := NewMemoryCampaignStore()
	scorer := NewResilienceScorer(ResilienceScorerConfig{Clock: func() time.Time { return now }})
	svc, err := NewAnalyticsService(AnalyticsConfig{
		Campaigns:    campaigns,
		Interactions: store,
		Templates:    templates,
		Scorer:       scorer,
		Clock:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAnalyticsService: %v", err)
	}

	created := now.Add(-5 * 24 * time.Hour)
	const tmpl = "bec.easy.ceo_gift_card"
	if serr := campaigns.SaveCampaign(context.Background(), dto.Campaign{
		CampaignID: "c1", TenantID: "t1", TemplateID: tmpl,
		Difficulty: dto.DifficultyEasy, CreatedAt: created, TargetCount: 2,
	}); serr != nil {
		t.Fatalf("SaveCampaign: %v", serr)
	}
	for _, u := range []string{"u1", "u2"} {
		if aerr := store.Append(context.Background(), dto.UserInteraction{
			CampaignID: "c1", UserHash: u, Action: dto.InteractionDelivered, OccurredAt: created,
		}); aerr != nil {
			t.Fatalf("Append: %v", aerr)
		}
	}
	if aerr := store.Append(context.Background(), dto.UserInteraction{
		CampaignID: "c1", UserHash: "u1", Action: dto.InteractionClickedLink, OccurredAt: created.Add(time.Hour),
	}); aerr != nil {
		t.Fatalf("Append: %v", aerr)
	}

	got, err := svc.ComputeAnalytics(context.Background(), "t1", dto.TimeRange{End: now})
	if err != nil {
		t.Fatalf("ComputeAnalytics: %v", err)
	}
	// The fallback must produce the same aggregation as the batch path:
	// one template with one distinct clicker (u1).
	if len(got.TopClickedTemplates) != 1 {
		t.Fatalf("expected 1 template row via fallback, got %+v", got.TopClickedTemplates)
	}
	if got.TopClickedTemplates[0].ClickCount != 1 {
		t.Errorf("click_count = %d, want 1 (distinct clicker u1)", got.TopClickedTemplates[0].ClickCount)
	}
}
