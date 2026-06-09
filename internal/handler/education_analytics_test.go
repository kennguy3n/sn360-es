package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/service/education"
)

func newTestAnalyticsService(t *testing.T) (*education.AnalyticsService, *education.MemoryCampaignStore, *education.MemoryInteractionStore) {
	t.Helper()
	templates, err := education.LoadDefaultTemplates()
	if err != nil {
		t.Fatalf("LoadDefaultTemplates: %v", err)
	}
	campaigns := education.NewMemoryCampaignStore()
	interactions := education.NewMemoryInteractionStore()
	scorer := education.NewResilienceScorer(education.ResilienceScorerConfig{})
	svc, err := education.NewAnalyticsService(education.AnalyticsConfig{
		Campaigns:    campaigns,
		Interactions: interactions,
		Templates:    templates,
		Scorer:       scorer,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewAnalyticsService: %v", err)
	}
	return svc, campaigns, interactions
}

func newAnalyticsHandler(t *testing.T, svc *education.AnalyticsService) *EducationAnalyticsHandler {
	t.Helper()
	return NewEducationAnalyticsHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), svc)
}

func TestEducationAnalytics_MethodNotAllowed(t *testing.T) {
	svc, _, _ := newTestAnalyticsService(t)
	h := newAnalyticsHandler(t, svc)
	req := httptest.NewRequest(http.MethodPost, "/v1/education/analytics?tenant_id=t1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestEducationAnalytics_ServiceUnavailable(t *testing.T) {
	h := newAnalyticsHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/education/analytics?tenant_id=t1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestEducationAnalytics_MissingTenant(t *testing.T) {
	svc, _, _ := newTestAnalyticsService(t)
	h := newAnalyticsHandler(t, svc)
	req := httptest.NewRequest(http.MethodGet, "/v1/education/analytics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestEducationAnalytics_InvalidRange(t *testing.T) {
	svc, _, _ := newTestAnalyticsService(t)
	h := newAnalyticsHandler(t, svc)
	req := httptest.NewRequest(http.MethodGet, "/v1/education/analytics?tenant_id=t1&range=bogus", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestEducationAnalytics_TenantMismatch(t *testing.T) {
	svc, _, _ := newTestAnalyticsService(t)
	h := newAnalyticsHandler(t, svc)
	// Bound tenant t1 (from JWT), but query asks for t2 -> 403.
	ctx := middleware.ContextWithTenantID(context.Background(), "t1")
	req := httptest.NewRequest(http.MethodGet, "/v1/education/analytics?tenant_id=t2", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestEducationAnalytics_BoundTenantWins(t *testing.T) {
	svc, campaigns, interactions := newTestAnalyticsService(t)
	now := time.Now().UTC()
	created := now.Add(-5 * 24 * time.Hour)
	// Data belongs to t1.
	_ = campaigns.SaveCampaign(context.Background(), dto.Campaign{
		CampaignID: "c1", TenantID: "t1", TemplateID: "bec.easy.ceo_gift_card",
		Difficulty: dto.DifficultyEasy, CreatedAt: created, TargetCount: 2,
	})
	_ = interactions.Append(context.Background(), dto.UserInteraction{
		CampaignID: "c1", UserHash: "u1", Action: dto.InteractionClickedLink, OccurredAt: created,
	})

	h := newAnalyticsHandler(t, svc)
	// No query tenant_id, but JWT-bound tenant is t1.
	ctx := middleware.ContextWithTenantID(context.Background(), "t1")
	req := httptest.NewRequest(http.MethodGet, "/v1/education/analytics", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got dto.EducationAnalytics
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TenantID != "t1" {
		t.Errorf("tenant_id = %q, want t1", got.TenantID)
	}
	if len(got.TopClickedTemplates) != 1 {
		t.Errorf("top clicked = %+v", got.TopClickedTemplates)
	}
}

func TestEducationAnalytics_HappyPathShape(t *testing.T) {
	svc, campaigns, interactions := newTestAnalyticsService(t)
	now := time.Now().UTC()
	created := now.Add(-7 * 24 * time.Hour)
	_ = campaigns.SaveCampaign(context.Background(), dto.Campaign{
		CampaignID: "c1", TenantID: "t1", TemplateID: "hipaa.easy.phi_email",
		Difficulty: dto.DifficultyEasy, CreatedAt: created, TargetCount: 2,
	})
	for _, u := range []string{"u1", "u2"} {
		_ = interactions.Append(context.Background(), dto.UserInteraction{
			CampaignID: "c1", UserHash: u, Action: dto.InteractionDelivered, OccurredAt: created,
		})
	}
	_ = interactions.Append(context.Background(), dto.UserInteraction{
		CampaignID: "c1", UserHash: "u1", Action: dto.InteractionReportedPhishing, OccurredAt: created.Add(time.Hour),
	})

	h := newAnalyticsHandler(t, svc)
	req := httptest.NewRequest(http.MethodGet, "/v1/education/analytics?tenant_id=t1&range=90d", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}
	var got dto.EducationAnalytics
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Regulatory map must always carry all three regimes.
	for _, cat := range dto.AllRegulatoryCategories {
		if _, ok := got.RegulatoryCompletion[string(cat)]; !ok {
			t.Errorf("missing regulatory regime %q", cat)
		}
	}
	if got.RegulatoryCompletion["hipaa"] != 0.5 {
		t.Errorf("hipaa completion = %v, want 0.5", got.RegulatoryCompletion["hipaa"])
	}
}
