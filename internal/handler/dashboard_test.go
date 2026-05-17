package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/dashboard"
)

// stubMetrics is a deterministic MetricsSource so the test exercises
// the handler's range/tenant validation and JSON shape without
// pulling in Postgres.
type stubMetrics struct {
	err      error
	emails   int
	tiers    []dto.TierCount
	cats     []dto.CategoryCount
	feedback dto.FeedbackStats
	quar     dto.QuarantineStats
	sim      dto.SimulationStats
	fp, fn   int
}

func (s *stubMetrics) EmailsProcessed(context.Context, string, dto.TimeRange) (int, error) {
	return s.emails, s.err
}
func (s *stubMetrics) ThreatsByTier(context.Context, string, dto.TimeRange) ([]dto.TierCount, error) {
	return s.tiers, s.err
}
func (s *stubMetrics) ThreatsByCategory(context.Context, string, dto.TimeRange) ([]dto.CategoryCount, error) {
	return s.cats, s.err
}
func (s *stubMetrics) Feedback(context.Context, string, dto.TimeRange) (dto.FeedbackStats, error) {
	return s.feedback, s.err
}
func (s *stubMetrics) Quarantine(context.Context, string, dto.TimeRange) (dto.QuarantineStats, error) {
	return s.quar, s.err
}
func (s *stubMetrics) Simulation(context.Context, string, dto.TimeRange) (dto.SimulationStats, error) {
	return s.sim, s.err
}
func (s *stubMetrics) FalseRates(context.Context, string, dto.TimeRange) (int, int, error) {
	return s.fp, s.fn, s.err
}

func newTestDashboard(t *testing.T, src dashboard.MetricsSource) *dashboard.DashboardGenerator {
	t.Helper()
	gen, err := dashboard.NewDashboardGenerator(dashboard.DashboardGeneratorConfig{
		Source: src,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:  func() time.Time { return time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	return gen
}

func TestDashboardHandler_ValidGet(t *testing.T) {
	src := &stubMetrics{
		emails: 100,
		tiers:  []dto.TierCount{{Tier: "Warning", Count: 5}},
		cats:   []dto.CategoryCount{{Category: "phishing", Count: 3}},
	}
	h := NewDashboardHandler(nil, newTestDashboard(t, src))
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/summary?tenant_id=acme&range=24h", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp dto.DashboardSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TenantID != "acme" || resp.EmailsProcessed != 100 || len(resp.ThreatsByTier) != 1 {
		t.Fatalf("unexpected: %+v", resp)
	}
	if got := resp.Range.End.Sub(resp.Range.Start); got != 24*time.Hour {
		t.Fatalf("range = %s, want 24h", got)
	}
}

func TestDashboardHandler_DefaultsToSevenDayRange(t *testing.T) {
	src := &stubMetrics{}
	h := NewDashboardHandler(nil, newTestDashboard(t, src))
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/summary?tenant_id=acme", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp dto.DashboardSummary
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if got := resp.Range.End.Sub(resp.Range.Start); got != 7*24*time.Hour {
		t.Fatalf("default range = %s, want 168h", got)
	}
}

func TestDashboardHandler_Rejections(t *testing.T) {
	gen := newTestDashboard(t, &stubMetrics{})
	h := NewDashboardHandler(nil, gen)

	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "wrong method", method: http.MethodPost, path: "/v1/dashboard/summary?tenant_id=acme", want: http.StatusMethodNotAllowed},
		{name: "missing tenant", method: http.MethodGet, path: "/v1/dashboard/summary", want: http.StatusBadRequest},
		{name: "invalid range unit", method: http.MethodGet, path: "/v1/dashboard/summary?tenant_id=acme&range=7q", want: http.StatusBadRequest},
		{name: "negative range", method: http.MethodGet, path: "/v1/dashboard/summary?tenant_id=acme&range=-1d", want: http.StatusBadRequest},
		{name: "garbage range", method: http.MethodGet, path: "/v1/dashboard/summary?tenant_id=acme&range=abc", want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestDashboardHandler_NilGenerator(t *testing.T) {
	h := NewDashboardHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/summary?tenant_id=acme", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not configured") {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestDashboardHandler_GeneratorError(t *testing.T) {
	src := &stubMetrics{err: errors.New("postgres down")}
	h := NewDashboardHandler(nil, newTestDashboard(t, src))
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/summary?tenant_id=acme&range=7d", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
}
