package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

func TestTelemetry_RecordsRequest(t *testing.T) {
	m := telemetry.NewMetrics(telemetry.MetricsConfig{})
	mw := NewTelemetry(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), TelemetryConfig{Metrics: m})
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	exposition := scrape(t, m)
	if !strings.Contains(exposition, `http_requests_total{`) {
		t.Fatalf("counter missing:\n%s", exposition)
	}
	if !strings.Contains(exposition, `http_request_latency_seconds_count`) {
		t.Fatalf("histogram missing:\n%s", exposition)
	}
	if !strings.Contains(exposition, `route="/v1/predict/open"`) {
		t.Fatalf("route label missing:\n%s", exposition)
	}
}

func TestTelemetry_NilMetricsPasses(t *testing.T) {
	called := false
	mw := NewTelemetry(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), TelemetryConfig{})
	mw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if !called {
		t.Fatal("inner handler must run even without metrics wired")
	}
}

// scrape returns the Prometheus exposition text for m's gatherer.
func scrape(t *testing.T, m *telemetry.Metrics) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.HTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape code=%d", rec.Code)
	}
	return rec.Body.String()
}
