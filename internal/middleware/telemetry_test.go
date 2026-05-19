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

func TestNormaliseRoute(t *testing.T) {
	patterns := []RoutePattern{
		{Prefix: "/v1/escalation/", Label: "/v1/escalation/:id"},
		{Prefix: "/l/", Label: "/l/:token"},
	}
	cases := []struct {
		name        string
		path        string
		wantLabel   string
		wantMatched bool
	}{
		// Prefix match collapses arbitrary suffix.
		{"escalation id", "/v1/escalation/abc123", "/v1/escalation/:id", true},
		// Bare-prefix-without-trailing-slash form ("/l") also matches
		// the "/l/" prefix so callers can hit either form without
		// blowing up cardinality.
		{"bare prefix without slash", "/l", "/l/:token", true},
		{"l token", "/l/sometoken", "/l/:token", true},
		// Non-matching path is passed through verbatim with matched=false.
		{"no match", "/v1/predict/open", "/v1/predict/open", false},
		// Critically: a path that LOOKS LIKE one of the prefixes but
		// extends past the slash boundary must NOT collide (`/longer`
		// is not the `/l/` prefix family).
		{"prefix bleed guard", "/longer-path", "/longer-path", false},
		// Empty patterns slice never matches.
		{"empty patterns", "/v1/anything", "/v1/anything", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			label, matched := NormaliseRoute(patterns, tc.path)
			if label != tc.wantLabel || matched != tc.wantMatched {
				t.Fatalf("NormaliseRoute(%q) = (%q, %v); want (%q, %v)",
					tc.path, label, matched, tc.wantLabel, tc.wantMatched)
			}
		})
	}

	// Empty-patterns slice still returns matched=false consistently.
	if label, matched := NormaliseRoute(nil, "/x"); label != "/x" || matched {
		t.Fatalf("nil patterns: got (%q, %v); want (\"/x\", false)", label, matched)
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
