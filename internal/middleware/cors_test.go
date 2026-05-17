package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/config"
)

func TestCORS_PreflightOK(t *testing.T) {
	called := false
	mw := NewCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
	}), CORSConfig{AllowedOrigins: []string{"https://app.sn360.io"}})
	req := httptest.NewRequest(http.MethodOptions, "/v1/predict/open", nil)
	req.Header.Set("Origin", "https://app.sn360.io")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code=%d", rec.Code)
	}
	if called {
		t.Fatal("preflight must not reach inner handler")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.sn360.io" {
		t.Fatalf("allow-origin=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("missing allow-methods")
	}
}

func TestCORS_AllowsListedOriginsOnly(t *testing.T) {
	mw := NewCORS(okHandler(), CORSConfig{AllowedOrigins: []string{"https://allowed.io"}})
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	req.Header.Set("Origin", "https://evil.io")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no allow-origin, got %q", got)
	}
}

func TestCORS_WildcardEchoesAnything(t *testing.T) {
	mw := NewCORS(okHandler(), CORSConfig{AllowedOrigins: []string{"*"}})
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	req.Header.Set("Origin", "https://random.io")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://random.io" {
		t.Fatalf("allow-origin=%q", got)
	}
}

func TestCORS_NoOriginNoEcho(t *testing.T) {
	mw := NewCORS(okHandler(), CORSConfig{AllowedOrigins: []string{"https://allowed.io"}})
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("allow-origin=%q (expected empty when no Origin header)", got)
	}
}

func TestCORS_MaxAgeHeader(t *testing.T) {
	mw := NewCORS(okHandler(), CORSConfig{
		AllowedOrigins: []string{"*"},
		MaxAge:         600,
	})
	req := httptest.NewRequest(http.MethodOptions, "/v1/predict/open", nil)
	req.Header.Set("Origin", "https://x.io")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "600" {
		t.Fatalf("max-age=%q", got)
	}
}

func TestCORS_FromConfigDevEchoesWildcard(t *testing.T) {
	cfg := config.Config{Environment: config.EnvironmentLocal}
	mw := NewCORSFromConfig(okHandler(), cfg, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	req.Header.Set("Origin", "https://localhost")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://localhost" {
		t.Fatalf("dev should echo origin, got %q", got)
	}
}

func TestCORS_FromConfigProdLocksDown(t *testing.T) {
	cfg := config.Config{Environment: config.EnvironmentProd}
	mw := NewCORSFromConfig(okHandler(), cfg, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	req.Header.Set("Origin", "https://attacker.io")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("prod must not echo unknown origins, got %q", got)
	}
}
