package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// newTestIssuer constructs a JWTIssuer with a fixed 32-byte secret. The
// secret is shared with every test below so handlers issued in one
// test can be verified by another.
func newTestIssuer(t *testing.T) *privacy.JWTIssuer {
	t.Helper()
	iss, err := privacy.NewJWTIssuer(privacy.JWTConfig{
		Secret: bytes.Repeat([]byte("x"), 32),
		Issuer: "sn360-es",
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestJWTAuth_SkipsHealth(t *testing.T) {
	mw := NewJWTAuth(okHandler(), JWTAuthConfig{})
	for _, path := range []string{"/healthz", "/readyz", "/metrics", "/openapi.yaml"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("path=%s code=%d", path, rec.Code)
		}
	}
}

func TestJWTAuth_SkipsDocsPrefix(t *testing.T) {
	mw := NewJWTAuth(okHandler(), JWTAuthConfig{})
	for _, path := range []string{"/docs", "/docs/", "/docs/swagger.css"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("path=%s code=%d", path, rec.Code)
		}
	}
}

func TestJWTAuth_MissingTokenIs401(t *testing.T) {
	iss := newTestIssuer(t)
	mw := NewJWTAuth(okHandler(), JWTAuthConfig{Issuer: iss})
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestJWTAuth_InvalidTokenIs401(t *testing.T) {
	iss := newTestIssuer(t)
	mw := NewJWTAuth(okHandler(), JWTAuthConfig{Issuer: iss})
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestJWTAuth_ValidTokenPropagatesTenant(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.Issue("acme", "pmid-1", privacy.IssueOptions{})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	var seenTenant string
	var seenClaims *privacy.ActionClaims
	mw := NewJWTAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTenant = TenantIDFromContext(r.Context())
		seenClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}), JWTAuthConfig{Issuer: iss})
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	if seenTenant != "acme" {
		t.Fatalf("tenant=%q", seenTenant)
	}
	if seenClaims == nil || seenClaims.PseudonymizedMessage != "pmid-1" {
		t.Fatalf("claims=%+v", seenClaims)
	}
}

func TestJWTAuth_NoIssuerFailsClosed(t *testing.T) {
	mw := NewJWTAuth(okHandler(), JWTAuthConfig{})
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	req.Header.Set("Authorization", "Bearer something")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d (expected 401 when issuer missing)", rec.Code)
	}
}

func TestExtractBearer(t *testing.T) {
	cases := map[string]string{
		"":               "",
		"Bearer abc":     "abc",
		"bearer xyz":     "xyz",
		"Token abc":      "",
		"Bearer ":        "",
		"Bearer  spaced": "spaced",
	}
	for header, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		if got := extractBearer(req); got != want {
			t.Fatalf("header=%q got=%q want=%q", header, got, want)
		}
	}
}
