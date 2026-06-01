package handler

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// interstitialURLStore is an in-memory URLStore.
type interstitialURLStore struct {
	mu   sync.Mutex
	data map[string]string
}

func newInterstitialURLStore() *interstitialURLStore {
	return &interstitialURLStore{data: map[string]string{}}
}

func (s *interstitialURLStore) Set(_ context.Context, k, v string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[k] = v
	return nil
}

func (s *interstitialURLStore) Get(_ context.Context, k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[k]
	return v, ok, nil
}

// interstitialEncryptor is the same xor-based fake used by the
// quarantine handler test.
type interstitialEncryptor struct{}

func (interstitialEncryptor) Encrypt(_ context.Context, tenant string, plaintext []byte) ([]byte, error) {
	k := byte(0xa5)
	if len(tenant) > 0 {
		k ^= tenant[0]
	}
	out := make([]byte, len(plaintext))
	for i, b := range plaintext {
		out[i] = b ^ k
	}
	return out, nil
}

func (e interstitialEncryptor) Decrypt(ctx context.Context, tenant string, ct []byte) ([]byte, error) {
	return e.Encrypt(ctx, tenant, ct)
}

// stubThreatIntel always returns the configured verdict.
type stubThreatIntel struct {
	safe   bool
	reason string
}

func (s stubThreatIntel) CheckURL(_ context.Context, _ string) (bool, string) {
	return s.safe, s.reason
}

// stubClickLogger records every call so tests can assert it fires.
type stubClickLogger struct {
	mu    sync.Mutex
	calls []clickEntry
}

type clickEntry struct {
	tenant  string
	urlHash string
	verdict string
}

func (l *stubClickLogger) LogClick(_ context.Context, tenant, urlHash, verdict string, _ time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, clickEntry{tenant: tenant, urlHash: urlHash, verdict: verdict})
}

// interstitialFixture wires a URLRewriter + issuer + store so tests
// can mint real tokens via Rewrite() and then drive ServeHTTP.
type interstitialFixture struct {
	issuer   *privacy.JWTIssuer
	rewriter *action.URLRewriter
	store    *interstitialURLStore
}

func newInterstitialFixture(t *testing.T) *interstitialFixture {
	t.Helper()
	issuer, err := privacy.NewJWTIssuer(privacy.JWTConfig{
		Secret: bytes.Repeat([]byte{0xa1}, 32),
		Issuer: "sn360-es",
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	store := newInterstitialURLStore()
	rw, err := action.NewURLRewriter(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		issuer, store, interstitialEncryptor{},
		action.URLRewriterConfig{BaseURL: "https://l.test"},
	)
	if err != nil {
		t.Fatalf("rewriter: %v", err)
	}
	return &interstitialFixture{issuer: issuer, rewriter: rw, store: store}
}

// rewriteFor produces a valid token for the given URL by running a
// rewrite pass on a synthetic HTML body. The token is extracted from
// the rewritten body.
func (fx *interstitialFixture) rewriteFor(t *testing.T, original string) string {
	t.Helper()
	body := `<a href="` + original + `">click</a>`
	out, err := fx.rewriter.Rewrite(context.Background(), action.RewriteRequest{
		TenantID:             "acme",
		PseudonymizedMessage: "pmid-1",
		Tier:                 constant.TierHighRisk,
		HTMLBody:             body,
	})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	// The rewritten body now contains href="https://l.test/<token>".
	const prefix = `href="https://l.test/`
	idx := strings.Index(out.HTMLBody, prefix)
	if idx < 0 {
		t.Fatalf("no rewrite happened: %s", out.HTMLBody)
	}
	rest := out.HTMLBody[idx+len(prefix):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		t.Fatalf("unterminated href: %s", out.HTMLBody)
	}
	return rest[:end]
}

func TestInterstitialHandler_SafeURLRedirects(t *testing.T) {
	fx := newInterstitialFixture(t)
	clicks := &stubClickLogger{}
	h := NewInterstitialHandler(nil, fx.rewriter, stubThreatIntel{safe: true}, clicks, InterstitialConfig{})

	token := fx.rewriteFor(t, "https://example.com/legitimate")
	req := httptest.NewRequest(http.MethodGet, "/l/"+token, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "https://example.com/legitimate" {
		t.Fatalf("location=%q", got)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing no-store cache header")
	}
	if len(clicks.calls) != 1 || clicks.calls[0].verdict != "safe" {
		t.Fatalf("click log: %+v", clicks.calls)
	}
}

func TestInterstitialHandler_BlockedURLRendersBlockPage(t *testing.T) {
	fx := newInterstitialFixture(t)
	clicks := &stubClickLogger{}
	h := NewInterstitialHandler(nil, fx.rewriter,
		stubThreatIntel{safe: false, reason: "credential phishing"}, clicks, InterstitialConfig{})

	token := fx.rewriteFor(t, "https://malicious.example/login")
	req := httptest.NewRequest(http.MethodGet, "/l/"+token, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Link blocked by SN360") {
		t.Fatalf("body missing block page heading: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "credential phishing") {
		t.Fatalf("body missing reason: %s", rec.Body.String())
	}
	if len(clicks.calls) != 1 || clicks.calls[0].verdict != "blocked" {
		t.Fatalf("click log: %+v", clicks.calls)
	}
}

func TestInterstitialHandler_NilThreatIntelRedirects(t *testing.T) {
	fx := newInterstitialFixture(t)
	h := NewInterstitialHandler(nil, fx.rewriter, nil, nil, InterstitialConfig{})
	token := fx.rewriteFor(t, "https://example.com/no-intel")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l/"+token, nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestInterstitialHandler_MissingTokenRejected(t *testing.T) {
	fx := newInterstitialFixture(t)
	h := NewInterstitialHandler(nil, fx.rewriter, nil, nil, InterstitialConfig{})

	// Root path → extractToken returns "" → 400. The handler
	// distinguishes between "no token in the URL at all" (BadRequest)
	// and "token present but unverifiable" (block page).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestInterstitialHandler_InvalidTokenRendersBlock(t *testing.T) {
	fx := newInterstitialFixture(t)
	h := NewInterstitialHandler(nil, fx.rewriter, nil, nil, InterstitialConfig{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l/not-a-real-token", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "link_expired") {
		t.Fatalf("body missing link_expired code: %s", rec.Body.String())
	}
}

func TestInterstitialHandler_WrongMethod(t *testing.T) {
	fx := newInterstitialFixture(t)
	h := NewInterstitialHandler(nil, fx.rewriter, nil, nil, InterstitialConfig{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/l/abc", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}

// TestInterstitialHandler_SecurityHeaders pins the WS-7d defense-in-
// depth headers. They must be present on every response shape the
// handler can produce — success redirect, threat-intel block, expired/
// invalid token block, missing token 400, and method-not-allowed 405
// — so older / non-CSP-aware clients still get X-Frame-Options /
// nosniff on the error path.
func TestInterstitialHandler_SecurityHeaders(t *testing.T) {
	const (
		wantCSP  = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
		wantXFO  = "DENY"
		wantXCTO = "nosniff"
	)

	fx := newInterstitialFixture(t)
	safeToken := fx.rewriteFor(t, "https://example.com/safe")
	blockedToken := fx.rewriteFor(t, "https://malicious.example/login")
	qpToken := fx.rewriteFor(t, "https://example.com/qp")

	safeIntel := stubThreatIntel{safe: true}
	dangerIntel := stubThreatIntel{safe: false, reason: "credential phishing"}

	cases := []struct {
		name       string
		intel      ThreatIntel
		method     string
		target     string
		wantStatus int
	}{
		{
			name:       "safe_redirect",
			intel:      safeIntel,
			method:     http.MethodGet,
			target:     "/l/" + safeToken,
			wantStatus: http.StatusFound,
		},
		{
			name:       "threat_intel_block",
			intel:      dangerIntel,
			method:     http.MethodGet,
			target:     "/l/" + blockedToken,
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid_token_block",
			intel:      nil,
			method:     http.MethodGet,
			target:     "/l/not-a-real-token",
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing_token_bad_request",
			intel:      nil,
			method:     http.MethodGet,
			target:     "/",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "wrong_method",
			intel:      nil,
			method:     http.MethodPost,
			target:     "/l/abc",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "token_query_param_redirect",
			intel:      safeIntel,
			method:     http.MethodGet,
			target:     "/l?token=" + qpToken,
			wantStatus: http.StatusFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewInterstitialHandler(nil, fx.rewriter, tc.intel, nil, InterstitialConfig{})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Security-Policy"); got != wantCSP {
				t.Fatalf("CSP=%q want %q", got, wantCSP)
			}
			if got := rec.Header().Get("X-Frame-Options"); got != wantXFO {
				t.Fatalf("X-Frame-Options=%q want %q", got, wantXFO)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != wantXCTO {
				t.Fatalf("X-Content-Type-Options=%q want %q", got, wantXCTO)
			}
		})
	}
}

func TestInterstitialHandler_TokenQueryParamFallback(t *testing.T) {
	fx := newInterstitialFixture(t)
	h := NewInterstitialHandler(nil, fx.rewriter, stubThreatIntel{safe: true}, nil, InterstitialConfig{})
	token := fx.rewriteFor(t, "https://example.com/qp")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l?token="+token, nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
