package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- Test helpers ------------------------------------------------------

// newTestRSAKey returns a fresh 2048-bit RSA key for tests. We avoid
// committing a fixture key so tooling that warns about leaked private
// keys in the repo stays happy.
func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

// newJWKSServer stands in for Google's certs endpoint, returning the
// supplied public key under the supplied kid. Atomic counters let
// tests assert how often the verifier hit the endpoint (cache
// behaviour).
func newJWKSServer(t *testing.T, kid string, pub *rsa.PublicKey, hits *int64) *httptest.Server {
	t.Helper()
	jwk := GoogleJWK{
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			atomic.AddInt64(hits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(GoogleJWKS{Keys: []GoogleJWK{jwk}})
	}))
}

// signedGoogleToken returns an RS256 JWT for the test issuer / audience.
func signedGoogleToken(t *testing.T, key *rsa.PrivateKey, kid, iss, aud string, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   iss,
		"aud":   aud,
		"sub":   "1234567890",
		"email": "pubsub@gcp.iam.gserviceaccount.com",
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"exp":   exp.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func newTestPushHandler(verifier PushSignatureVerifier) *PushWebhookHandler {
	return &PushWebhookHandler{
		Manager:           nil,
		Logger:            slog.New(slog.NewJSONHandler(io.Discard, nil)),
		SignatureVerifier: verifier,
	}
}

// --- validationToken echo ----------------------------------------------

// TestPushWebhook_ValidationTokenEchoedVerbatim pins the Microsoft
// Graph protocol contract: the validationToken query parameter must
// be reflected byte-for-byte in the response body. Microsoft compares
// the echoed value against what it sent and rejects subscription
// creation on any mismatch — so even an "innocent" HTML escape that
// turns "&" into "&amp;" breaks validation.
//
// Defense-in-depth against a browser rendering the body as HTML is
// asserted at the response-header layer (Content-Type: text/plain;
// charset=utf-8 + X-Content-Type-Options: nosniff), not by mutating
// the body.
func TestPushWebhook_ValidationTokenEchoedVerbatim(t *testing.T) {
	// The handler must short-circuit before signature verification
	// on the validation request, so wire an always-reject verifier
	// to prove the validation-token branch runs first.
	h := newTestPushHandler(rejectVerifier{})

	// Microsoft's real tokens are URL-safe base64-ish, but the
	// protocol does not constrain the character set. Use a value
	// that contains every HTML metacharacter (<, >, &, ", ') to
	// guarantee a regression would re-introduce escaping.
	const token = "<script>alert('xss')</script>&\"'"

	req := httptest.NewRequest(http.MethodPost,
		"/v1/push/outlook/tenantA?validationToken=anything", nil)
	req.URL.RawQuery = "validationToken=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E%26%22%27"

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("content-type=%q, want text/plain prefix", got)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options=%q, want nosniff", got)
	}
	if got := rr.Body.String(); got != token {
		t.Fatalf("body=%q, want %q (validationToken must be echoed verbatim per Microsoft Graph)", got, token)
	}
}

// --- Microsoft clientState verifier ------------------------------------

func TestMicrosoftClientStateVerifier_AcceptsMatchingState(t *testing.T) {
	v := &MicrosoftClientStateVerifier{
		ExpectedFor: func(tenantID string) string { return "sn360-es-" + tenantID },
	}
	body := []byte(`{"value":[{"clientState":"sn360-es-acme"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/push/outlook/acme", nil)
	if err := v.VerifyPush(context.Background(), "outlook", "acme", req, body); err != nil {
		t.Fatalf("VerifyPush: %v", err)
	}
}

func TestMicrosoftClientStateVerifier_RejectsMismatch(t *testing.T) {
	v := &MicrosoftClientStateVerifier{
		ExpectedFor: func(tenantID string) string { return "sn360-es-" + tenantID },
	}
	body := []byte(`{"value":[{"clientState":"attacker-supplied"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/push/outlook/acme", nil)
	err := v.VerifyPush(context.Background(), "outlook", "acme", req, body)
	if !errors.Is(err, ErrPushAuthInvalid) {
		t.Fatalf("err=%v, want ErrPushAuthInvalid", err)
	}
}

func TestMicrosoftClientStateVerifier_RejectsEmptyBatch(t *testing.T) {
	v := &MicrosoftClientStateVerifier{
		ExpectedFor: func(tenantID string) string { return "sn360-es-" + tenantID },
	}
	body := []byte(`{"value":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/push/outlook/acme", nil)
	err := v.VerifyPush(context.Background(), "outlook", "acme", req, body)
	if !errors.Is(err, ErrPushAuthMissing) {
		t.Fatalf("err=%v, want ErrPushAuthMissing", err)
	}
}

func TestMicrosoftClientStateVerifier_RejectsUnknownTenant(t *testing.T) {
	v := &MicrosoftClientStateVerifier{
		ExpectedFor: func(tenantID string) string { return "" },
	}
	body := []byte(`{"value":[{"clientState":"anything"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/push/outlook/ghost", nil)
	err := v.VerifyPush(context.Background(), "outlook", "ghost", req, body)
	if !errors.Is(err, ErrPushAuthMissing) {
		t.Fatalf("err=%v, want ErrPushAuthMissing", err)
	}
}

// --- Google OIDC verifier ----------------------------------------------

func TestGoogleOIDCVerifier_AcceptsValidToken(t *testing.T) {
	key := newTestRSAKey(t)
	const kid = "test-kid-1"
	var hits int64
	srv := newJWKSServer(t, kid, &key.PublicKey, &hits)
	defer srv.Close()

	v := &GoogleOIDCVerifier{
		Audience: "https://api.sn360.example.com/v1/push/gmail",
		Issuer:   "https://accounts.google.com",
		JWKSURL:  srv.URL,
		Now:      time.Now,
	}
	tok := signedGoogleToken(t, key, kid, v.Issuer, v.Audience, time.Now().Add(5*time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/v1/push/gmail/acme", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if err := v.VerifyPush(context.Background(), "gmail", "acme", req, nil); err != nil {
		t.Fatalf("VerifyPush: %v", err)
	}

	// A second verification should hit the JWKS cache (not the
	// upstream server) because the cache is still fresh.
	if err := v.VerifyPush(context.Background(), "gmail", "acme", req, nil); err != nil {
		t.Fatalf("VerifyPush (cached): %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("JWKS hits=%d, want 1 (cache should absorb the second call)", got)
	}
}

func TestGoogleOIDCVerifier_RejectsExpiredToken(t *testing.T) {
	key := newTestRSAKey(t)
	const kid = "test-kid-2"
	srv := newJWKSServer(t, kid, &key.PublicKey, nil)
	defer srv.Close()

	v := &GoogleOIDCVerifier{
		Audience: "aud-x",
		JWKSURL:  srv.URL,
		Now:      time.Now,
	}
	tok := signedGoogleToken(t, key, kid, "https://accounts.google.com", v.Audience,
		time.Now().Add(-1*time.Minute)) // already expired

	req := httptest.NewRequest(http.MethodPost, "/v1/push/gmail/acme", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	err := v.VerifyPush(context.Background(), "gmail", "acme", req, nil)
	if !errors.Is(err, ErrPushAuthInvalid) {
		t.Fatalf("err=%v, want ErrPushAuthInvalid for expired token", err)
	}
}

func TestGoogleOIDCVerifier_RejectsWrongAudience(t *testing.T) {
	key := newTestRSAKey(t)
	const kid = "test-kid-3"
	srv := newJWKSServer(t, kid, &key.PublicKey, nil)
	defer srv.Close()

	v := &GoogleOIDCVerifier{
		Audience: "aud-expected",
		JWKSURL:  srv.URL,
		Now:      time.Now,
	}
	tok := signedGoogleToken(t, key, kid, "https://accounts.google.com", "aud-other",
		time.Now().Add(5*time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/v1/push/gmail/acme", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	err := v.VerifyPush(context.Background(), "gmail", "acme", req, nil)
	if !errors.Is(err, ErrPushAuthInvalid) {
		t.Fatalf("err=%v, want ErrPushAuthInvalid for wrong audience", err)
	}
}

func TestGoogleOIDCVerifier_RejectsMissingAuthorization(t *testing.T) {
	v := &GoogleOIDCVerifier{
		Audience: "any",
		JWKSURL:  "http://127.0.0.1:0", // never reached
		Now:      time.Now,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/push/gmail/acme", nil)
	err := v.VerifyPush(context.Background(), "gmail", "acme", req, nil)
	if !errors.Is(err, ErrPushAuthMissing) {
		t.Fatalf("err=%v, want ErrPushAuthMissing for missing Authorization", err)
	}
}

func TestGoogleOIDCVerifier_RejectsWrongSigningKey(t *testing.T) {
	jwksKey := newTestRSAKey(t)
	attackerKey := newTestRSAKey(t)
	const kid = "test-kid-4"
	srv := newJWKSServer(t, kid, &jwksKey.PublicKey, nil)
	defer srv.Close()

	v := &GoogleOIDCVerifier{
		Audience: "aud-x",
		JWKSURL:  srv.URL,
		Now:      time.Now,
	}
	// Sign with attackerKey but claim kid=jwksKey's kid.
	tok := signedGoogleToken(t, attackerKey, kid, "https://accounts.google.com", v.Audience,
		time.Now().Add(5*time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/v1/push/gmail/acme", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	err := v.VerifyPush(context.Background(), "gmail", "acme", req, nil)
	if !errors.Is(err, ErrPushAuthInvalid) {
		t.Fatalf("err=%v, want ErrPushAuthInvalid for wrong signing key", err)
	}
}

func TestGoogleOIDCVerifier_RejectsUnknownKid(t *testing.T) {
	key := newTestRSAKey(t)
	const realKid = "test-kid-5"
	srv := newJWKSServer(t, realKid, &key.PublicKey, nil)
	defer srv.Close()

	v := &GoogleOIDCVerifier{
		Audience: "aud-x",
		JWKSURL:  srv.URL,
		Now:      time.Now,
	}
	tok := signedGoogleToken(t, key, "ghost-kid", "https://accounts.google.com", v.Audience,
		time.Now().Add(5*time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/v1/push/gmail/acme", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	err := v.VerifyPush(context.Background(), "gmail", "acme", req, nil)
	if !errors.Is(err, ErrPushAuthInvalid) {
		t.Fatalf("err=%v, want ErrPushAuthInvalid for unknown kid", err)
	}
}

// --- Handler-level integration -----------------------------------------

func TestPushWebhook_RejectsUnauthenticatedCalls(t *testing.T) {
	h := newTestPushHandler(rejectVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/v1/push/outlook/acme",
		strings.NewReader(`{"value":[{"clientState":"anything"}]}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rr.Code)
	}
}

func TestPushWebhook_FailsClosedWithoutVerifier(t *testing.T) {
	h := newTestPushHandler(nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/push/outlook/acme",
		strings.NewReader(`{"value":[]}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500 (closed-by-default)", rr.Code)
	}
}

func TestPushSignatureRouter_DispatchesByProvider(t *testing.T) {
	// The router keys match the canonical [PushReceiver.Kind] strings
	// returned by [internal/service/ingestion.GmailPushReceiver]
	// ("gmail") and [internal/service/ingestion.OutlookPushReceiver]
	// ("outlook"). Mixed-case input on the first call exercises the
	// lower-casing dispatch in [PushSignatureRouter.VerifyPush] so a
	// future regression that drops normalization fails this test.
	called := map[string]int{}
	router := &PushSignatureRouter{
		Verifiers: map[string]PushSignatureVerifier{
			"gmail":   acceptVerifier{name: "gmail", calls: called},
			"outlook": acceptVerifier{name: "outlook", calls: called},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := router.VerifyPush(context.Background(), "GMAIL", "t1", req, nil); err != nil {
		t.Fatalf("VerifyPush gmail: %v", err)
	}
	if err := router.VerifyPush(context.Background(), "outlook", "t2", req, nil); err != nil {
		t.Fatalf("VerifyPush outlook: %v", err)
	}
	err := router.VerifyPush(context.Background(), "unknown", "t3", req, nil)
	if !errors.Is(err, ErrPushProviderUnknown) {
		t.Fatalf("err=%v, want ErrPushProviderUnknown", err)
	}
	if called["gmail"] != 1 || called["outlook"] != 1 {
		t.Fatalf("dispatch counts wrong: %+v", called)
	}
}

// --- Fakes -------------------------------------------------------------

type rejectVerifier struct{}

func (rejectVerifier) VerifyPush(_ context.Context, _ string, _ string, _ *http.Request, _ []byte) error {
	return ErrPushAuthInvalid
}

type acceptVerifier struct {
	name  string
	calls map[string]int
}

func (a acceptVerifier) VerifyPush(_ context.Context, _ string, _ string, _ *http.Request, _ []byte) error {
	if a.calls != nil {
		a.calls[a.name]++
	}
	return nil
}
