package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

func mustES256Issuer(t *testing.T, kid string) (*privacy.JWTIssuer, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	iss, err := privacy.NewJWTIssuer(privacy.JWTConfig{
		SigningAlg: privacy.SigningAlgES256,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		KeyID:      kid,
		Issuer:     "sn360-test",
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTIssuer: %v", err)
	}
	return iss, priv
}

func mustHS256Issuer(t *testing.T) *privacy.JWTIssuer {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	iss, err := privacy.NewJWTIssuer(privacy.JWTConfig{
		Secret: secret,
		Issuer: "sn360-test",
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTIssuer: %v", err)
	}
	return iss
}

func TestJWKSHandler_ES256_ReturnsKey(t *testing.T) {
	iss, _ := mustES256Issuer(t, "k-abc")
	h := NewJWKSHandler(nil, iss)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/jwk-set+json" {
		t.Errorf("content-type = %q, want application/jwk-set+json", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("cache-control = %q, want public, max-age=300", got)
	}

	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("got %d keys, want 1; body=%v", len(body.Keys), body)
	}
	for _, field := range []string{"kty", "crv", "x", "y", "kid", "use", "alg"} {
		if _, ok := body.Keys[0][field]; !ok {
			t.Errorf("JWK missing field %q", field)
		}
	}
	if body.Keys[0]["kid"] != "k-abc" {
		t.Errorf("kid = %v, want k-abc", body.Keys[0]["kid"])
	}
}

func TestJWKSHandler_HS256Only_ReturnsEmptyKeys(t *testing.T) {
	iss := mustHS256Issuer(t)
	h := NewJWKSHandler(nil, iss)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Keys) != 0 {
		t.Errorf("HS256-only deployment published %d keys, want 0", len(body.Keys))
	}
}

func TestJWKSHandler_HEAD_NoBody(t *testing.T) {
	iss, _ := mustES256Issuer(t, "k-1")
	h := NewJWKSHandler(nil, iss)

	req := httptest.NewRequest(http.MethodHead, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	// httptest doesn't enforce HEAD-suppression at the transport
	// layer, so the recorder may capture whatever the handler wrote
	// to w. Our handler explicitly returns before encoding for HEAD,
	// so the body should be empty.
	if len(body) != 0 {
		t.Errorf("HEAD response body length = %d, want 0; body=%q", len(body), body)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/jwk-set+json" {
		t.Errorf("content-type = %q, want application/jwk-set+json (set even for HEAD)", got)
	}
}

func TestJWKSHandler_RejectsOtherMethods(t *testing.T) {
	iss, _ := mustES256Issuer(t, "k-1")
	h := NewJWKSHandler(nil, iss)

	for _, verb := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(verb, "/.well-known/jwks.json", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s status = %d, want 405", verb, rr.Code)
		}
		if got := rr.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s Allow header = %q, want GET, HEAD", verb, got)
		}
		// 405 body should be JSON, matching the package-wide
		// writeError envelope (banner_action.go). Pins
		// against any future regression that re-introduces
		// http.Error's text/plain default for this handler.
		if got := rr.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("%s Content-Type = %q, want application/json; charset=utf-8", verb, got)
		}
		if got := rr.Body.String(); got != "{\"error\":\"method not allowed\"}\n" {
			t.Errorf("%s body = %q, want {\"error\":\"method not allowed\"}", verb, got)
		}
	}
}
