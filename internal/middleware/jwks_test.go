package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- test key / JWKS helpers ---------------------------------------

const (
	testIAMIssuer = "https://iam.example.com/"
	testECKid     = "ec-key-1"
	testRSAKid    = "rsa-key-1"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ecJWK renders an ECDSA public key as a JWK map.
func ecJWK(kid string, pub *ecdsa.PublicKey) map[string]any {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": kid,
		"use": "sig",
		"alg": "ES256",
		"x":   b64u(pub.X.FillBytes(make([]byte, byteLen))),
		"y":   b64u(pub.Y.FillBytes(make([]byte, byteLen))),
	}
}

// rsaJWK renders an RSA public key as a JWK map.
func rsaJWK(kid string, pub *rsa.PublicKey) map[string]any {
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   b64u(pub.N.Bytes()),
		"e":   b64u(eBytes),
	}
}

// jwksTestServer holds keys and an httptest server serving their JWKS.
type jwksTestServer struct {
	server *httptest.Server
	ecKey  *ecdsa.PrivateKey
	rsaKey *rsa.PrivateKey
	hits   int
}

func newJWKSTestServer(t *testing.T) *jwksTestServer {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ts := &jwksTestServer{ecKey: ecKey, rsaKey: rsaKey}
	ts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ts.hits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				ecJWK(testECKid, &ecKey.PublicKey),
				rsaJWK(testRSAKid, &rsaKey.PublicKey),
			},
		})
	}))
	t.Cleanup(ts.server.Close)
	return ts
}

// signECToken mints an ES256 token with the given claims and kid.
func (ts *jwksTestServer) signECToken(t *testing.T, claims jwt.Claims, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(ts.ecKey)
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}
	return s
}

// signRSAToken mints an RS256 token with the given claims and kid.
func (ts *jwksTestServer) signRSAToken(t *testing.T, claims jwt.Claims, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(ts.rsaKey)
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	return s
}

func iamClaims(tenantID string) iamCoreClaims {
	return iamCoreClaims{
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIAMIssuer,
			Subject:   "user-123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
}

// --- tests ---------------------------------------------------------

func TestJWKSVerifier_VerifiesES256AndRS256(t *testing.T) {
	ts := newJWKSTestServer(t)
	v, err := NewJWKSVerifier(JWKSVerifierConfig{JWKSURL: ts.server.URL, Issuer: testIAMIssuer})
	if err != nil {
		t.Fatalf("NewJWKSVerifier: %v", err)
	}

	ecTok := ts.signECToken(t, iamClaims("acme"), testECKid)
	if tid, err := v.Verify(context.Background(), ecTok); err != nil || tid != "acme" {
		t.Fatalf("ES256 verify: tid=%q err=%v", tid, err)
	}

	rsaTok := ts.signRSAToken(t, iamClaims("globex"), testRSAKid)
	if tid, err := v.Verify(context.Background(), rsaTok); err != nil || tid != "globex" {
		t.Fatalf("RS256 verify: tid=%q err=%v", tid, err)
	}

	// Second verify must hit the cache, not the network.
	if ts.hits != 1 {
		t.Errorf("JWKS endpoint hit %d times, want 1 (cached)", ts.hits)
	}
}

func TestJWKSVerifier_RejectsWrongIssuer(t *testing.T) {
	ts := newJWKSTestServer(t)
	v, _ := NewJWKSVerifier(JWKSVerifierConfig{JWKSURL: ts.server.URL, Issuer: testIAMIssuer})

	claims := iamClaims("acme")
	claims.Issuer = "https://evil.example.com/"
	tok := ts.signECToken(t, claims, testECKid)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection of token with wrong issuer")
	}
}

func TestJWKSVerifier_RejectsMissingTenant(t *testing.T) {
	ts := newJWKSTestServer(t)
	v, _ := NewJWKSVerifier(JWKSVerifierConfig{JWKSURL: ts.server.URL, Issuer: testIAMIssuer})

	tok := ts.signECToken(t, iamClaims(""), testECKid)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection of token missing tenant_id")
	}
}

func TestJWKSVerifier_RejectsUnknownKid(t *testing.T) {
	ts := newJWKSTestServer(t)
	v, _ := NewJWKSVerifier(JWKSVerifierConfig{JWKSURL: ts.server.URL, Issuer: testIAMIssuer})

	tok := ts.signECToken(t, iamClaims("acme"), "no-such-kid")
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection of token with unknown kid")
	}
}

// TestJWKSVerifier_RejectsAlgConfusion ensures a token forged with the
// HS256 (symmetric) algorithm cannot be validated using the published
// public key bytes as the HMAC secret.
func TestJWKSVerifier_RejectsAlgConfusion(t *testing.T) {
	ts := newJWKSTestServer(t)
	v, _ := NewJWKSVerifier(JWKSVerifierConfig{JWKSURL: ts.server.URL, Issuer: testIAMIssuer})

	// Forge an HS256 token signed with arbitrary bytes; the verifier
	// must refuse the symmetric algorithm outright.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, iamClaims("acme"))
	tok.Header["kid"] = testECKid
	forged, err := tok.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign HS256: %v", err)
	}
	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("expected rejection of HS256 (alg confusion) token")
	}
}

func TestJWKSVerifier_RefreshesOnRotatedKid(t *testing.T) {
	ec1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// The server starts serving only ec1, then rotates to ec2.
	current := ec1
	currentKid := "kid-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{ecJWK(currentKid, &current.PublicKey)},
		})
	}))
	defer srv.Close()

	v, _ := NewJWKSVerifier(JWKSVerifierConfig{
		JWKSURL:            srv.URL,
		Issuer:             testIAMIssuer,
		MinRefreshInterval: time.Nanosecond, // allow immediate reactive refresh
	})

	// Prime the cache with kid-1.
	tok1 := jwt.NewWithClaims(jwt.SigningMethodES256, iamClaims("acme"))
	tok1.Header["kid"] = "kid-1"
	s1, _ := tok1.SignedString(ec1)
	if _, err := v.Verify(context.Background(), s1); err != nil {
		t.Fatalf("verify kid-1: %v", err)
	}

	// Rotate the signing key on the server.
	current = ec2
	currentKid = "kid-2"
	tok2 := jwt.NewWithClaims(jwt.SigningMethodES256, iamClaims("acme"))
	tok2.Header["kid"] = "kid-2"
	s2, _ := tok2.SignedString(ec2)

	// Unknown kid-2 must trigger a reactive refresh and then succeed.
	if tid, err := v.Verify(context.Background(), s2); err != nil || tid != "acme" {
		t.Fatalf("verify rotated kid-2: tid=%q err=%v", tid, err)
	}
}

func TestNewJWKSVerifier_Validation(t *testing.T) {
	if _, err := NewJWKSVerifier(JWKSVerifierConfig{Issuer: "x"}); err == nil {
		t.Error("expected error when JWKSURL missing")
	}
	if _, err := NewJWKSVerifier(JWKSVerifierConfig{JWKSURL: "https://x"}); err == nil {
		t.Error("expected error when Issuer missing")
	}
}
