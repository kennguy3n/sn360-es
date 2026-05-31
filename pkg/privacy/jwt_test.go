package privacy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mustIssuer(t *testing.T, ttl time.Duration) *JWTIssuer {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	iss, err := NewJWTIssuer(JWTConfig{Secret: secret, Issuer: "sn360-test", TTL: ttl})
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	return iss
}

func TestJWTIssuerRejectsShortSecret(t *testing.T) {
	_, err := NewJWTIssuer(JWTConfig{Secret: []byte("short")})
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestJWTIssueAndVerifyRoundTrip(t *testing.T) {
	iss := mustIssuer(t, time.Hour)
	tok, err := iss.Issue("tenant-1", "msg-abc", IssueOptions{
		Tier:    "HighRisk",
		Action:  "report_phishing",
		URLHash: "deadbeef",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tok == "" {
		t.Fatal("token is empty")
	}
	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.TenantID != "tenant-1" {
		t.Errorf("tid = %s, want tenant-1", claims.TenantID)
	}
	if claims.PseudonymizedMessage != "msg-abc" {
		t.Errorf("pmid = %s, want msg-abc", claims.PseudonymizedMessage)
	}
	if claims.Tier != "HighRisk" {
		t.Errorf("tier = %s, want HighRisk", claims.Tier)
	}
	if claims.Action != "report_phishing" {
		t.Errorf("act = %s, want report_phishing", claims.Action)
	}
	if claims.OriginalURLHash != "deadbeef" {
		t.Errorf("urlh = %s, want deadbeef", claims.OriginalURLHash)
	}
}

// TestJWTIssueAndVerifyStampsRole pins the round-trip of the new
// role claim added for the RBAC layer. Without this, a regression on
// the `json:"role,omitempty"` tag (or the IssueOptions.Role wiring)
// would silently strip the claim on the wire and middleware.RequireRole
// would 403 every previously-valid admin/operator token in production.
func TestJWTIssueAndVerifyStampsRole(t *testing.T) {
	iss := mustIssuer(t, time.Hour)
	for _, role := range []string{RoleAdmin, RoleOperator, RoleViewer, RoleEndUser} {
		tok, err := iss.Issue("tenant-1", "msg-abc", IssueOptions{Role: role})
		if err != nil {
			t.Fatalf("issue(role=%s): %v", role, err)
		}
		claims, err := iss.Verify(tok)
		if err != nil {
			t.Fatalf("verify(role=%s): %v", role, err)
		}
		if claims.Role != role {
			t.Errorf("role round-trip: got %q want %q", claims.Role, role)
		}
	}
}

// TestIsValidRole pins the closed allowlist. If a future contributor
// adds a fifth Role* constant without extending validRoles, the new
// role will silently 403 against every RequireRole gate — this test
// surfaces that mismatch at build time.
func TestIsValidRole(t *testing.T) {
	cases := map[string]bool{
		RoleAdmin:    true,
		RoleOperator: true,
		RoleViewer:   true,
		RoleEndUser:  true,
		"":           false,
		"root":       false,
		"superuser":  false,
		// Common typos that have historically slipped past code
		// review on this pattern:
		"end-user": false,
		"enduser":  false,
		"Admin":    false, // case-sensitive
	}
	for r, want := range cases {
		if got := IsValidRole(r); got != want {
			t.Errorf("IsValidRole(%q) = %v, want %v", r, got, want)
		}
	}
}

// TestJWTIssueRejectsInvalidRole pins the issuance-time validation
// added in response to PR #51 Devin Review finding 0004. A typo'd
// role constant (e.g. "adim" instead of "admin") must fail at the
// Issue() call site, not later as a silent 403 against the RBAC
// gate — that mismatch would burn an unbounded amount of debug
// time before someone thinks to inspect the actual `role` claim
// on the token. Empty string stays permitted (covered below).
func TestJWTIssueRejectsInvalidRole(t *testing.T) {
	iss := mustIssuer(t, time.Hour)
	for _, bad := range []string{"adim", "Administrator", "root", "end-user", "ADMIN"} {
		if _, err := iss.Issue("t", "msg", IssueOptions{Role: bad}); err == nil {
			t.Errorf("expected error issuing with invalid role %q", bad)
		}
	}
	// Empty role must still be accepted — see IssueOptions.Role
	// docstring. Tests, transitional callers, and token classes
	// that intentionally carry no role rely on this.
	if _, err := iss.Issue("t", "msg", IssueOptions{Role: ""}); err != nil {
		t.Errorf("empty role rejected: %v (must be permitted)", err)
	}
}

func TestJWTIssueRequiresArgs(t *testing.T) {
	iss := mustIssuer(t, time.Hour)
	if _, err := iss.Issue("", "msg", IssueOptions{}); err == nil {
		t.Error("expected error when tenant_id missing")
	}
	if _, err := iss.Issue("t", "", IssueOptions{}); err == nil {
		t.Error("expected error when pseudoMessageID missing")
	}
}

func TestJWTVerifyRejectsTamperedSecret(t *testing.T) {
	issA := mustIssuer(t, time.Hour)
	issB := mustIssuer(t, time.Hour)
	tok, err := issA.Issue("t", "m", IssueOptions{})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := issB.Verify(tok); err == nil {
		t.Error("token signed by A should not verify under B's secret")
	}
}

func TestJWTVerifyRejectsExpiredToken(t *testing.T) {
	// Issue with the smallest positive TTL the issuer accepts (any
	// non-positive value is auto-corrected to the default 7-day TTL).
	iss := mustIssuer(t, time.Nanosecond)
	tok, err := iss.Issue("t", "m", IssueOptions{TTL: time.Nanosecond})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Wait long enough for the token to land outside any reasonable
	// clock-skew leeway.
	time.Sleep(50 * time.Millisecond)
	if _, err := iss.Verify(tok); err == nil {
		t.Error("expired token must not verify")
	}
}

func TestJWTVerifyRejectsEmptyToken(t *testing.T) {
	iss := mustIssuer(t, time.Hour)
	if _, err := iss.Verify(""); err == nil {
		t.Error("empty token must fail")
	}
}

func TestJWTVerifyEnforcesIssuer(t *testing.T) {
	iss := mustIssuer(t, time.Hour)
	tok, err := iss.Issue("t", "m", IssueOptions{})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Another issuer with the same secret but a different `iss` claim
	// must reject the token.
	other := &JWTIssuer{
		signingAlg: SigningAlgHS256,
		secret:     iss.secret,
		issuer:     "different-issuer",
		ttl:        time.Hour,
	}
	if _, err := other.Verify(tok); err == nil {
		t.Error("token should not verify under a different issuer string")
	}
}

// mustES256Issuer builds an ES256 issuer with a fresh P-256 keypair.
// Used by the ES256 round-trip and dual-verify tests below.
func mustES256Issuer(t *testing.T, ttl time.Duration, kid string) (*JWTIssuer, *ecdsa.PrivateKey) {
	t.Helper()
	priv := mustGenerateP256(t)
	iss, err := NewJWTIssuer(JWTConfig{
		SigningAlg: SigningAlgES256,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		KeyID:      kid,
		Issuer:     "sn360-test",
		TTL:        ttl,
	})
	if err != nil {
		t.Fatalf("NewJWTIssuer(ES256): %v", err)
	}
	return iss, priv
}

// TestJWTES256RoundTrip exercises the new ES256 signing path. The
// token must verify under the corresponding public key AND must carry
// the kid header so a JWKS-pinning consumer can find the right key.
func TestJWTES256RoundTrip(t *testing.T) {
	iss, _ := mustES256Issuer(t, time.Hour, "k-1")
	tok, err := iss.Issue("tenant-1", "msg-abc", IssueOptions{
		Role:    RoleAdmin,
		Tier:    "HighRisk",
		Action:  "report_phishing",
		URLHash: "deadbeef",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The JWS header must declare alg=ES256 and kid=k-1 so downstream
	// JWKS-based verifiers can pick the right key. We parse the
	// header without verifying so the assertion does not depend on the
	// verify path being correct.
	parser := jwt.NewParser()
	parts, _, err := parser.ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("unverified parse: %v", err)
	}
	if got := parts.Method.Alg(); got != "ES256" {
		t.Errorf("alg = %q, want ES256", got)
	}
	if got := parts.Header["kid"]; got != "k-1" {
		t.Errorf("kid = %v, want k-1", got)
	}

	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.TenantID != "tenant-1" {
		t.Errorf("tid = %s, want tenant-1", claims.TenantID)
	}
	if claims.Role != RoleAdmin {
		t.Errorf("role = %s, want %s", claims.Role, RoleAdmin)
	}
}

// TestJWTES256RejectsMismatchedKey pins the negative-path: an ES256
// token signed by issuer A must not verify under issuer B with an
// unrelated keypair.
func TestJWTES256RejectsMismatchedKey(t *testing.T) {
	issA, _ := mustES256Issuer(t, time.Hour, "a")
	issB, _ := mustES256Issuer(t, time.Hour, "b")
	tok, err := issA.Issue("t", "m", IssueOptions{})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := issB.Verify(tok); err == nil {
		t.Error("token signed by A's private key should not verify under B's public key")
	}
}

// TestJWTES256RequiresKey pins the boot-time guard that NewJWTIssuer
// fails closed when ES256 is selected without a keypair.
func TestJWTES256RequiresKey(t *testing.T) {
	priv := mustGenerateP256(t)
	if _, err := NewJWTIssuer(JWTConfig{SigningAlg: SigningAlgES256}); err == nil {
		t.Error("expected error with neither key configured")
	}
	if _, err := NewJWTIssuer(JWTConfig{SigningAlg: SigningAlgES256, PrivateKey: priv}); err == nil {
		t.Error("expected error with only private key configured")
	}
	if _, err := NewJWTIssuer(JWTConfig{SigningAlg: SigningAlgES256, PublicKey: &priv.PublicKey}); err == nil {
		t.Error("expected error with only public key configured")
	}
}

// TestJWTRejectsUnknownAlg pins the boot-time guard that
// NewJWTIssuer rejects an algorithm string that is not HS256 / ES256.
func TestJWTRejectsUnknownAlg(t *testing.T) {
	if _, err := NewJWTIssuer(JWTConfig{SigningAlg: "RS512", Secret: make([]byte, 32)}); err == nil {
		t.Error("expected error for unknown alg")
	}
}

// TestJWTES256RejectsShortDualVerifySecret pins the closed-by-default
// behavior for the dual-verify migration path. When the operator
// selects ES256 issuance AND supplies an HS256 secret for in-flight
// token verification, the secret must still meet the >=32 byte
// minimum or the issuer refuses to construct. Without this guard a
// short BANNER_TOKEN_SECRET would silently weaken HS256 verification:
// the issuer would sign ES256 but accept forged HS256 tokens minted
// against a trivially brute-forceable HMAC key.
func TestJWTES256RejectsShortDualVerifySecret(t *testing.T) {
	priv := mustGenerateP256(t)
	short := []byte("too-short")
	if len(short) >= 32 {
		t.Fatalf("test setup error: short secret unexpectedly long (%d)", len(short))
	}
	_, err := NewJWTIssuer(JWTConfig{
		SigningAlg: SigningAlgES256,
		Secret:     short,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Issuer:     "sn360-test",
		TTL:        time.Hour,
	})
	if err == nil {
		t.Fatal("expected ES256 + short dual-verify secret to be rejected")
	}
}

// TestJWTHS256RejectsEmptySecret pins the parallel boot-time check
// for the primary HS256 issuance path: an empty Secret is rejected
// even though the new "len(Secret) > 0" guard above only fires for
// short-but-present secrets.
func TestJWTHS256RejectsEmptySecret(t *testing.T) {
	if _, err := NewJWTIssuer(JWTConfig{SigningAlg: SigningAlgHS256}); err == nil {
		t.Fatal("expected HS256 with empty secret to be rejected")
	}
}

// TestJWTDualVerifyHS256AndES256 pins the migration story: an issuer
// configured with both an HS256 secret and an ES256 public key must
// verify a token signed under either algorithm. This is what lets a
// deployment add ES256 without a flag-day cutover — ES256 tokens flow
// while in-flight HS256 tokens still verify until their TTL expires.
func TestJWTDualVerifyHS256AndES256(t *testing.T) {
	priv := mustGenerateP256(t)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Issuer A signs HS256 with the shared secret.
	hsIss, err := NewJWTIssuer(JWTConfig{
		SigningAlg: SigningAlgHS256,
		Secret:     secret,
		Issuer:     "sn360-test",
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("HS256 issuer: %v", err)
	}

	// Issuer B signs ES256 with the asymmetric key.
	esIss, err := NewJWTIssuer(JWTConfig{
		SigningAlg: SigningAlgES256,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Issuer:     "sn360-test",
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("ES256 issuer: %v", err)
	}

	// Dual-verify issuer (the production migration shape) carries
	// both the legacy HS256 secret AND the new ES256 public key.
	// Its SigningAlg is ES256 (the new shape) but it accepts HS256
	// at verify time. This is the exact runtime shape an operator
	// targets during a cutover.
	dualIss, err := NewJWTIssuer(JWTConfig{
		SigningAlg: SigningAlgES256,
		Secret:     secret,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Issuer:     "sn360-test",
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("dual issuer: %v", err)
	}

	hsTok, err := hsIss.Issue("t", "m", IssueOptions{Role: RoleAdmin})
	if err != nil {
		t.Fatalf("hs issue: %v", err)
	}
	esTok, err := esIss.Issue("t", "m", IssueOptions{Role: RoleAdmin})
	if err != nil {
		t.Fatalf("es issue: %v", err)
	}

	if _, err := dualIss.Verify(hsTok); err != nil {
		t.Errorf("dual issuer must verify HS256 tokens during migration: %v", err)
	}
	if _, err := dualIss.Verify(esTok); err != nil {
		t.Errorf("dual issuer must verify ES256 tokens: %v", err)
	}

	// And the dual issuer's own Issue() emits ES256 (the configured
	// SigningAlg) — not HS256. This is what guarantees new tokens
	// migrate forward even when HS256 verifier material is still
	// configured for backward compatibility.
	selfTok, err := dualIss.Issue("t", "m", IssueOptions{Role: RoleAdmin})
	if err != nil {
		t.Fatalf("dual issuer self-issue: %v", err)
	}
	parser := jwt.NewParser()
	selfParts, _, err := parser.ParseUnverified(selfTok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("unverified parse: %v", err)
	}
	if got := selfParts.Method.Alg(); got != "ES256" {
		t.Errorf("dual issuer signed with alg=%q, want ES256", got)
	}
}

// TestJWTRejectsAlgWithoutKey covers two fail-closed scenarios:
//
//  1. An HS256-only issuer rejects an ES256 token (no public key
//     configured).
//  2. An ES256-only issuer rejects an HS256 token (no secret
//     configured).
//
// This is the explicit guarantee that adding asymmetric verification
// material does not weaken the HS256-only deployments — the verifier
// only accepts algorithms whose key material is actually configured.
func TestJWTRejectsAlgWithoutKey(t *testing.T) {
	hsIss := mustIssuer(t, time.Hour)
	esIss, _ := mustES256Issuer(t, time.Hour, "")

	hsTok, err := hsIss.Issue("t", "m", IssueOptions{})
	if err != nil {
		t.Fatalf("hs issue: %v", err)
	}
	esTok, err := esIss.Issue("t", "m", IssueOptions{})
	if err != nil {
		t.Fatalf("es issue: %v", err)
	}

	if _, err := hsIss.Verify(esTok); err == nil {
		t.Error("HS256-only issuer must reject ES256 token")
	} else if !strings.Contains(err.Error(), "parse") && !strings.Contains(err.Error(), "signing method is invalid") {
		// We don't pin the exact wording — just confirm the
		// error path is the jwt parser's, not a panic.
		t.Logf("HS256-only rejected ES256 with: %v", err)
	}
	if _, err := esIss.Verify(hsTok); err == nil {
		t.Error("ES256-only issuer must reject HS256 token")
	}
}

// TestJWTIssuerPublicJWKS pins the JWKS export shape exposed by the
// /.well-known/jwks.json handler. ES256 issuers MUST publish exactly
// one key; HS256-only issuers MUST publish an empty (but well-formed)
// key set.
func TestJWTIssuerPublicJWKS(t *testing.T) {
	t.Run("es256", func(t *testing.T) {
		iss, _ := mustES256Issuer(t, time.Hour, "k-1")
		jwks, err := iss.PublicJWKS()
		if err != nil {
			t.Fatalf("PublicJWKS: %v", err)
		}
		if len(jwks.Keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(jwks.Keys))
		}
		if jwks.Keys[0].KeyID != "k-1" {
			t.Errorf("kid = %q, want k-1", jwks.Keys[0].KeyID)
		}
	})

	t.Run("hs256_only", func(t *testing.T) {
		iss := mustIssuer(t, time.Hour)
		jwks, err := iss.PublicJWKS()
		if err != nil {
			t.Fatalf("PublicJWKS: %v", err)
		}
		if len(jwks.Keys) != 0 {
			t.Errorf("HS256-only issuer published %d keys, want 0", len(jwks.Keys))
		}
	})
}
