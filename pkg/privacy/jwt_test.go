package privacy

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
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
	other := &JWTIssuer{secret: iss.secret, issuer: "different-issuer", ttl: time.Hour}
	if _, err := other.Verify(tok); err == nil {
		t.Error("token should not verify under a different issuer string")
	}
}
