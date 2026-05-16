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
