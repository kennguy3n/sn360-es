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

// TestJWTIssueWithScopeAndRecipient covers the WS-3a additions:
// the `scp` and `ruh` claims round-trip through Issue → Verify.
func TestJWTIssueWithScopeAndRecipient(t *testing.T) {
	iss := mustIssuer(t, time.Hour)
	tok, err := iss.Issue("tenant-1", "pmid-9", IssueOptions{
		Scope:             ScopeQuarantineRelease,
		RecipientUserHash: "deadbeefcafebabe",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Scope != ScopeQuarantineRelease {
		t.Errorf("scope=%q want=%q", claims.Scope, ScopeQuarantineRelease)
	}
	if claims.RecipientUserHash != "deadbeefcafebabe" {
		t.Errorf("ruh=%q want deadbeefcafebabe", claims.RecipientUserHash)
	}
}

// TestJWTVerifyDetail_DistinguishesExpiredFromInvalid is the key
// invariant for the WS-3a audit layer: an expired token surfaces
// Expired=true so the handler can write outcome=token_expired,
// while signature-invalid / malformed tokens surface Expired=false
// so the handler writes outcome=invalid_token. Both still return
// a non-nil error so callers can keep using Verify when they
// don't need the distinction.
func TestJWTVerifyDetail_DistinguishesExpiredFromInvalid(t *testing.T) {
	iss := mustIssuer(t, time.Hour)

	t.Run("expired flag set on expired token", func(t *testing.T) {
		// Mint with a 1ms TTL then wait past expiry. Issue's
		// ttl<=0 branch falls through to the issuer default,
		// so we cannot pass a negative TTL through the public
		// API — a tiny positive TTL + sleep is the canonical
		// way to test expiry without reaching into internals.
		tok, err := iss.Issue("t", "m", IssueOptions{TTL: 5 * time.Millisecond})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
		res, err := iss.VerifyDetail(tok)
		if err == nil {
			t.Fatal("expired token should produce a non-nil error")
		}
		if !res.Expired {
			t.Fatal("Expired must be true for past-exp tokens")
		}
	})

	t.Run("invalid signature surfaces Expired=false", func(t *testing.T) {
		tok, err := iss.Issue("t", "m", IssueOptions{})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		// Tamper with the signature by replacing the trailing
		// 8 chars wholesale. A single-byte swap is not enough
		// because base64url decoding may absorb a one-bit
		// difference without changing the decoded signature
		// bytes (different base64 chars can map to the same
		// bits when one ends in padding-equivalent bits).
		// Eight chars guarantees ≥6 decoded bytes change.
		if len(tok) < 16 {
			t.Fatalf("token too short to tamper: %q", tok)
		}
		tampered := tok[:len(tok)-8] + "AAAAAAAA"
		if tampered == tok {
			tampered = tok[:len(tok)-8] + "BBBBBBBB"
		}
		res, err := iss.VerifyDetail(tampered)
		if err == nil {
			t.Fatal("tampered token must error")
		}
		if res.Expired {
			t.Fatal("Expired must be false for signature failures")
		}
	})

	t.Run("malformed surfaces Expired=false", func(t *testing.T) {
		res, err := iss.VerifyDetail("not-a-jwt")
		if err == nil {
			t.Fatal("malformed token must error")
		}
		if res.Expired {
			t.Fatal("Expired must be false for malformed tokens")
		}
	})

	t.Run("empty token rejected uniformly", func(t *testing.T) {
		_, err := iss.VerifyDetail("")
		if err == nil {
			t.Fatal("empty token must error")
		}
	})
}

// TestJWTUnsetScopeDoesNotEqualQuarantineRelease verifies that a
// missing `scp` claim is treated as ScopeBannerAction in upstream
// handlers (we check the claim string here; the dispatcher in
// internal/handler/quarantine.go applies the default). This is the
// scope-confusion guard that prevents a leaked banner token from
// being replayed against the self-release endpoint.
func TestJWTUnsetScopeDoesNotEqualQuarantineRelease(t *testing.T) {
	iss := mustIssuer(t, time.Hour)
	tok, err := iss.Issue("t", "m", IssueOptions{}) // no scope
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Scope == ScopeQuarantineRelease {
		t.Fatal("unset scope must not equal ScopeQuarantineRelease")
	}
}
