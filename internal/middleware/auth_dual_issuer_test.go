package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// captureHandler records the tenant + claims the middleware injected.
func captureHandler(seenTenant *string, seenClaims **privacy.ActionClaims) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seenTenant = TenantIDFromContext(r.Context())
		*seenClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

// TestJWTAuth_DualIssuer_AcceptsBothTokens proves the dual-issuer
// middleware accepts an existing privacy-package token AND an iam-core
// JWKS token, populating tenant_id in context from each.
func TestJWTAuth_DualIssuer_AcceptsBothTokens(t *testing.T) {
	primary := newTestIssuer(t)
	ts := newJWKSTestServer(t)

	var seenTenant string
	var seenClaims *privacy.ActionClaims
	mw := NewJWTAuth(captureHandler(&seenTenant, &seenClaims), JWTAuthConfig{
		Issuer:         primary,
		IAMCoreJWKSURL: ts.server.URL,
		IAMCoreIssuer:  testIAMIssuer,
	})

	// 1) Existing privacy-package token.
	primaryTok, err := primary.Issue("acme", "pmid-1", privacy.IssueOptions{})
	if err != nil {
		t.Fatalf("issue primary: %v", err)
	}
	rec := doAuthRequest(mw, primaryTok)
	if rec.Code != http.StatusOK {
		t.Fatalf("primary token: code=%d", rec.Code)
	}
	if seenTenant != "acme" {
		t.Fatalf("primary tenant=%q", seenTenant)
	}
	if seenClaims == nil || seenClaims.PseudonymizedMessage != "pmid-1" {
		t.Fatalf("primary claims=%+v", seenClaims)
	}

	// 2) iam-core JWKS token.
	seenTenant, seenClaims = "", nil
	iamTok := ts.signECToken(t, iamClaims("globex"), testECKid)
	rec = doAuthRequest(mw, iamTok)
	if rec.Code != http.StatusOK {
		t.Fatalf("iam-core token: code=%d", rec.Code)
	}
	if seenTenant != "globex" {
		t.Fatalf("iam-core tenant=%q", seenTenant)
	}
	// iam-core claims surface only the tenant.
	if seenClaims == nil || seenClaims.TenantID != "globex" {
		t.Fatalf("iam-core claims=%+v", seenClaims)
	}
}

// TestJWTAuth_DualIssuer_IAMCoreTenantInContext is the focused check
// that an iam-core token's tenant_id claim lands in the context key.
func TestJWTAuth_DualIssuer_IAMCoreTenantInContext(t *testing.T) {
	ts := newJWKSTestServer(t)

	var seenTenant string
	var seenClaims *privacy.ActionClaims
	// iam-core-only deployment: no primary issuer wired.
	mw := NewJWTAuth(captureHandler(&seenTenant, &seenClaims), JWTAuthConfig{
		IAMCoreJWKSURL: ts.server.URL,
		IAMCoreIssuer:  testIAMIssuer,
	})

	tok := ts.signRSAToken(t, iamClaims("tenant-xyz"), testRSAKid)
	rec := doAuthRequest(mw, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	if seenTenant != "tenant-xyz" {
		t.Fatalf("tenant=%q, want tenant-xyz", seenTenant)
	}
}

// TestJWTAuth_DualIssuer_RejectsForeignToken ensures a token from
// neither issuer is rejected (no silent pass-through).
func TestJWTAuth_DualIssuer_RejectsForeignToken(t *testing.T) {
	primary := newTestIssuer(t)
	ts := newJWKSTestServer(t)
	mw := NewJWTAuth(okHandler(), JWTAuthConfig{
		Issuer:         primary,
		IAMCoreJWKSURL: ts.server.URL,
		IAMCoreIssuer:  testIAMIssuer,
	})

	// Valid signature/kid but wrong issuer → neither path accepts it.
	claims := iamClaims("acme")
	claims.Issuer = "https://attacker.example.com/"
	tok := ts.signECToken(t, claims, testECKid)

	rec := doAuthRequest(mw, tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("foreign token: code=%d, want 401", rec.Code)
	}
}

// TestJWTAuth_DualIssuer_InjectedVerifier exercises the IAMCore
// injection seam used by callers that build their own verifier.
func TestJWTAuth_DualIssuer_InjectedVerifier(t *testing.T) {
	var seenTenant string
	var seenClaims *privacy.ActionClaims
	mw := NewJWTAuth(captureHandler(&seenTenant, &seenClaims), JWTAuthConfig{
		IAMCore: stubVerifier{tenantID: "stub-tenant"},
	})
	rec := doAuthRequest(mw, "any-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	if seenTenant != "stub-tenant" {
		t.Fatalf("tenant=%q", seenTenant)
	}
}

type stubVerifier struct {
	tenantID string
}

func (s stubVerifier) Verify(_ context.Context, _ string) (string, error) {
	return s.tenantID, nil
}

func doAuthRequest(mw http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/predict/open", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	return rec
}
