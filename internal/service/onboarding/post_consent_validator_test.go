package onboarding

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPPostConsentValidator_Google_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/directory/v1/users" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("domain") != "example.com" {
			t.Errorf("unexpected domain: %s", r.URL.Query().Get("domain"))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"users": []map[string]string{{"primaryEmail": "admin@example.com"}},
		})
	}))
	defer srv.Close()

	v := &HTTPPostConsentValidator{
		GoogleAdminBaseURL:    srv.URL,
		MicrosoftGraphBaseURL: "",
	}

	tok := Token{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	err := v.ValidateTenantAccess(context.Background(), tok, "example.com", ProviderGoogle)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestHTTPPostConsentValidator_Google_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	v := &HTTPPostConsentValidator{
		GoogleAdminBaseURL: srv.URL,
	}

	tok := Token{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	err := v.ValidateTenantAccess(context.Background(), tok, "example.com", ProviderGoogle)
	if err == nil {
		t.Error("expected error for forbidden response")
	}
}

func TestHTTPPostConsentValidator_Microsoft_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.0/organization" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]string{{"id": "tenant-123"}},
		})
	}))
	defer srv.Close()

	v := &HTTPPostConsentValidator{
		MicrosoftGraphBaseURL: srv.URL,
	}

	tok := Token{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	err := v.ValidateTenantAccess(context.Background(), tok, "tenant-123", ProviderMicrosoft)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestHTTPPostConsentValidator_Microsoft_WrongTenant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]string{{"id": "other-tenant"}},
		})
	}))
	defer srv.Close()

	v := &HTTPPostConsentValidator{
		MicrosoftGraphBaseURL: srv.URL,
	}

	tok := Token{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	err := v.ValidateTenantAccess(context.Background(), tok, "expected-tenant", ProviderMicrosoft)
	if err == nil {
		t.Error("expected error for tenant mismatch")
	}
}

func TestHTTPPostConsentValidator_UnknownProvider(t *testing.T) {
	v := &HTTPPostConsentValidator{}
	tok := Token{AccessToken: "x", ExpiresAt: time.Now().Add(time.Hour)}
	err := v.ValidateTenantAccess(context.Background(), tok, "t", "unknown")
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestHTTPPostConsentValidator_Zoho_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/organization" {
			t.Errorf("Zoho validator hit unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Zoho-oauthtoken zoho-at" {
			t.Errorf("Zoho validator Authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"zoid": "100200300", "orgId": "100200300"},
			},
		})
	}))
	defer srv.Close()
	v := &HTTPPostConsentValidator{
		ZohoAPIBaseURL:    srv.URL,
		ZohoExpectedOrgID: "100200300",
	}
	tok := Token{AccessToken: "zoho-at", ExpiresAt: time.Now().Add(time.Hour)}
	if err := v.ValidateTenantAccess(context.Background(), tok, "acme", ProviderZoho); err != nil {
		t.Fatalf("ValidateTenantAccess: %v", err)
	}
}

func TestHTTPPostConsentValidator_Zoho_WrongOrgID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"zoid": "999", "orgId": "999"},
			},
		})
	}))
	defer srv.Close()
	v := &HTTPPostConsentValidator{
		ZohoAPIBaseURL:    srv.URL,
		ZohoExpectedOrgID: "100200300",
	}
	tok := Token{AccessToken: "x", ExpiresAt: time.Now().Add(time.Hour)}
	if err := v.ValidateTenantAccess(context.Background(), tok, "acme", ProviderZoho); err == nil {
		t.Fatal("expected org mismatch to error")
	}
}

func TestHTTPPostConsentValidator_FastmailWorkmail_AlwaysOK(t *testing.T) {
	// Fastmail (static token) and WorkMail (IAM SigV4) bypass OAuth
	// post-consent validation; the validator should return nil so the
	// onboarding flow doesn't reject them on a check that doesn't
	// apply to their auth model.
	v := &HTTPPostConsentValidator{}
	tok := Token{AccessToken: "x", ExpiresAt: time.Now().Add(time.Hour)}
	if err := v.ValidateTenantAccess(context.Background(), tok, "acme", ProviderFastmail); err != nil {
		t.Errorf("Fastmail validation: %v", err)
	}
	if err := v.ValidateTenantAccess(context.Background(), tok, "acme", ProviderWorkmail); err != nil {
		t.Errorf("WorkMail validation: %v", err)
	}
}
