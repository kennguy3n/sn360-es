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
