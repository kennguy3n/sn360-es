package onboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PostConsentValidator verifies that a freshly-obtained token grants
// access to the expected tenant. This catches mismatched consent
// (user consents from wrong org).
type PostConsentValidator interface {
	ValidateTenantAccess(ctx context.Context, token Token, tenantID string, provider ProviderType) error
}

// HTTPPostConsentValidator validates by calling provider APIs.
type HTTPPostConsentValidator struct {
	client                *http.Client
	gwsDomain             string // expected GWS primary domain
	GoogleAdminBaseURL    string // overridable for tests; defaults to https://admin.googleapis.com
	MicrosoftGraphBaseURL string // overridable for tests; defaults to https://graph.microsoft.com
}

// NewHTTPPostConsentValidator constructs a validator.
func NewHTTPPostConsentValidator(client *http.Client, gwsDomain string) *HTTPPostConsentValidator {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HTTPPostConsentValidator{
		client:                client,
		gwsDomain:             gwsDomain,
		GoogleAdminBaseURL:    "https://admin.googleapis.com",
		MicrosoftGraphBaseURL: "https://graph.microsoft.com",
	}
}

// ValidateTenantAccess checks that the token grants access to the
// expected tenant. For Google: call Admin SDK users endpoint. For
// Microsoft: call Graph /organization and verify tenantId.
func (v *HTTPPostConsentValidator) ValidateTenantAccess(ctx context.Context, token Token, tenantID string, provider ProviderType) error {
	switch provider {
	case ProviderGoogle:
		return v.validateGoogle(ctx, token, tenantID)
	case ProviderMicrosoft:
		return v.validateMicrosoft(ctx, token, tenantID)
	default:
		return fmt.Errorf("onboarding: unsupported provider for validation: %s", provider)
	}
}

func (v *HTTPPostConsentValidator) httpClient() *http.Client {
	if v.client != nil {
		return v.client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (v *HTTPPostConsentValidator) validateGoogle(ctx context.Context, token Token, tenantID string) error {
	baseURL := v.GoogleAdminBaseURL
	if baseURL == "" {
		baseURL = "https://admin.googleapis.com"
	}
	url := baseURL + "/admin/directory/v1/users?maxResults=1"
	domain := v.gwsDomain
	if domain == "" {
		domain = tenantID
	}
	if domain != "" {
		url += "&domain=" + domain
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := v.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("onboarding: google domain validation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("onboarding: google domain validation failed (status %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

func (v *HTTPPostConsentValidator) validateMicrosoft(ctx context.Context, token Token, tenantID string) error {
	baseURL := v.MicrosoftGraphBaseURL
	if baseURL == "" {
		baseURL = "https://graph.microsoft.com"
	}
	url := baseURL + "/v1.0/organization"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := v.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("onboarding: microsoft org validation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("onboarding: microsoft org validation failed (status %d): %s", resp.StatusCode, string(body))
	}
	var result struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("onboarding: decode org response: %w", err)
	}
	for _, org := range result.Value {
		if org.ID == tenantID {
			return nil
		}
	}
	return fmt.Errorf("onboarding: token tenant mismatch — expected %q, not found in organization list", tenantID)
}

// NoopPostConsentValidator always succeeds. Used when validation is
// disabled or in tests.
type NoopPostConsentValidator struct{}

// ValidateTenantAccess always returns nil.
func (NoopPostConsentValidator) ValidateTenantAccess(context.Context, Token, string, ProviderType) error {
	return nil
}
