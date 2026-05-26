package onboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	ZohoAPIBaseURL        string // overridable for tests; defaults to https://mail.zoho.com/api
	// ZohoExpectedOrgID, when non-empty, requires the org returned by
	// /api/organization to match this value. When empty the validator
	// only confirms that the token can read the org endpoint.
	ZohoExpectedOrgID string
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
		ZohoAPIBaseURL:        "https://mail.zoho.com/api",
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
	case ProviderZoho:
		return v.validateZoho(ctx, token, tenantID)
	case ProviderFastmail:
		// Fastmail uses static API tokens that are minted directly by
		// the user; there is no OAuth consent to validate. The token
		// itself proves possession of the account.
		return nil
	case ProviderWorkmail:
		// WorkMail uses IAM credentials; no OAuth consent to validate.
		// AWS rejects unsigned/unauthorised SigV4 requests at the API
		// edge, so the first WorkMail call serves as the access check.
		return nil
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
	endpoint := baseURL + "/admin/directory/v1/users?maxResults=1"
	domain := v.gwsDomain
	if domain == "" {
		domain = tenantID
	}
	if domain != "" {
		endpoint += "&domain=" + url.QueryEscape(domain)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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

// validateZoho calls Zoho Mail's /api/organization endpoint. A 200
// response proves the access token has the ZohoMail.accounts.READ
// scope on a real org; when ZohoExpectedOrgID is set the response
// body is parsed and the returned zoid must match.
func (v *HTTPPostConsentValidator) validateZoho(ctx context.Context, token Token, _ string) error {
	baseURL := v.ZohoAPIBaseURL
	if baseURL == "" {
		baseURL = "https://mail.zoho.com/api"
	}
	endpoint := baseURL + "/organization"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Zoho-oauthtoken "+token.AccessToken)
	resp, err := v.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("onboarding: zoho org validation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("onboarding: zoho org validation failed (status %d): %s", resp.StatusCode, string(body))
	}
	if v.ZohoExpectedOrgID == "" {
		return nil
	}
	var result struct {
		Data []struct {
			Zoid       string `json:"zoid"`
			OrgID      string `json:"orgId"`
			OrgIDAlt   string `json:"OrgId"`
			PrimaryURL string `json:"primaryUrl"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("onboarding: decode zoho org response: %w", err)
	}
	for _, org := range result.Data {
		if org.Zoid == v.ZohoExpectedOrgID || org.OrgID == v.ZohoExpectedOrgID || org.OrgIDAlt == v.ZohoExpectedOrgID {
			return nil
		}
	}
	return fmt.Errorf("onboarding: zoho org mismatch — expected %q, not found in response", v.ZohoExpectedOrgID)
}

// NoopPostConsentValidator always succeeds. Used when validation is
// disabled or in tests.
type NoopPostConsentValidator struct{}

// ValidateTenantAccess always returns nil.
func (NoopPostConsentValidator) ValidateTenantAccess(context.Context, Token, string, ProviderType) error {
	return nil
}
