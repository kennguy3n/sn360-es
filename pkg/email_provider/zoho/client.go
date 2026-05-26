package zoho

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the shared HTTP plumbing reused by every Zoho integration
// in this package (mailbox, label, banner, body, quarantine,
// directory). Centralising auth + error decoding keeps the surface
// per-feature file tiny and ensures the same retry / token semantics
// everywhere.
//
// The Zoho REST API uses the custom `Authorization: Zoho-oauthtoken
// <token>` header rather than the more common Bearer scheme.
type Client struct {
	http    *http.Client
	tokens  TokenSource
	baseURL string
	orgID   string
}

// ClientConfig configures Client.
type ClientConfig struct {
	HTTPClient  *http.Client
	TokenSource TokenSource
	// BaseURL overrides the Zoho Mail REST endpoint. When empty the
	// DataCenter field is mapped to the canonical mail.zoho.<tld>/api
	// hostname.
	BaseURL string
	// DataCenter selects the Zoho region when BaseURL is empty.
	DataCenter string
	// OrgID is the Zoho Mail organisation ID. Required for
	// /api/organization endpoints.
	OrgID string
}

// NewClient validates the config and returns a ready-to-use Client.
// TokenSource and OrgID are required.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("zoho: token source is required")
	}
	if strings.TrimSpace(cfg.OrgID) == "" {
		return nil, errors.New("zoho: org_id is required")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = MailBaseURL(cfg.DataCenter)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		http:    client,
		tokens:  cfg.TokenSource,
		baseURL: base,
		orgID:   strings.TrimSpace(cfg.OrgID),
	}, nil
}

// BaseURL exposes the resolved base URL, useful for diagnostics.
func (c *Client) BaseURL() string { return c.baseURL }

// OrgID exposes the configured org id.
func (c *Client) OrgID() string { return c.orgID }

// APIError captures a non-2xx Zoho response.
type APIError struct {
	StatusCode int
	Body       string
	Endpoint   string
}

// Error renders a compact form including the endpoint for fast triage.
func (e *APIError) Error() string {
	return fmt.Sprintf("zoho: %d %s: %s", e.StatusCode, e.Endpoint, truncate(e.Body, 256))
}

// do executes an authenticated request and decodes the JSON response
// into out when out != nil. Non-2xx responses are turned into a typed
// APIError carrying the response body.
func (c *Client) do(ctx context.Context, method, endpoint string, in, out any) error {
	var bodyReader io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("zoho: marshal: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("zoho: build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	tok, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("zoho: acquire token: %w", err)
	}
	if tok == "" {
		return errors.New("zoho: empty bearer token")
	}
	// Zoho uses the custom Zoho-oauthtoken scheme rather than Bearer.
	req.Header.Set("Authorization", "Zoho-oauthtoken "+tok)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("zoho: http: %w", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if rerr != nil {
		return fmt.Errorf("zoho: read body: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return &APIError{StatusCode: resp.StatusCode, Body: string(respBody), Endpoint: endpoint}
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("zoho: decode: %w", err)
	}
	return nil
}

// truncate caps the printed body length in error strings.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
