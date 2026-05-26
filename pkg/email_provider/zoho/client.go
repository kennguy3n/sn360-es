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
	"sync"
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

	// accountIDCache memoises the email → Zoho account-id lookup so
	// ApplyLabel / InjectBanner / MoveToQuarantine don't each trigger a
	// full /api/users enumeration. The cache lives on the Client (not
	// per-provider) so all six provider implementations share one
	// resolved account-id table per Zoho tenant.
	accountIDMu     sync.RWMutex
	accountIDByMail map[string]string

	// dirWarmMu serialises the directory-warm path so only one
	// goroutine issues the underlying /api/users walk even when
	// several providers call ResolveAccountID concurrently. We use a
	// plain Mutex + warmed bool rather than sync.Once because we need
	// retry-on-error semantics: a transient directory failure must
	// not permanently disable resolution, which means we have to be
	// able to re-arm the gate from a goroutine that may share the
	// gate with another in-flight reader. sync.Once cannot be reset
	// safely (its internal atomic state cannot be reassigned without
	// a data race with concurrent Do() callers), so we own that state
	// ourselves.
	dirWarmMu sync.Mutex
	dirWarmed bool
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
		http:            client,
		tokens:          cfg.TokenSource,
		baseURL:         base,
		orgID:           strings.TrimSpace(cfg.OrgID),
		accountIDByMail: make(map[string]string),
	}, nil
}

// ResolveAccountID looks up the Zoho account-id for the supplied
// email (matched case-insensitively against primary address and
// aliases) using a per-Client memoised cache. On a miss it issues a
// single directory ListUsers walk, populates the cache, and returns
// the result. Concurrent callers race on the underlying lookup; only
// one network call is made per Client lifetime.
func (c *Client) ResolveAccountID(ctx context.Context, email string) (string, error) {
	target := strings.ToLower(strings.TrimSpace(email))
	if target == "" {
		return "", errors.New("zoho: email is required")
	}
	c.accountIDMu.RLock()
	if id, ok := c.accountIDByMail[target]; ok {
		c.accountIDMu.RUnlock()
		return id, nil
	}
	c.accountIDMu.RUnlock()

	if err := c.warmAccountIDCache(ctx); err != nil {
		return "", err
	}
	c.accountIDMu.RLock()
	id, ok := c.accountIDByMail[target]
	c.accountIDMu.RUnlock()
	if !ok {
		return "", fmt.Errorf("zoho: no account found for %s", target)
	}
	return id, nil
}

// warmAccountIDCache populates the email → account-id cache from a
// single DirectoryClient.ListUsers walk. It is safe for concurrent
// callers: the dirWarmMu guarantees at most one outstanding warm at a
// time, and dirWarmed remembers a successful warm so subsequent
// callers fast-path through. On error dirWarmed stays false so the
// next caller (this one or another goroutine) will retry.
func (c *Client) warmAccountIDCache(ctx context.Context) error {
	c.dirWarmMu.Lock()
	defer c.dirWarmMu.Unlock()
	if c.dirWarmed {
		return nil
	}
	dir, err := NewDirectoryClient(DirectoryClientConfig{Client: c})
	if err != nil {
		return err
	}
	users, err := dir.ListUsers(ctx, "")
	if err != nil {
		return fmt.Errorf("zoho: warm account id cache: %w", err)
	}
	c.accountIDMu.Lock()
	for _, u := range users {
		if u.Email != "" {
			c.accountIDByMail[strings.ToLower(u.Email)] = u.ID
		}
		for _, a := range u.Aliases {
			if a != "" {
				c.accountIDByMail[strings.ToLower(a)] = u.ID
			}
		}
	}
	c.accountIDMu.Unlock()
	c.dirWarmed = true
	return nil
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
