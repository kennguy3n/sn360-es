// Package zoho implements the SN360-ES provider integration against
// Zoho Mail's REST API (https://www.zoho.com/mail/help/api/).
//
// Zoho operates six independent data centres ("com", "eu", "in",
// "com.au", "com.cn", "jp") with isolated user databases, so every
// REST and OAuth endpoint must be addressed at its region-specific
// hostname. The token source and HTTP clients in this package derive
// their hostnames from the configured DataCenter when an explicit
// BaseURL / AccountsURL is not provided.
//
// The package mirrors the dependency-free style of the other
// providers: only the Go standard library is used.
package zoho

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenSource yields a fresh OAuth2 bearer token on each call. The
// surface is intentionally tiny so consumers can plug in
// RefreshTokenSource (production), a static-token adapter
// (StaticTokenSource), or a custom function for tests.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts an ordinary function to TokenSource.
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token implements TokenSource.
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// StaticTokenSource returns the same access token on every call.
// Useful for tests that drive httptest servers without exercising
// the refresh flow.
type StaticTokenSource struct{ AccessToken string }

// Token implements TokenSource.
func (s StaticTokenSource) Token(context.Context) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("zoho: static token source has empty access token")
	}
	return s.AccessToken, nil
}

// RefreshTokenSource performs the OAuth2 refresh-token grant against
// Zoho's accounts endpoint and caches the resulting access token
// until 60s before expiry. The refresh token itself is long-lived
// and issued by the Zoho API Console for the (ClientID, ClientSecret)
// pair.
type RefreshTokenSource struct {
	clientID     string
	clientSecret string
	refreshToken string
	tokenURL     string
	http         *http.Client
	clock        func() time.Time

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// RefreshTokenConfig wires RefreshTokenSource.
type RefreshTokenConfig struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
	// DataCenter selects the Zoho region. When AccountsURL is set
	// it takes precedence; otherwise DataCenter is mapped onto the
	// canonical accounts.zoho.<tld> hostname via AccountsBaseURL.
	DataCenter string
	// AccountsURL overrides the accounts endpoint. Useful for
	// httptest in unit tests.
	AccountsURL string
	HTTPClient  *http.Client
	// Clock is injectable for deterministic TTL tests; nil → time.Now.
	Clock func() time.Time
}

// NewRefreshTokenSource validates the configuration and returns a
// usable token source. ClientID, ClientSecret and RefreshToken are
// required; AccountsURL / DataCenter pick the Zoho region.
func NewRefreshTokenSource(cfg RefreshTokenConfig) (*RefreshTokenSource, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RefreshToken == "" {
		return nil, errors.New("zoho: client_id, client_secret and refresh_token are required")
	}
	tokenURL := strings.TrimRight(cfg.AccountsURL, "/")
	if tokenURL == "" {
		tokenURL = AccountsBaseURL(cfg.DataCenter)
	}
	tokenURL += "/oauth/v2/token" //nolint:gosec // G101: URL path, not a credential
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &RefreshTokenSource{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		refreshToken: cfg.RefreshToken,
		tokenURL:     tokenURL,
		http:         client,
		clock:        clock,
	}, nil
}

// Token returns a fresh access token, refreshing when fewer than 60s
// of TTL remain. Safe for concurrent use.
func (s *RefreshTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accessToken != "" && s.clock().Before(s.expiresAt.Add(-60*time.Second)) {
		return s.accessToken, nil
	}
	tok, ttl, err := s.refresh(ctx)
	if err != nil {
		return "", err
	}
	s.accessToken = tok
	s.expiresAt = s.clock().Add(ttl)
	return tok, nil
}

// refresh exchanges the long-lived refresh token for a short-lived
// access token. Must be called with s.mu held.
func (s *RefreshTokenSource) refresh(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{}
	form.Set("client_id", s.clientID)
	form.Set("client_secret", s.clientSecret)
	form.Set("refresh_token", s.refreshToken)
	form.Set("grant_type", "refresh_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("zoho: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("zoho: token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return "", 0, fmt.Errorf("zoho: read token response: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return "", 0, fmt.Errorf("zoho: token exchange %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		// Zoho occasionally returns errors under HTTP 200 with an
		// "error" field instead of a status. Surface that as a
		// transport error so the caller can retry.
		Error string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", 0, fmt.Errorf("zoho: decode token response: %w", err)
	}
	if out.Error != "" {
		return "", 0, fmt.Errorf("zoho: token error: %s", out.Error)
	}
	if out.AccessToken == "" {
		return "", 0, errors.New("zoho: token response missing access_token")
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		// Zoho documents 3600s as the default; fall back to that
		// rather than treating a missing expires_in as "never
		// refresh".
		ttl = time.Hour
	}
	return out.AccessToken, ttl, nil
}

// AccountsBaseURL returns the canonical Zoho accounts URL for the
// given data center code. Supported codes mirror the Zoho regions;
// unknown values fall back to the US ("com") region so a typo
// produces a recognisable 4xx instead of a panic.
func AccountsBaseURL(dataCenter string) string {
	switch strings.ToLower(strings.TrimSpace(dataCenter)) {
	case "eu":
		return "https://accounts.zoho.eu"
	case "in":
		return "https://accounts.zoho.in"
	case "com.au", "au":
		return "https://accounts.zoho.com.au"
	case "com.cn", "cn":
		return "https://accounts.zoho.com.cn"
	case "jp":
		return "https://accounts.zoho.jp"
	default:
		return "https://accounts.zoho.com"
	}
}

// MailBaseURL returns the canonical Zoho Mail REST API URL for the
// given data center code. Same regional mapping as AccountsBaseURL.
func MailBaseURL(dataCenter string) string {
	switch strings.ToLower(strings.TrimSpace(dataCenter)) {
	case "eu":
		return "https://mail.zoho.eu/api"
	case "in":
		return "https://mail.zoho.in/api"
	case "com.au", "au":
		return "https://mail.zoho.com.au/api"
	case "com.cn", "cn":
		return "https://mail.zoho.com.cn/api"
	case "jp":
		return "https://mail.zoho.jp/api"
	default:
		return "https://mail.zoho.com/api"
	}
}
