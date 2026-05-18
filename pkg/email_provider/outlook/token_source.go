package outlook

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

// ClientCredentialsSource issues access tokens for Microsoft Graph
// using the OAuth2 client_credentials flow. It caches the most
// recently issued token until 60s before expiry.
type ClientCredentialsSource struct {
	tenantID     string
	clientID     string
	clientSecret string
	scope        string
	tokenURL     string
	http         *http.Client
	clock        func() time.Time

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// ClientCredentialsConfig wires ClientCredentialsSource.
type ClientCredentialsConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Scope        string
	TokenURL     string // overrideable for tests; defaults to login.microsoftonline.com
	HTTPClient   *http.Client
}

// NewClientCredentialsSource constructs a Graph client-credentials
// token source. TenantID, ClientID and ClientSecret are required.
func NewClientCredentialsSource(cfg ClientCredentialsConfig) (*ClientCredentialsSource, error) {
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("outlook: tenant_id, client_id, client_secret required")
	}
	scope := cfg.Scope
	if scope == "" {
		scope = "https://graph.microsoft.com/.default"
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token",
			url.PathEscape(cfg.TenantID))
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &ClientCredentialsSource{
		tenantID:     cfg.TenantID,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		scope:        scope,
		tokenURL:     tokenURL,
		http:         client,
		clock:        time.Now,
	}, nil
}

// Token returns a fresh access token, refreshing when fewer than 60s
// of TTL remain.
func (s *ClientCredentialsSource) Token(ctx context.Context) (string, error) {
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

// refresh executes the client_credentials grant and returns the new
// access token along with its TTL. Always called with s.mu held.
func (s *ClientCredentialsSource) refresh(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{}
	form.Set("client_id", s.clientID)
	form.Set("client_secret", s.clientSecret)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", s.scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return "", 0, fmt.Errorf("read token response: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return "", 0, fmt.Errorf("token exchange %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", 0, fmt.Errorf("decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", 0, errors.New("token response missing access_token")
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return out.AccessToken, ttl, nil
}
