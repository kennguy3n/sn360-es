package onboarding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPExchanger is the default TokenExchanger that speaks OAuth 2.0 to
// the provider's token endpoint.
type HTTPExchanger struct {
	Client *http.Client
}

// NewHTTPExchanger returns a HTTPExchanger with sensible defaults.
func NewHTTPExchanger(client *http.Client) *HTTPExchanger {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &HTTPExchanger{Client: client}
}

type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (e *HTTPExchanger) post(ctx context.Context, p ProviderConfig, form url.Values) (Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := e.Client.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("oauth: POST %s: %w", p.TokenURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Token{}, fmt.Errorf("oauth: read body: %w", err)
	}

	var parsed oauthTokenResponse
	// Some providers (notably older M365 endpoints) return form-encoded;
	// try JSON first, fall back to form.
	if err := json.Unmarshal(body, &parsed); err != nil {
		vals, formErr := url.ParseQuery(string(body))
		if formErr != nil {
			return Token{}, fmt.Errorf("oauth: parse response: %w (status=%d)", err, resp.StatusCode)
		}
		parsed.AccessToken = vals.Get("access_token")
		parsed.RefreshToken = vals.Get("refresh_token")
		parsed.TokenType = vals.Get("token_type")
		parsed.Scope = vals.Get("scope")
	}
	if resp.StatusCode/100 != 2 || parsed.Error != "" {
		return Token{}, fmt.Errorf("oauth: provider error: status=%d code=%s desc=%s", resp.StatusCode, parsed.Error, parsed.ErrorDesc)
	}
	if parsed.AccessToken == "" {
		return Token{}, errors.New("oauth: empty access token in response")
	}
	tok := Token{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
		TokenType:    parsed.TokenType,
		Scope:        parsed.Scope,
		IDToken:      parsed.IDToken,
	}
	if parsed.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(parsed.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// ExchangeCode implements TokenExchanger.
func (e *HTTPExchanger) ExchangeCode(ctx context.Context, p ProviderConfig, code string) (Token, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", p.ClientID)
	form.Set("client_secret", p.ClientSecret)
	form.Set("redirect_uri", p.RedirectURL)
	return e.post(ctx, p, form)
}

// RefreshToken implements TokenExchanger.
func (e *HTTPExchanger) RefreshToken(ctx context.Context, p ProviderConfig, refreshToken string) (Token, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", p.ClientID)
	form.Set("client_secret", p.ClientSecret)
	return e.post(ctx, p, form)
}
