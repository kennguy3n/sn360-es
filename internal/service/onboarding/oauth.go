// Package onboarding hosts the OAuth consent + post-consent discovery
// flow for new tenants. It speaks to the AI Onboarding agent and the
// provider directory clients but does not depend on either of them
// directly — both are injected so this package stays test-friendly.
package onboarding

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// ProviderType identifies the OAuth provider.
type ProviderType string

const (
	ProviderGoogle    ProviderType = "google_workspace"
	ProviderMicrosoft ProviderType = "microsoft_365"
)

// ProviderConfig captures the per-provider OAuth parameters.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	Scopes       []string
	RedirectURL  string
}

// Validate sanity-checks the config.
func (p ProviderConfig) Validate() error {
	if p.ClientID == "" || p.ClientSecret == "" {
		return errors.New("onboarding: client credentials required")
	}
	if p.AuthURL == "" || p.TokenURL == "" {
		return errors.New("onboarding: provider URLs required")
	}
	if p.RedirectURL == "" {
		return errors.New("onboarding: redirect URL required")
	}
	if len(p.Scopes) == 0 {
		return errors.New("onboarding: at least one scope required")
	}
	return nil
}

// Token is the canonical OAuth token shape, persisted in encrypted
// storage between sessions.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
}

// IsExpired reports whether the access token has expired (or will in
// the next 60s).
func (t Token) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(60 * time.Second).After(t.ExpiresAt)
}

// TokenStore is implemented by encrypted storage (e.g. S3 with KMS
// envelope encryption). The OAuth flow persists / loads tokens through
// this interface.
type TokenStore interface {
	Save(ctx context.Context, tenantID string, provider ProviderType, tok Token) error
	Load(ctx context.Context, tenantID string, provider ProviderType) (Token, error)
	Delete(ctx context.Context, tenantID string, provider ProviderType) error
}

// TokenExchanger is the HTTP surface for exchanging codes / refresh
// tokens. The default implementation lives in oauth_http.go (one HTTP
// POST per call). Tests can supply a stub.
type TokenExchanger interface {
	ExchangeCode(ctx context.Context, p ProviderConfig, code string) (Token, error)
	RefreshToken(ctx context.Context, p ProviderConfig, refreshToken string) (Token, error)
}

// PostConsentTrigger is the callback the flow runs immediately after a
// successful exchange. Typically this invokes the OnboardingAgent.
type PostConsentTrigger interface {
	StartOnboarding(ctx context.Context, tenantID string, provider ProviderType) error
}

// StateSigner is the small HMAC helper used to bind tenant_id +
// provider + nonce into the OAuth `state` parameter so the callback
// can verify the consent originated from us.
type StateSigner struct {
	secret []byte
}

// NewStateSigner returns a StateSigner. secret must be ≥16 bytes.
func NewStateSigner(secret []byte) (*StateSigner, error) {
	if len(secret) < 16 {
		return nil, errors.New("onboarding: state signer secret must be ≥16 bytes")
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &StateSigner{secret: cp}, nil
}

// StatePayload bundles the data we encode into the state parameter.
type StatePayload struct {
	TenantID  string       `json:"tid"`
	Provider  ProviderType `json:"p"`
	Nonce     string       `json:"n"`
	IssuedAt  int64        `json:"iat"`
	ExpiresAt int64        `json:"exp"`
}

// Sign returns "{base64(payload)}.{hex(hmac)}".
func (s *StateSigner) Sign(payload StatePayload) (string, error) {
	if payload.Nonce == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		payload.Nonce = hex.EncodeToString(buf)
	}
	if payload.IssuedAt == 0 {
		payload.IssuedAt = time.Now().Unix()
	}
	if payload.ExpiresAt == 0 {
		payload.ExpiresAt = payload.IssuedAt + 600 // 10 minutes
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(blob)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(enc))
	return enc + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify decodes and validates a state value. Returns the payload on
// success.
func (s *StateSigner) Verify(token string) (StatePayload, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return StatePayload{}, errors.New("onboarding: invalid state format")
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(parts[0]))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return StatePayload{}, errors.New("onboarding: state HMAC mismatch")
	}
	blob, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return StatePayload{}, fmt.Errorf("onboarding: state base64: %w", err)
	}
	var p StatePayload
	if err := json.Unmarshal(blob, &p); err != nil {
		return StatePayload{}, fmt.Errorf("onboarding: state decode: %w", err)
	}
	now := time.Now().Unix()
	if p.ExpiresAt > 0 && now > p.ExpiresAt {
		return StatePayload{}, errors.New("onboarding: state expired")
	}
	return p, nil
}

// Service is the orchestrator that builds consent URLs, validates
// callbacks, exchanges codes, persists tokens, and kicks off the
// onboarding agent.
type Service struct {
	providers map[ProviderType]ProviderConfig
	store     TokenStore
	exch      TokenExchanger
	state     *StateSigner
	trigger   PostConsentTrigger
	nonces    NonceStore
	validator PostConsentValidator
	log       *slog.Logger
}

// ServiceConfig bundles the inputs to NewService.
type ServiceConfig struct {
	Providers map[ProviderType]ProviderConfig
	Store     TokenStore
	Exch      TokenExchanger
	State     *StateSigner
	Trigger   PostConsentTrigger
	Nonces    NonceStore
	Validator PostConsentValidator
	Logger    *slog.Logger
}

// NewService validates cfg and returns a Service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("onboarding: TokenStore is required")
	}
	if cfg.Exch == nil {
		return nil, errors.New("onboarding: TokenExchanger is required")
	}
	if cfg.State == nil {
		return nil, errors.New("onboarding: StateSigner is required")
	}
	if len(cfg.Providers) == 0 {
		return nil, errors.New("onboarding: at least one provider config required")
	}
	for k, v := range cfg.Providers {
		if err := v.Validate(); err != nil {
			return nil, fmt.Errorf("onboarding: provider %s: %w", k, err)
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{
		providers: cfg.Providers,
		store:     cfg.Store,
		exch:      cfg.Exch,
		state:     cfg.State,
		trigger:   cfg.Trigger,
		nonces:    cfg.Nonces,
		validator: cfg.Validator,
		log:       cfg.Logger,
	}, nil
}

// AuthURL returns the consent URL the user should visit. Includes a
// signed state binding tenantID + provider. Parameters are
// provider-aware: Google gets access_type=offline; Microsoft does not.
func (s *Service) AuthURL(provider ProviderType, tenantID string) (string, error) {
	p, ok := s.providers[provider]
	if !ok {
		return "", fmt.Errorf("onboarding: unknown provider %q", provider)
	}
	stateTok, err := s.state.Sign(StatePayload{TenantID: tenantID, Provider: provider})
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(p.Scopes, " "))
	q.Set("state", stateTok)
	// Provider-specific parameters.
	switch provider {
	case ProviderGoogle:
		q.Set("access_type", "offline")
		q.Set("prompt", "consent")
	case ProviderMicrosoft:
		q.Set("prompt", "consent")
	default:
		q.Set("prompt", "consent")
	}
	return p.AuthURL + "?" + q.Encode(), nil
}

// HandleCallback validates the state, checks nonce replay, exchanges
// the code, validates tenant access, persists the token, and triggers
// onboarding. It returns the tenant ID extracted from the state on
// success.
func (s *Service) HandleCallback(ctx context.Context, stateTok, code string) (string, ProviderType, error) {
	payload, err := s.state.Verify(stateTok)
	if err != nil {
		return "", "", err
	}
	// Nonce replay prevention.
	if s.nonces != nil {
		alreadyUsed, nonceErr := s.nonces.MarkUsed(ctx, payload.Nonce, 10*time.Minute)
		if nonceErr != nil {
			s.log.Warn("onboarding: nonce store error (proceeding)",
				slog.String("err", nonceErr.Error()))
		} else if alreadyUsed {
			return "", "", errors.New("onboarding: nonce already used (replay detected)")
		}
	}
	p, ok := s.providers[payload.Provider]
	if !ok {
		return "", "", fmt.Errorf("onboarding: unknown provider %q", payload.Provider)
	}
	tok, err := s.exch.ExchangeCode(ctx, p, code)
	if err != nil {
		return "", "", fmt.Errorf("onboarding: exchange code: %w", err)
	}
	// Post-consent domain/tenant verification.
	if s.validator != nil {
		if valErr := s.validator.ValidateTenantAccess(ctx, tok, payload.TenantID, payload.Provider); valErr != nil {
			_ = s.store.Delete(ctx, payload.TenantID, payload.Provider)
			return "", "", fmt.Errorf("onboarding: tenant validation failed: %w", valErr)
		}
	}
	if err := s.store.Save(ctx, payload.TenantID, payload.Provider, tok); err != nil {
		return "", "", fmt.Errorf("onboarding: persist token: %w", err)
	}
	if s.trigger != nil {
		if err := s.trigger.StartOnboarding(ctx, payload.TenantID, payload.Provider); err != nil {
			s.log.Warn("onboarding: post-consent trigger failed",
				slog.String("tenant_id", payload.TenantID),
				slog.String("err", err.Error()))
		}
	}
	s.log.Info("onboarding: consent completed",
		slog.String("tenant_id", payload.TenantID),
		slog.String("provider", string(payload.Provider)))
	return payload.TenantID, payload.Provider, nil
}

// TokenFor returns a valid (possibly refreshed) token for (tenantID,
// provider). If the stored token is expired and a refresh token is
// present, the call transparently refreshes and rewrites storage.
func (s *Service) TokenFor(ctx context.Context, tenantID string, provider ProviderType) (Token, error) {
	tok, err := s.store.Load(ctx, tenantID, provider)
	if err != nil {
		return Token{}, err
	}
	if !tok.IsExpired() {
		return tok, nil
	}
	if tok.RefreshToken == "" {
		return Token{}, errors.New("onboarding: token expired and no refresh token available")
	}
	p, ok := s.providers[provider]
	if !ok {
		return Token{}, fmt.Errorf("onboarding: unknown provider %q", provider)
	}
	refreshed, err := s.exch.RefreshToken(ctx, p, tok.RefreshToken)
	if err != nil {
		return Token{}, fmt.Errorf("onboarding: refresh: %w", err)
	}
	if refreshed.RefreshToken == "" {
		// Some providers do not roll the refresh token; keep the old one.
		refreshed.RefreshToken = tok.RefreshToken
	}
	if err := s.store.Save(ctx, tenantID, provider, refreshed); err != nil {
		return Token{}, fmt.Errorf("onboarding: persist refreshed token: %w", err)
	}
	return refreshed, nil
}

// Revoke clears the stored token. Used on tenant deletion or admin
// revocation.
func (s *Service) Revoke(ctx context.Context, tenantID string, provider ProviderType) error {
	return s.store.Delete(ctx, tenantID, provider)
}
