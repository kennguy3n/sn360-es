package gmail

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ServiceAccount is the wire shape of a Google service-account JSON
// file. We only consume the four fields needed for the JWT-Bearer
// flow; the rest are ignored so the same JSON can be reused with
// other Google SDKs.
type ServiceAccount struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURI     string `json:"token_uri"`
}

// LoadServiceAccount accepts either a path to a service-account JSON
// file or inline JSON content; it auto-detects the shape by looking
// for a leading "{" byte.
func LoadServiceAccount(jsonOrPath string) (*ServiceAccount, error) {
	if jsonOrPath == "" {
		return nil, errors.New("gmail: service account is empty")
	}
	raw := []byte(jsonOrPath)
	if !strings.HasPrefix(strings.TrimSpace(jsonOrPath), "{") {
		b, err := os.ReadFile(jsonOrPath)
		if err != nil {
			return nil, fmt.Errorf("read service account file: %w", err)
		}
		raw = b
	}
	var sa ServiceAccount
	if err := json.Unmarshal(raw, &sa); err != nil {
		return nil, fmt.Errorf("parse service account: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("gmail: service account missing client_email or private_key")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	return &sa, nil
}

// JWTBearerSource issues access tokens for the Gmail API using the
// JWT-Bearer assertion flow with domain-wide delegation. Each call to
// Token() returns a cached token until 60s before expiry, at which
// point a fresh assertion is signed and exchanged.
type JWTBearerSource struct {
	sa         *ServiceAccount
	subject    string // impersonated user; required for delegated access
	scopes     []string
	http       *http.Client
	clock      func() time.Time
	privateKey *rsa.PrivateKey

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// JWTBearerConfig wires JWTBearerSource. ImpersonatedUser is the
// delegated admin / mailbox owner the service account acts as; for
// Gmail this is typically the mailbox owner's address.
type JWTBearerConfig struct {
	ServiceAccount    *ServiceAccount
	ImpersonatedUser  string
	Scopes            []string
	HTTPClient        *http.Client
	OverrideTokenURI  string // tests inject httptest URL here
}

// NewJWTBearerSource constructs a JWTBearerSource and parses the
// PEM-encoded private key once so each Token call is cheap.
func NewJWTBearerSource(cfg JWTBearerConfig) (*JWTBearerSource, error) {
	if cfg.ServiceAccount == nil {
		return nil, errors.New("gmail: service account is required")
	}
	if cfg.ImpersonatedUser == "" {
		return nil, errors.New("gmail: impersonated user is required for domain-wide delegation")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{
			"https://www.googleapis.com/auth/gmail.modify",
			"https://www.googleapis.com/auth/admin.directory.user.readonly",
		}
	}
	priv, err := parseRSAKey([]byte(cfg.ServiceAccount.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	sa := *cfg.ServiceAccount
	if cfg.OverrideTokenURI != "" {
		sa.TokenURI = cfg.OverrideTokenURI
	}
	return &JWTBearerSource{
		sa:         &sa,
		subject:    cfg.ImpersonatedUser,
		scopes:     append([]string(nil), cfg.Scopes...),
		http:       client,
		clock:      time.Now,
		privateKey: priv,
	}, nil
}

// Token returns a fresh access token, refreshing when the cached
// value has fewer than 60 seconds remaining.
func (s *JWTBearerSource) Token(ctx context.Context) (string, error) {
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

// refresh signs a fresh assertion and exchanges it for an access
// token. Always called with s.mu held.
func (s *JWTBearerSource) refresh(ctx context.Context) (string, time.Duration, error) {
	now := s.clock()
	claims := jwt.MapClaims{
		"iss":   s.sa.ClientEmail,
		"scope": strings.Join(s.scopes, " "),
		"aud":   s.sa.TokenURI,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"sub":   s.subject,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.sa.PrivateKeyID != "" {
		tok.Header["kid"] = s.sa.PrivateKeyID
	}
	assertion, err := tok.SignedString(s.privateKey)
	if err != nil {
		return "", 0, fmt.Errorf("sign assertion: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.sa.TokenURI,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

// parseRSAKey decodes a PEM-encoded RSA private key. Both PKCS#1
// ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") are accepted because
// Google issues PKCS#8 by default but operators sometimes re-export
// the key.
func parseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", parsed)
	}
	return rsaKey, nil
}
