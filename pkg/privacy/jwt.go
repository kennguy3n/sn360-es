package privacy

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTIssuer signs and verifies action tokens used by the banner UX
// (Report Phishing / Mark Safe / Trust Sender) and the URL interstitial.
// Tokens are deliberately small (HS256, no PII) — see
// ARCHITECTURE.md Section 8.6.
type JWTIssuer struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

// JWTConfig holds the inputs for NewJWTIssuer.
type JWTConfig struct {
	// Secret is the HMAC secret. Must be at least 32 bytes (the issuer
	// rejects shorter secrets to keep cryptographic strength sane).
	Secret []byte
	// Issuer is the `iss` claim emitted on every token.
	Issuer string
	// TTL is the default token lifetime. Per-call options can override.
	TTL time.Duration
}

// ActionClaims is the canonical claim shape for banner / interstitial
// tokens. The intent is to carry zero PII so a leaked token cannot be
// used to enumerate users or messages from a third party.
type ActionClaims struct {
	TenantID              string `json:"tid"`
	PseudonymizedMessage  string `json:"pmid"`
	Tier                  string `json:"tier,omitempty"`
	Action                string `json:"act,omitempty"`
	OriginalURLHash       string `json:"urlh,omitempty"`
	jwt.RegisteredClaims
}

// NewJWTIssuer constructs an issuer. Secrets shorter than 32 bytes are
// rejected.
func NewJWTIssuer(cfg JWTConfig) (*JWTIssuer, error) {
	if len(cfg.Secret) < 32 {
		return nil, fmt.Errorf("%w: JWT secret must be >= 32 bytes (got %d)", ErrInvalidKey, len(cfg.Secret))
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 7 * 24 * time.Hour
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "sn360-es"
	}
	return &JWTIssuer{secret: cfg.Secret, issuer: cfg.Issuer, ttl: cfg.TTL}, nil
}

// IssueOptions customises a single Issue call.
type IssueOptions struct {
	TTL     time.Duration
	Tier    string
	Action  string
	URLHash string
}

// Issue signs a fresh ActionClaims token for tenantID + pseudoMessageID.
// The caller should always supply a pseudonymised message ID — never the
// raw provider-issued ID — so leaking a token does not let an attacker
// look up the underlying message at the provider.
func (i *JWTIssuer) Issue(tenantID, pseudoMessageID string, opts IssueOptions) (string, error) {
	if tenantID == "" {
		return "", errors.New("privacy/jwt: tenantID is required")
	}
	if pseudoMessageID == "" {
		return "", errors.New("privacy/jwt: pseudoMessageID is required")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = i.ttl
	}
	now := time.Now().UTC()
	claims := ActionClaims{
		TenantID:             tenantID,
		PseudonymizedMessage: pseudoMessageID,
		Tier:                 opts.Tier,
		Action:               opts.Action,
		OriginalURLHash:      opts.URLHash,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(i.secret)
	if err != nil {
		return "", fmt.Errorf("privacy/jwt: sign: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a token previously issued by Issue. It
// returns the embedded claims on success.
func (i *JWTIssuer) Verify(token string) (*ActionClaims, error) {
	if token == "" {
		return nil, errors.New("privacy/jwt: token is required")
	}
	parsed, err := jwt.ParseWithClaims(token, &ActionClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("privacy/jwt: unexpected signing method %T", t.Method)
			}
			return i.secret, nil
		},
		jwt.WithIssuer(i.issuer),
		jwt.WithValidMethods([]string{"HS256"}),
	)
	if err != nil {
		return nil, fmt.Errorf("privacy/jwt: parse: %w", err)
	}
	claims, ok := parsed.Claims.(*ActionClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("privacy/jwt: invalid token")
	}
	return claims, nil
}
