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

// Role enumerates the principal types the RBAC layer understands.
// These values are stamped into the `role` JWT claim at issuance
// time and read back by middleware.RequireRole on every authenticated
// HTTP request. Keep this enum closed — the middleware fails-closed
// on any value not in this set, so adding a new role requires:
//
//  1. Adding it here.
//  2. Updating the issuance site (e.g. the dashboard login flow) to
//     stamp the new value.
//  3. Updating every RequireRole(...) call-site in cmd/sn360-es/
//     routes.go that should accept it.
//
// Compile-time tying of the constants keeps the call-sites grep-able
// and prevents typo'd role strings from silently 403-ing in prod.
const (
	// RoleAdmin can perform every action including destructive
	// tenant-scoped operations (delete vendor, revoke onboarding,
	// tune score engine, modify RBAC). Reserved for human SOC /
	// platform owners.
	RoleAdmin = "admin"
	// RoleOperator can perform most day-to-day write operations
	// (approve / revoke vendor, resolve escalation, start
	// onboarding) but cannot revoke onboarding or perform
	// destructive deletes. Reserved for tenant-admin operators.
	RoleOperator = "operator"
	// RoleViewer is read-only across the dashboard and investigation
	// surfaces. Cannot mutate anything.
	RoleViewer = "viewer"
	// RoleEndUser is the principal type stamped onto banner-action,
	// URL-interstitial and quarantine-release tokens consumed by
	// end recipients. These tokens are validated inside their own
	// per-route handlers (see handler.BannerActionHandler,
	// handler.InterstitialHandler, handler.QuarantineHandler) and
	// the paths they hit bypass the platform-wide JWT middleware
	// (see defaultAuthSkipPaths) — so RoleEndUser is mostly
	// informational on the wire today, but it is the value any
	// future RequireRole(end_user) gate would match.
	RoleEndUser = "end_user"
)

// validRoles is the closed allowlist used by IsValidRole. Update both
// the constants above and this map together — RBAC fails-closed on
// unknown role strings, so a typo here surfaces as 403 in production.
var validRoles = map[string]struct{}{
	RoleAdmin:    {},
	RoleOperator: {},
	RoleViewer:   {},
	RoleEndUser:  {},
}

// IsValidRole reports whether r is one of the four canonical role
// constants (Admin, Operator, Viewer, EndUser). The empty string and
// any unknown value return false. This is the sole sanctioned check
// callers should use to validate role values — middleware.RequireRole
// invokes it on both the principal's claim and on each role listed in
// an Allow(...) tuple, so misspellings in either are caught before any
// authorization decision is made.
func IsValidRole(r string) bool {
	_, ok := validRoles[r]
	return ok
}

// ActionClaims is the canonical claim shape for banner / interstitial
// tokens AND for the principal-bearing API session tokens consumed by
// middleware.JWTAuth on /v1/* routes. The intent is to carry zero PII
// so a leaked token cannot be used to enumerate users or messages
// from a third party — Role and TenantID are the only fields that
// influence access decisions, and Role only resolves to one of the
// four constants above.
type ActionClaims struct {
	TenantID             string `json:"tid"`
	PseudonymizedMessage string `json:"pmid"`
	Tier                 string `json:"tier,omitempty"`
	Action               string `json:"act,omitempty"`
	OriginalURLHash      string `json:"urlh,omitempty"`
	// Role is the RBAC principal type. Required on tokens that hit
	// JWT-protected /v1/* routes. Banner-action / interstitial /
	// quarantine-release tokens stamp RoleEndUser even though their
	// paths bypass the platform JWT middleware — this keeps every
	// token issued by sn360-es self-describing for any future audit
	// or transition-period gate.
	Role string `json:"role,omitempty"`
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
	// Role stamps the `role` claim onto the issued token. Must be
	// one of the Role* constants OR the empty string. The empty
	// string is permitted so a caller that doesn't yet know the
	// principal (e.g. a unit test focused on tenant_id round-trip,
	// or a token class that intentionally carries no role) can
	// still issue a token; RequireRole will then fail-closed at
	// verify time because the empty role isn't in any allow-list.
	//
	// Non-empty values, by contrast, are validated against the
	// closed enum below — Issue refuses to sign a token with a
	// role string that isn't one of admin / operator / viewer /
	// end_user. This catches typo'd role constants (e.g.
	// "RoleAdmni") at the call-site rather than letting the typo
	// flow all the way to a 403 in production.
	Role string
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
	// Validate the role claim at issuance time so a typo'd role
	// constant — e.g. RequireRole(privacy.RoleAdmin) at the gate
	// site but Issue(... Role: "adim") at the issuance site —
	// fails fast at the issuance call instead of silently
	// 403-ing in production. Empty string remains permitted (see
	// IssueOptions.Role docstring): RequireRole fails closed on
	// it anyway, so the round-trip is still safe, but tests and
	// transitional callers that don't carry a role aren't forced
	// to.
	if opts.Role != "" && !IsValidRole(opts.Role) {
		return "", fmt.Errorf("privacy/jwt: invalid role %q (must be one of admin, operator, viewer, end_user, or empty)", opts.Role)
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
		Role:                 opts.Role,
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
