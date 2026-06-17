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

// Scope constants define the closed set of permitted `scp` claim
// values. A token issued for one scope MUST NOT be accepted by a
// handler that checks for a different scope — the scope check is
// the only thing that prevents a leaked banner token (Report
// Phishing) from being replayed against the self-release endpoint.
const (
	// ScopeBannerAction is the implicit scope for legacy banner
	// action tokens (Report Phishing / Mark Safe / Trust Sender /
	// URL interstitial). A token with no `scp` claim is treated
	// as having ScopeBannerAction for backward compatibility with
	// tokens minted before WS-3a landed.
	ScopeBannerAction = "banner_action"
	// ScopeQuarantineRelease is the WS-3a self-service release
	// scope. The release handler refuses any token whose `scp` is
	// not exactly this value (uniform 401).
	ScopeQuarantineRelease = "quarantine_release"
	// ScopeAdminAPI is the operator-grade scope required by
	// /v1/intel/* endpoints (threat-intel feed CRUD + indicator
	// debug lookup). It is intentionally distinct from
	// ScopeBannerAction so a leaked recipient/operator token
	// can't be replayed against the admin surface. Tokens with
	// this scope MAY be issued only by the internal admin
	// console — no public-facing endpoint mints them.
	ScopeAdminAPI = "admin_api"
)

// Role constants identify the kind of principal a token represents.
//
// Tokens minted for message-scoped flows (banner action, quarantine
// release) carry an empty Role — those flows authenticate the
// recipient by the message-id + tenant-id binding, not by an
// operator identity. Operator-issued tokens that drive the
// management plane carry RoleAdmin; middleware.RequireAdmin gates
// admin-only routes on this value.
const (
	// RoleAdmin grants access to tenant-administrator endpoints
	// (e.g. WS-5B.2 webhook-sink CRUD).
	RoleAdmin = "admin"
)

// ActionClaims is the canonical claim shape for banner / interstitial
// and self-release tokens. The intent is to carry zero PII so a
// leaked token cannot be used to enumerate users or messages from a
// third party.
//
// Scope is the cross-handler isolation primitive (see Scope*
// constants). RecipientUserHash is populated only for
// ScopeQuarantineRelease tokens; it is the BLAKE2b-256 hex digest
// of the recipient mailbox the token authorises — the same shape
// `users.email_hash` carries — so the release handler can
// rate-limit per recipient without trusting any header.
type ActionClaims struct {
	TenantID             string `json:"tid"`
	PseudonymizedMessage string `json:"pmid"`
	Tier                 string `json:"tier,omitempty"`
	Action               string `json:"act,omitempty"`
	OriginalURLHash      string `json:"urlh,omitempty"`
	// Scope is the closed-set claim that prevents cross-scope
	// token replay. Empty is treated as ScopeBannerAction for
	// backward compatibility — never blank-equivalent to
	// ScopeQuarantineRelease.
	Scope string `json:"scp,omitempty"`
	// RecipientUserHash is the hex-encoded BLAKE2b-256 pseudonym
	// of the recipient mailbox the token authorises. Populated
	// only for ScopeQuarantineRelease.
	RecipientUserHash string `json:"ruh,omitempty"`
	// Role identifies the principal type the token represents.
	// Empty means "recipient / message-scoped action token" (the
	// legacy banner / quarantine path). Operator-issued admin
	// tokens that drive management-plane CRUD APIs (e.g.
	// WS-5B.2 webhook-sink configuration) carry RoleAdmin.
	// Middleware that gates admin-only routes
	// (middleware.RequireAdmin) accepts a token only when this
	// is RoleAdmin.
	Role string `json:"role,omitempty"`
	jwt.RegisteredClaims
}

// ErrScopeNotPermitted is returned by VerifyWithOptions /
// VerifyDetailWithOptions when a cryptographically valid token carries
// a `scp` claim that is not in the caller's allowed set. It is the
// centralised form of the cross-scope replay guard described in the
// Scope* doc comment: rather than relying on every verify site to
// remember the check, a call site declares the scope(s) it accepts and
// a leaked token minted for a different surface is refused here.
var ErrScopeNotPermitted = errors.New("privacy/jwt: token scope not permitted")

// EffectiveScope returns the scope a token is treated as carrying: its
// literal `scp` claim, or ScopeBannerAction when the claim is empty
// (the documented backward-compatibility default — a token minted
// before the `scp` claim existed is a banner-action token). Dispatch
// and enforcement logic should funnel through this so the
// empty-means-banner rule lives in exactly one place.
func EffectiveScope(scope string) string {
	if scope == "" {
		return ScopeBannerAction
	}
	return scope
}

// VerifyResult is the verifier's return type when the caller needs
// to distinguish "expired token" from "invalid signature" for audit
// purposes WITHOUT differentiating them on the wire. The handler
// always returns the same 401 body to the client, but writes
// different audit outcomes (`token_expired` vs `invalid_token`)
// based on Expired.
type VerifyResult struct {
	Claims *ActionClaims
	// Expired is true when the token parsed and the signature
	// validated but `exp` was in the past. False when the token
	// was rejected for any other reason (signature, malformed,
	// missing claim).
	Expired bool
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
	// Scope is the value the issued token carries in its `scp`
	// claim. When empty, the token is minted without a `scp`
	// claim and Verify treats it as ScopeBannerAction. Set
	// explicitly for new flows (e.g. ScopeQuarantineRelease).
	Scope string
	// RecipientUserHash is hex-encoded into the `ruh` claim.
	// Populated only for ScopeQuarantineRelease tokens.
	RecipientUserHash string
	// Role is the value the issued token carries in its `role`
	// claim. Used for operator-issued admin tokens — see
	// privacy.RoleAdmin.
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
		Scope:                opts.Scope,
		RecipientUserHash:    opts.RecipientUserHash,
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
	res, err := i.VerifyDetail(token)
	if err != nil {
		return nil, err
	}
	return res.Claims, nil
}

// VerifyDetail is like Verify but distinguishes "expired token" from
// "other invalid" via the returned VerifyResult.Expired flag. Both
// cases still return a non-nil error so callers that don't need the
// distinction can keep using Verify. Use this from handlers that
// need to audit expired-vs-tampered separately while emitting the
// same wire response.
func (i *JWTIssuer) VerifyDetail(token string) (VerifyResult, error) {
	if token == "" {
		return VerifyResult{}, errors.New("privacy/jwt: token is required")
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
		// jwt-go signals expiry via errors.Is(err,
		// jwt.ErrTokenExpired). Capture that distinction so the
		// handler can pick the right audit outcome — but keep the
		// wrapped error path identical so the wire response is
		// uniform 401 regardless of which underlying validation
		// failed.
		expired := errors.Is(err, jwt.ErrTokenExpired)
		var claims *ActionClaims
		if parsed != nil {
			if c, ok := parsed.Claims.(*ActionClaims); ok {
				claims = c
			}
		}
		return VerifyResult{Claims: claims, Expired: expired},
			fmt.Errorf("privacy/jwt: parse: %w", err)
	}
	claims, ok := parsed.Claims.(*ActionClaims)
	if !ok || !parsed.Valid {
		return VerifyResult{}, errors.New("privacy/jwt: invalid token")
	}
	return VerifyResult{Claims: claims}, nil
}

// VerifyOptions tunes the scope-aware verify entry points. The zero
// value imposes no scope restriction, so VerifyWithOptions /
// VerifyDetailWithOptions with a zero VerifyOptions behave exactly
// like Verify / VerifyDetail.
type VerifyOptions struct {
	// AllowedScopes is the closed set of `scp` values the caller
	// accepts. Empty means "accept any scope" (the historical
	// behaviour). When non-empty, a cryptographically valid token is
	// rejected with ErrScopeNotPermitted unless its EffectiveScope is
	// a member — so a banner-action endpoint that passes
	// []string{ScopeBannerAction} refuses a leaked quarantine_release
	// or admin_api token, while still accepting legacy tokens minted
	// without an explicit `scp` (their empty claim normalises to
	// ScopeBannerAction).
	AllowedScopes []string
}

// VerifyWithOptions verifies token like Verify and then enforces the
// scope restriction in opts. Callers that need to distinguish expired
// from invalid for audit should use VerifyDetailWithOptions.
func (i *JWTIssuer) VerifyWithOptions(token string, opts VerifyOptions) (*ActionClaims, error) {
	res, err := i.VerifyDetailWithOptions(token, opts)
	if err != nil {
		return nil, err
	}
	return res.Claims, nil
}

// VerifyDetailWithOptions verifies token like VerifyDetail and then,
// when opts.AllowedScopes is non-empty, enforces that the token's
// EffectiveScope is a member of it — returning ErrScopeNotPermitted
// otherwise. The scope check runs strictly after signature, issuer and
// expiry validation succeed: a token that fails VerifyDetail surfaces
// that error (and its Expired distinction) unchanged, so the
// auth-failure audit path is unaffected.
func (i *JWTIssuer) VerifyDetailWithOptions(token string, opts VerifyOptions) (VerifyResult, error) {
	res, err := i.VerifyDetail(token)
	if err != nil {
		return res, err
	}
	if len(opts.AllowedScopes) > 0 {
		got := EffectiveScope(res.Claims.Scope)
		if !scopeAllowed(got, opts.AllowedScopes) {
			return VerifyResult{Claims: res.Claims},
				fmt.Errorf("%w: have %q", ErrScopeNotPermitted, got)
		}
	}
	return res, nil
}

// scopeAllowed reports whether scope (already normalised via
// EffectiveScope) matches any entry in allowed. Allowed entries are
// normalised too so a caller may pass "" as shorthand for
// ScopeBannerAction.
func scopeAllowed(scope string, allowed []string) bool {
	for _, a := range allowed {
		if EffectiveScope(a) == scope {
			return true
		}
	}
	return false
}
