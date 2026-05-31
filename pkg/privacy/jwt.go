package privacy

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SigningAlg names the JWT signature algorithm a token-issuing
// JWTIssuer should use.
//
// HS256 — HMAC-SHA-256, the original (and still-supported) banner
// token signing scheme. Symmetric, no JWKS publishing. Suitable for
// in-cluster issue/verify only; consumers that need to verify a
// token without holding the shared secret cannot use HS256.
//
// ES256 — ECDSA P-256 with SHA-256 (RFC 7518 §3.4). Asymmetric; the
// public half is published over GET /.well-known/jwks.json so
// out-of-cluster verifiers (downstream platforms, partner products,
// the future eventbus signature consumer) can verify tokens without
// shared-secret rotation. ES256 is the target steady-state algorithm;
// HS256 remains as a migration bridge so tokens issued under the old
// scheme keep verifying for the remainder of their TTL.
type SigningAlg string

const (
	SigningAlgHS256 SigningAlg = "HS256"
	SigningAlgES256 SigningAlg = "ES256"
)

// String exposes the canonical (uppercase) algorithm name. Useful in
// log lines and headers without exposing the underlying type.
func (a SigningAlg) String() string { return string(a) }

// JWTIssuer signs and verifies action tokens used by the banner UX
// (Report Phishing / Mark Safe / Trust Sender) and the URL
// interstitial, plus the principal-bearing platform session tokens
// consumed by middleware.JWTAuth on /v1/* routes.
//
// The issuer supports two algorithms (see SigningAlg). The `signingAlg`
// field selects which one Issue() uses. Verify() is intentionally more
// permissive: it accepts ANY algorithm whose key material has been
// configured on this issuer. This dual-verify behaviour is what lets a
// deployment cut over from HS256 to ES256 without a flag-day: an
// operator can deploy ES256 issuance while still verifying the trailing
// tail of in-flight HS256 tokens, then deconfigure the HS256 secret
// after one TTL window.
//
// Production deployments stamp a non-empty keyID on the issuer when
// signing ES256 — the kid is propagated as a JWS header and lets a
// JWKS-pinning consumer match the verification key without trial.
type JWTIssuer struct {
	signingAlg SigningAlg
	issuer     string
	ttl        time.Duration

	// HS256 verifier (and issuer when signingAlg == HS256).
	secret []byte

	// ES256 issuer (when signingAlg == ES256) and verifier (always,
	// when the public key is configured).
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	keyID      string
}

// JWTConfig holds the inputs for NewJWTIssuer.
//
// Algorithm selection:
//
//   - SigningAlg empty or SigningAlgHS256: issue HS256, require Secret
//     to be set and ≥ 32 bytes.
//   - SigningAlgES256: issue ES256, require both PrivateKey and
//     PublicKey to be set (PublicKey is needed because Verify
//     re-derives the verification material from the configured public
//     half — we never trust the embedded key inside the private key
//     struct as the verification key, so operators that rotate the
//     public half independently still get the expected behaviour).
//
// Verifier configuration is orthogonal to issuer configuration: an
// HS256-issuing process MAY still set PublicKey to dual-verify ES256
// tokens issued by a sibling process, and vice-versa. Both keys may
// be configured simultaneously during migration.
type JWTConfig struct {
	// SigningAlg selects which algorithm Issue() uses. Empty
	// defaults to SigningAlgHS256 for backward compatibility —
	// every existing caller continues to issue HS256 tokens
	// without code change.
	SigningAlg SigningAlg
	// Secret is the HMAC secret. Must be at least 32 bytes (the issuer
	// rejects shorter secrets to keep cryptographic strength sane).
	Secret []byte
	// PrivateKey signs ES256 tokens at Issue() time. Required when
	// SigningAlg == SigningAlgES256. May be nil otherwise.
	PrivateKey *ecdsa.PrivateKey
	// PublicKey verifies ES256 tokens at Verify() time. Required
	// when SigningAlg == SigningAlgES256 OR when this issuer is
	// expected to dual-verify ES256 tokens issued elsewhere.
	PublicKey *ecdsa.PublicKey
	// KeyID is stamped as the JWS `kid` header on ES256 tokens and
	// surfaces as the JWK `kid` member on the JWKS endpoint. Empty
	// is permitted (the JWS header simply omits `kid`) but every
	// production deployment should set a stable identifier so
	// JWKS-pinning consumers can survive key rotation. Recommended
	// default: the RFC 7638 thumbprint of the public key, computed
	// by JWKFromECDSAPublicKey when KeyID is empty.
	KeyID string
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

// NewJWTIssuer constructs an issuer.
//
// Algorithm-specific requirements:
//
//   - HS256 (default): Secret must be at least 32 bytes. Public/private
//     key fields are ignored unless the caller also wants to dual-
//     verify ES256 tokens issued elsewhere.
//   - ES256: PrivateKey and PublicKey must both be non-nil and use the
//     P-256 curve. Secret is permitted to be set in parallel so the
//     issuer can verify HS256 tokens still in flight during migration.
func NewJWTIssuer(cfg JWTConfig) (*JWTIssuer, error) {
	alg := cfg.SigningAlg
	if alg == "" {
		alg = SigningAlgHS256
	}
	switch alg {
	case SigningAlgHS256:
		if len(cfg.Secret) < 32 {
			return nil, fmt.Errorf("%w: JWT secret must be >= 32 bytes (got %d)", ErrInvalidKey, len(cfg.Secret))
		}
	case SigningAlgES256:
		if cfg.PrivateKey == nil {
			return nil, errors.New("privacy/jwt: ES256 requires a non-nil ECDSA P-256 private key")
		}
		if cfg.PublicKey == nil {
			return nil, errors.New("privacy/jwt: ES256 requires a non-nil ECDSA P-256 public key")
		}
		if cfg.PrivateKey.Curve == nil || cfg.PrivateKey.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("privacy/jwt: ES256 private key curve is %q, want P-256", curveName(&cfg.PrivateKey.PublicKey))
		}
		if cfg.PublicKey.Curve == nil || cfg.PublicKey.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("privacy/jwt: ES256 public key curve is %q, want P-256", curveName(cfg.PublicKey))
		}
	default:
		return nil, fmt.Errorf("privacy/jwt: unsupported signing algorithm %q (want %s or %s)", alg, SigningAlgHS256, SigningAlgES256)
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 7 * 24 * time.Hour
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "sn360-es"
	}
	return &JWTIssuer{
		signingAlg: alg,
		secret:     cfg.Secret,
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PublicKey,
		keyID:      cfg.KeyID,
		issuer:     cfg.Issuer,
		ttl:        cfg.TTL,
	}, nil
}

// SigningAlg returns the algorithm Issue() stamps onto fresh tokens.
// Verify() may accept additional algorithms when the corresponding
// key material is configured — see the JWTIssuer doc-comment.
func (i *JWTIssuer) SigningAlg() SigningAlg { return i.signingAlg }

// PublicJWKS returns the JWKS document that should be served at
// /.well-known/jwks.json.
//
// When the issuer has no ECDSA public key configured (i.e. an
// HS256-only deployment), an empty JWKS is returned — NOT an error.
// This keeps the handler trivially correct: an HS256-only cluster
// can still expose /.well-known/jwks.json and the consumer sees a
// well-formed but empty key set, which is the documented signal
// (RFC 7517 §5 implies an empty keys array is valid) that no
// asymmetric verification material is available.
//
// When the keyID is empty, JWKFromECDSAPublicKey falls back to the
// RFC 7638 thumbprint so the JWK is still self-identifying.
func (i *JWTIssuer) PublicJWKS() (JWKS, error) {
	if i.publicKey == nil {
		return JWKS{Keys: []JWK{}}, nil
	}
	jwk, err := JWKFromECDSAPublicKey(i.publicKey, i.keyID)
	if err != nil {
		return JWKS{}, fmt.Errorf("privacy/jwt: build JWK: %w", err)
	}
	return JWKS{Keys: []JWK{jwk}}, nil
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
	var (
		tok *jwt.Token
		key any
	)
	switch i.signingAlg {
	case SigningAlgES256:
		tok = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		if i.keyID != "" {
			// Stamp `kid` on the JWS header so a JWKS-pinning
			// verifier can pick the right key out of a
			// multi-entry JWKS without trial-verifying every
			// candidate.
			tok.Header["kid"] = i.keyID
		}
		key = i.privateKey
	case SigningAlgHS256:
		tok = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key = i.secret
	default:
		// Defensive: NewJWTIssuer would have rejected this
		// already, but covering the branch keeps an in-process
		// mutation of i.signingAlg (e.g. fuzz tests, future
		// hot-reload) from silently signing with an unintended
		// algorithm.
		return "", fmt.Errorf("privacy/jwt: signing algorithm %q is not configured for this issuer", i.signingAlg)
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("privacy/jwt: sign: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a token previously issued by Issue (or
// by a sibling process configured with the same key material). It
// returns the embedded claims on success.
//
// Algorithm acceptance is determined by which key material is
// configured on this issuer:
//
//   - When secret is set, HS256 tokens are accepted.
//   - When publicKey is set, ES256 tokens are accepted.
//
// Both may be set simultaneously, in which case the issuer
// dual-verifies. The fail-closed default still applies: a token with
// alg=none, or with an algorithm whose key is not configured, is
// rejected before any signature check runs (jwt.WithValidMethods is
// computed from the configured set).
func (i *JWTIssuer) Verify(token string) (*ActionClaims, error) {
	if token == "" {
		return nil, errors.New("privacy/jwt: token is required")
	}
	validMethods := i.validMethods()
	if len(validMethods) == 0 {
		return nil, errors.New("privacy/jwt: issuer has no verification material configured")
	}
	parsed, err := jwt.ParseWithClaims(token, &ActionClaims{},
		func(t *jwt.Token) (interface{}, error) {
			switch t.Method.(type) {
			case *jwt.SigningMethodHMAC:
				if i.secret == nil {
					return nil, errors.New("privacy/jwt: HS256 token but no HMAC secret configured")
				}
				return i.secret, nil
			case *jwt.SigningMethodECDSA:
				if i.publicKey == nil {
					return nil, errors.New("privacy/jwt: ES256 token but no ECDSA public key configured")
				}
				return i.publicKey, nil
			default:
				return nil, fmt.Errorf("privacy/jwt: unexpected signing method %T", t.Method)
			}
		},
		jwt.WithIssuer(i.issuer),
		jwt.WithValidMethods(validMethods),
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

// validMethods returns the JWS `alg` values this issuer will accept
// at verify time. It is the set of algorithms whose key material is
// configured — NOT the set of algorithms supported by the library.
// Returning an empty slice trips the explicit guard at the top of
// Verify().
func (i *JWTIssuer) validMethods() []string {
	out := make([]string, 0, 2)
	if len(i.secret) > 0 {
		out = append(out, string(SigningAlgHS256))
	}
	if i.publicKey != nil {
		out = append(out, string(SigningAlgES256))
	}
	return out
}
