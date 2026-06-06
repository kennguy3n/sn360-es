package middleware

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IAMCoreVerifier validates a bearer token minted by iam-core and
// returns the tenant_id claim it carries. It is the secondary,
// JWKS-backed issuer the dual-issuer middleware consults after the
// primary privacy.JWTIssuer rejects a token.
type IAMCoreVerifier interface {
	// Verify validates token's signature against the issuer's JWKS,
	// checks the `iss` claim, and returns the `tenant_id` claim. A
	// non-nil error means the token is not a valid iam-core token.
	Verify(ctx context.Context, token string) (tenantID string, err error)
}

// iamCoreClaims is the minimal claim shape sn360-es reads from an
// iam-core access token. iam-core mints far richer tokens (see
// iam-core internal/biz/jwt.go JWTClaims); we deliberately bind only
// to the `tenant_id` claim plus the standard registered claims so the
// coupling between the two services stays narrow.
type iamCoreClaims struct {
	TenantID string `json:"tenant_id"`
	jwt.RegisteredClaims
}

// iamCoreAsymmetricAlgs is the closed set of signing algorithms the
// JWKS verifier accepts. It is intentionally restricted to asymmetric
// families so that an attacker who learns a JWKS public key cannot
// forge a token by submitting it as an HS256 (symmetric) secret — the
// classic "alg confusion" downgrade. `none` is rejected for the same
// reason. iam-core itself signs with RS256 (legacy keys) or ES256
// (the current default for new tenants); the broader RSA/ECDSA family
// is permitted so key rotation to a stronger curve/size never wedges
// validation here.
var iamCoreAsymmetricAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// JWKSVerifierConfig wires a JWKSVerifier.
type JWKSVerifierConfig struct {
	// JWKSURL is the absolute URL of the iam-core JWKS document
	// (e.g. https://iam.example.com/.well-known/jwks.json). Required.
	JWKSURL string
	// Issuer is the expected `iss` claim. Tokens whose issuer does
	// not match are rejected. Required.
	Issuer string
	// HTTPClient fetches the JWKS. Defaults to a client with a 10s
	// timeout when nil.
	HTTPClient *http.Client
	// CacheTTL is how long a fetched key set is trusted before a
	// proactive refresh. Defaults to 1h. The cache is what keeps
	// token validation off the network on the hot path — a per-
	// request JWKS fetch would add an iam-core round-trip to every
	// authenticated call.
	CacheTTL time.Duration
	// MinRefreshInterval rate-limits reactive refreshes triggered by
	// an unknown `kid` (i.e. a freshly rotated signing key). Defaults
	// to 1m so a burst of tokens carrying an unrecognised kid cannot
	// stampede iam-core's JWKS endpoint.
	MinRefreshInterval time.Duration
}

// JWKSVerifier validates iam-core tokens against a cached JWKS. It is
// safe for concurrent use.
type JWKSVerifier struct {
	jwksURL    string
	issuer     string
	client     *http.Client
	cacheTTL   time.Duration
	minRefresh time.Duration
	parser     *jwt.Parser

	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

// NewJWKSVerifier constructs a JWKSVerifier. It does not perform any
// network I/O — the first Verify call lazily fetches the JWKS.
func NewJWKSVerifier(cfg JWKSVerifierConfig) (*JWKSVerifier, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("middleware/jwks: JWKSURL is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("middleware/jwks: Issuer is required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	minRefresh := cfg.MinRefreshInterval
	if minRefresh <= 0 {
		minRefresh = time.Minute
	}
	return &JWKSVerifier{
		jwksURL:    cfg.JWKSURL,
		issuer:     cfg.Issuer,
		client:     client,
		cacheTTL:   ttl,
		minRefresh: minRefresh,
		parser: jwt.NewParser(
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithValidMethods(iamCoreAsymmetricAlgs),
		),
		keys: map[string]crypto.PublicKey{},
	}, nil
}

// Verify implements IAMCoreVerifier.
func (v *JWKSVerifier) Verify(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", errors.New("middleware/jwks: token is required")
	}
	// Proactively refresh when the cache is empty or stale so the
	// common case never depends on a reactive (unknown-kid) refresh.
	// Use refreshIfAllowed (rate-limited) instead of refresh directly
	// so that concurrent requests hitting the TTL boundary don't all
	// stampede the JWKS endpoint — only the first one through the
	// throttle window actually fetches.
	if v.stale() {
		// A refresh failure here is non-fatal: a still-valid cached
		// key set can keep validating tokens while iam-core's JWKS
		// endpoint is briefly unavailable.
		_ = v.refreshIfAllowed(ctx)
	}

	var claims iamCoreClaims
	_, err := v.parser.ParseWithClaims(token, &claims, v.keyfunc(ctx))
	if err != nil {
		return "", fmt.Errorf("middleware/jwks: verify: %w", err)
	}
	if claims.TenantID == "" {
		return "", errors.New("middleware/jwks: token missing tenant_id claim")
	}
	return claims.TenantID, nil
}

// keyfunc resolves the verification key for a parsed token by matching
// its `kid` header against the cached key set. On an unknown kid it
// triggers a single rate-limited refresh (a signing-key rotation is
// the expected cause) before failing.
func (v *JWKSVerifier) keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		// Defence in depth: the parser already restricts to
		// iamCoreAsymmetricAlgs, but re-assert the method family so a
		// returned public key can never be fed to an HMAC verifier.
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodECDSA:
		default:
			return nil, fmt.Errorf("middleware/jwks: unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("middleware/jwks: token missing kid header")
		}
		if key, ok := v.lookup(kid); ok {
			return key, nil
		}
		// Unknown kid: iam-core most likely rotated its signing key.
		// Refresh once (rate-limited) and retry the lookup.
		if err := v.refreshIfAllowed(ctx); err != nil {
			// A concurrent goroutine may have completed a refresh
			// while this one was throttled; retry the lookup before
			// giving up so we don't reject a valid token.
			if key, ok := v.lookup(kid); ok {
				return key, nil
			}
			return nil, fmt.Errorf("middleware/jwks: refresh for kid %q: %w", kid, err)
		}
		if key, ok := v.lookup(kid); ok {
			return key, nil
		}
		return nil, fmt.Errorf("middleware/jwks: no key for kid %q", kid)
	}
}

func (v *JWKSVerifier) lookup(kid string) (crypto.PublicKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok := v.keys[kid]
	return key, ok
}

func (v *JWKSVerifier) stale() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.keys) == 0 || time.Since(v.fetchedAt) >= v.cacheTTL
}

// refreshIfAllowed performs at most one JWKS fetch per
// MinRefreshInterval. The throttle check and the claim of the refresh
// window happen under a single write lock, so when a flood of tokens
// carrying an unknown kid (or a burst hitting the TTL boundary) arrives
// at once, exactly one goroutine advances to fetch and the rest are
// throttled immediately — there is no check-then-act window in which
// several callers could all stampede the JWKS endpoint. lastAttempt is
// claimed before the fetch, so the throttle also covers failed attempts.
func (v *JWKSVerifier) refreshIfAllowed(ctx context.Context) error {
	v.mu.Lock()
	if !v.lastAttempt.IsZero() && time.Since(v.lastAttempt) < v.minRefresh {
		v.mu.Unlock()
		return errors.New("refresh throttled")
	}
	v.lastAttempt = time.Now()
	v.mu.Unlock()
	return v.refresh(ctx)
}

// refresh fetches and parses the JWKS, atomically replacing the cached
// key set on success. Callers must claim the refresh window first via
// refreshIfAllowed, which records lastAttempt; refresh itself does not
// touch the throttle state.
func (v *JWKSVerifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: unexpected status %d", resp.StatusCode)
	}
	// Cap the body so a hostile or misconfigured endpoint cannot
	// exhaust memory. A real JWKS is a few KB.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read jwks: %w", err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no usable keys")
	}
	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

// jwk is a single JSON Web Key. Only the fields needed to reconstruct
// RSA and EC public keys are modelled.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWKS decodes a JWKS document into a kid-indexed map of public
// keys. Keys explicitly marked for encryption (`use: enc`) and key
// types other than RSA/EC are skipped rather than failing the whole
// set, so an iam-core JWKS that adds an unrelated key never breaks
// signature validation.
func parseJWKS(body []byte) (map[string]crypto.PublicKey, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("middleware/jwks: decode jwks: %w", err)
	}
	out := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" || k.Use == "enc" {
			continue
		}
		var (
			key crypto.PublicKey
			err error
		)
		switch k.Kty {
		case "RSA":
			key, err = k.rsaKey()
		case "EC":
			key, err = k.ecKey()
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("middleware/jwks: kid %q: %w", k.Kid, err)
		}
		out[k.Kid] = key
	}
	return out, nil
}

func (k jwk) rsaKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("empty RSA parameter")
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 2 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}

func (k jwk) ecKey() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("EC point is not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
