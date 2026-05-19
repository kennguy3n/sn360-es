package handler

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

// Sentinel errors returned by [PushSignatureVerifier] implementations.
// Callers should rely on errors.Is rather than message text so we can
// keep the wire-level reason private when surfaced to the caller.
var (
	// ErrPushAuthMissing is returned when the request did not carry
	// the credentials required to authenticate the push (e.g. no
	// Authorization bearer token for Google, missing clientState
	// for Microsoft).
	ErrPushAuthMissing = errors.New("push: authentication missing")
	// ErrPushAuthInvalid is returned when credentials were present
	// but failed verification (bad signature, wrong audience,
	// mismatched clientState, expired token, ...).
	ErrPushAuthInvalid = errors.New("push: authentication invalid")
	// ErrPushProviderUnknown is returned when the dispatcher cannot
	// route to a verifier for the configured provider.
	ErrPushProviderUnknown = errors.New("push: unknown provider")
)

// PushSignatureVerifier authenticates an inbound push notification
// from a third-party provider (Google Pub/Sub or Microsoft Graph).
//
// Implementations should be cheap to re-invoke per request and
// must be safe for concurrent use. The body is provided as a byte
// slice (already read in full from r.Body) so verifiers that need
// to inspect the payload — e.g. Microsoft Graph's clientState — can
// do so without re-reading the request.
type PushSignatureVerifier interface {
	// VerifyPush validates the request against the rules for
	// provider on behalf of tenantID. It returns nil on success and
	// one of the sentinel errors (ErrPushAuthMissing,
	// ErrPushAuthInvalid, ErrPushProviderUnknown) on failure.
	VerifyPush(ctx context.Context, provider, tenantID string, r *http.Request, body []byte) error
}

// PushSignatureRouter dispatches verification to per-provider
// verifiers based on the {provider} path parameter. A nil entry in
// the map means "accept" — used in tests / unsigned local dev — and
// MUST NOT appear in production wiring.
type PushSignatureRouter struct {
	Verifiers map[string]PushSignatureVerifier
}

// VerifyPush implements [PushSignatureVerifier] by delegating to the
// per-provider verifier. Provider names are lower-cased for the
// lookup so callers can be lenient about casing in the URL.
func (r *PushSignatureRouter) VerifyPush(ctx context.Context, provider, tenantID string, req *http.Request, body []byte) error {
	if r == nil || r.Verifiers == nil {
		return ErrPushProviderUnknown
	}
	v, ok := r.Verifiers[strings.ToLower(provider)]
	if !ok {
		return ErrPushProviderUnknown
	}
	if v == nil {
		// Explicitly-nil verifier means "accept", reserved for
		// unsigned local-dev / test wiring.
		return nil
	}
	return v.VerifyPush(ctx, provider, tenantID, req, body)
}

// --- Microsoft Graph clientState verifier ------------------------------

// MicrosoftClientStateVerifier authenticates a Microsoft Graph push
// by validating that every notification entry's clientState matches
// the per-tenant secret minted at subscription-creation time.
//
// Microsoft documents clientState as the recommended mechanism for
// validating that a notification genuinely came from a subscription
// the application created:
// https://learn.microsoft.com/graph/webhooks#client-validation .
type MicrosoftClientStateVerifier struct {
	// ExpectedFor returns the expected clientState for the given
	// tenantID. The function is supplied by the caller so the
	// secret can be rotated at runtime without restarting the
	// server. It MUST return a non-empty string for any tenant the
	// handler is willing to accept callbacks for.
	ExpectedFor func(tenantID string) string
}

// graphNotificationEnvelope is the minimal subset of the Graph
// change-notification payload needed to validate clientState. We
// re-parse the body here (rather than using a shared decoder) so the
// verifier can run before HandlePushNotification and reject
// unauthenticated payloads at the edge.
type graphNotificationEnvelope struct {
	Value []struct {
		ClientState string `json:"clientState"`
	} `json:"value"`
}

// VerifyPush implements [PushSignatureVerifier].
func (v *MicrosoftClientStateVerifier) VerifyPush(_ context.Context, _ string, tenantID string, _ *http.Request, body []byte) error {
	if v == nil || v.ExpectedFor == nil {
		return ErrPushAuthMissing
	}
	expected := v.ExpectedFor(tenantID)
	if expected == "" {
		// No secret registered for this tenant: refuse to accept
		// the callback rather than implicitly trusting it. This
		// preserves the closed-by-default invariant if a tenant is
		// removed but its subscription URL is still being called.
		return ErrPushAuthMissing
	}
	if len(body) == 0 {
		return ErrPushAuthMissing
	}
	var env graphNotificationEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("%w: unmarshal notification body: %v", ErrPushAuthInvalid, err)
	}
	if len(env.Value) == 0 {
		// Graph occasionally sends empty notification batches
		// (e.g. lifecycle/heartbeat). Treating those as
		// authenticated would let any unauthenticated caller
		// trigger our 200 OK path; instead require at least one
		// validated entry.
		return ErrPushAuthMissing
	}
	for i, entry := range env.Value {
		// Constant-time comparison via crypto/subtle so verifiers
		// cannot be turned into a clientState oracle by an attacker
		// timing per-byte mismatches. crypto/subtle is documented
		// to run in constant time even for unequal-length inputs
		// (the function returns 0 immediately on length mismatch
		// rather than walking the longer slice, which is fine for
		// our threat model because the expected length is fixed
		// per tenant and not attacker-derived).
		if subtle.ConstantTimeCompare([]byte(entry.ClientState), []byte(expected)) != 1 {
			return fmt.Errorf("%w: clientState mismatch at value[%d]", ErrPushAuthInvalid, i)
		}
	}
	return nil
}

// --- Google Pub/Sub OIDC verifier --------------------------------------

// GoogleJWKS describes the subset of Google's JWKS endpoint required
// to verify RS256 OIDC tokens.
type GoogleJWKS struct {
	Keys []GoogleJWK `json:"keys"`
}

// GoogleJWK is one RS256 entry from Google's JWKS endpoint.
type GoogleJWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// GoogleOIDCVerifier validates the Authorization bearer token that
// Google Pub/Sub attaches to push deliveries when the subscription
// is configured with an OIDC service account. The token's audience
// claim must equal the configured audience (typically the push
// endpoint URL); the issuer must be "https://accounts.google.com";
// the signature must verify against a Google-issued RS256 key.
//
// See https://cloud.google.com/pubsub/docs/push#authentication for
// the protocol details.
type GoogleOIDCVerifier struct {
	// Audience is the expected `aud` claim. Required.
	Audience string
	// Issuer is the expected `iss` claim. Defaults to
	// "https://accounts.google.com" when empty; can be overridden
	// in tests.
	Issuer string
	// JWKSURL is the URL fetched to discover Google's signing keys.
	// Defaults to "https://www.googleapis.com/oauth2/v3/certs".
	JWKSURL string
	// HTTPClient fetches the JWKS document. Defaults to
	// http.DefaultClient with a short timeout if nil.
	HTTPClient *http.Client
	// CacheTTL is how long a successfully-fetched JWKS document is
	// reused before a refresh. Defaults to 1 hour, matching
	// Google's documented rotation cadence.
	CacheTTL time.Duration
	// Now is overridable for tests; nil means time.Now.
	Now func() time.Time

	mu       sync.Mutex
	cache    map[string]*rsa.PublicKey
	cachedAt time.Time
	// refresh collapses concurrent JWKS-refresh fetches into a
	// single in-flight HTTP call. Without this, N concurrent
	// requests that all hit a stale cache or a missing kid each
	// independently call Google's certs endpoint, which both
	// wastes bandwidth and risks rate-limit pushback under burst
	// traffic.
	refresh singleflight.Group
}

// VerifyPush implements [PushSignatureVerifier].
func (v *GoogleOIDCVerifier) VerifyPush(ctx context.Context, _ string, _ string, r *http.Request, _ []byte) error {
	if v == nil {
		return ErrPushAuthMissing
	}
	if v.Audience == "" {
		// Mis-configured: fail closed rather than accept anything.
		return fmt.Errorf("%w: google audience not configured", ErrPushAuthMissing)
	}
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return ErrPushAuthMissing
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return fmt.Errorf("%w: Authorization header missing Bearer prefix", ErrPushAuthInvalid)
	}
	raw := strings.TrimSpace(strings.TrimPrefix(authz, prefix))
	if raw == "" {
		return ErrPushAuthMissing
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("%w: unexpected alg %q", ErrPushAuthInvalid, token.Method.Alg())
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: token missing kid header", ErrPushAuthInvalid)
		}
		key, err := v.lookupKey(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.expectedIssuer()),
		jwt.WithAudience(v.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
	)

	if _, err := parser.Parse(raw, keyFunc); err != nil {
		if errors.Is(err, ErrPushAuthInvalid) || errors.Is(err, ErrPushAuthMissing) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrPushAuthInvalid, err)
	}
	return nil
}

func (v *GoogleOIDCVerifier) expectedIssuer() string {
	if v.Issuer != "" {
		return v.Issuer
	}
	return "https://accounts.google.com"
}

func (v *GoogleOIDCVerifier) jwksURL() string {
	if v.JWKSURL != "" {
		return v.JWKSURL
	}
	return "https://www.googleapis.com/oauth2/v3/certs"
}

func (v *GoogleOIDCVerifier) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func (v *GoogleOIDCVerifier) cacheTTL() time.Duration {
	if v.CacheTTL > 0 {
		return v.CacheTTL
	}
	return time.Hour
}

func (v *GoogleOIDCVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// lookupKey returns the cached RSA public key for kid, refreshing
// the JWKS document on a miss or when the cache has expired. Key
// rotation is handled implicitly: a kid that is not in the current
// cache forces a single refresh attempt, which captures any newly
// minted keys before the cache TTL elapses.
//
// Concurrent callers that all observe a stale/missing kid are
// collapsed into a single in-flight refresh via singleflight; the
// shared key ("jwks") names the operation so every kid-miss waits on
// the same refresh.
func (v *GoogleOIDCVerifier) lookupKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	key, ok := v.cache[kid]
	fresh := v.cachedAt.Add(v.cacheTTL()).After(v.now())
	v.mu.Unlock()
	if ok && fresh {
		return key, nil
	}
	if _, err, _ := v.refresh.Do("jwks", func() (any, error) {
		return nil, v.refreshJWKS(ctx)
	}); err != nil {
		return nil, err
	}
	v.mu.Lock()
	key, ok = v.cache[kid]
	v.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrPushAuthInvalid, kid)
	}
	return key, nil
}

// refreshJWKS fetches Google's JWKS document, parses the RSA keys,
// and atomically swaps the cache. The name is no longer "…Locked"
// because the function does not run with v.mu held — singleflight
// already serialises concurrent callers, and v.mu is only taken for
// the final swap so reads do not block on the network round-trip.
func (v *GoogleOIDCVerifier) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL(), nil)
	if err != nil {
		return fmt.Errorf("%w: build JWKS request: %v", ErrPushAuthInvalid, err)
	}
	resp, err := v.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("%w: fetch JWKS: %v", ErrPushAuthInvalid, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: JWKS fetch returned HTTP %d", ErrPushAuthInvalid, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB safety cap
	if err != nil {
		return fmt.Errorf("%w: read JWKS body: %v", ErrPushAuthInvalid, err)
	}
	var jwks GoogleJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("%w: parse JWKS: %v", ErrPushAuthInvalid, err)
	}
	parsed := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		if k.Alg != "" && k.Alg != "RS256" {
			continue
		}
		pub, perr := parseRSAJWK(k.N, k.E)
		if perr != nil {
			// Ignore malformed entries individually; a real
			// rotation might publish an unfamiliar shape we
			// don't care about, and rejecting the whole
			// document would be a noisy DoS surface.
			continue
		}
		parsed[k.Kid] = pub
	}
	if len(parsed) == 0 {
		return fmt.Errorf("%w: JWKS contained no usable RS256 keys", ErrPushAuthInvalid)
	}
	v.mu.Lock()
	v.cache = parsed
	v.cachedAt = v.now()
	v.mu.Unlock()
	return nil
}

// parseRSAJWK turns the base64url-encoded modulus + exponent fields
// of a JWK entry into a usable *rsa.PublicKey. The encoding is
// defined by RFC 7518 §6.3.1 (JWA).
func parseRSAJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("empty modulus or exponent")
	}
	// Exponent: big-endian, variable length (typically 3 bytes for
	// 65537). Pad to 8 bytes for binary.BigEndian.Uint64.
	if len(eBytes) > 8 {
		return nil, fmt.Errorf("exponent too large: %d bytes", len(eBytes))
	}
	padded := make([]byte, 8)
	copy(padded[8-len(eBytes):], eBytes)
	e := int(binary.BigEndian.Uint64(padded))
	if e <= 0 {
		return nil, errors.New("non-positive exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}
