package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// ctxKey is the unexported context-key type for middleware-injected
// values. Using a typed key avoids accidental clashes with handler-
// level context keys that might use a bare string.
type ctxKey string

const (
	// ctxKeyTenantID carries the tenant_id (`tid` JWT claim) once a
	// request has been authenticated.
	ctxKeyTenantID ctxKey = "sn360.tenant_id"
	// ctxKeyClaims carries the full privacy.ActionClaims for handlers
	// that need richer assertions (e.g. message_id, tier).
	ctxKeyClaims ctxKey = "sn360.claims"
)

// TenantIDFromContext returns the authenticated tenant ID from ctx or
// "" if the request was unauthenticated (or hit a skipped path).
func TenantIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyTenantID).(string)
	return v
}

// ContextWithTenantID returns ctx augmented with the supplied tenantID
// under the same key JWTAuth uses to inject the verified claim. It is
// the inverse of TenantIDFromContext and is intended for two specific
// call-sites:
//
//   - tests, which need to seed an authenticated request context
//     without standing up a real JWT issuer; and
//   - internal callers (e.g. event-bus consumers) that have already
//     verified the tenant via the message header and want to make it
//     available to downstream handler-style code that reads from
//     context.
//
// Production callers MUST treat the tenantID as already-verified —
// e.g. consumers extract it from a signed message header, not from
// the message body. See cmd/sn360-es/consumers.go's verifiedTenantID
// helper for the producer-side pattern.
//
// Outside those two cases, the JWT middleware is the only thing that
// should set this key. Setting it from a request handler that
// otherwise reads it would be a bypass of the auth check.
func ContextWithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, ctxKeyTenantID, tenantID)
}

// ContextWithClaims returns ctx augmented with the supplied JWT
// claims under the same key JWTAuth uses. The same authentication
// caveats as ContextWithTenantID apply — production callers MUST
// have already verified the claims (e.g. via a signed event-bus
// envelope); tests use this helper to seed an authenticated request
// context without standing up an issuer.
//
// When non-nil, the function also seeds the tenant_id context key
// from claims.TenantID so handler-level helpers (which read
// TenantIDFromContext) keep working without a second call.
func ContextWithClaims(ctx context.Context, claims *privacy.ActionClaims) context.Context {
	if claims == nil {
		return ctx
	}
	ctx = context.WithValue(ctx, ctxKeyClaims, claims)
	if claims.TenantID != "" {
		ctx = context.WithValue(ctx, ctxKeyTenantID, claims.TenantID)
	}
	return ctx
}

// ClaimsFromContext returns the full JWT claims if the request was
// authenticated, or nil otherwise.
func ClaimsFromContext(ctx context.Context) *privacy.ActionClaims {
	v, _ := ctx.Value(ctxKeyClaims).(*privacy.ActionClaims)
	return v
}

// JWTAuthConfig wires JWTAuth.
type JWTAuthConfig struct {
	// Issuer verifies tokens. Must be non-nil.
	Issuer *privacy.JWTIssuer
	// SkipPaths is the list of exact paths that bypass auth (health
	// probes, docs, metrics). Paths are matched verbatim, with one
	// exception: a trailing "/" makes the entry a prefix match so
	// "/docs/" also covers "/docs/swagger.css".
	SkipPaths []string
}

// JWTAuth validates the `Authorization: Bearer <token>` header on every
// incoming request, extracting the tenant_id claim and forwarding it to
// downstream handlers via request context. Requests hitting paths in
// SkipPaths bypass authentication.
type JWTAuth struct {
	next   http.Handler
	issuer *privacy.JWTIssuer
	skip   map[string]bool
	prefix []string
}

// NewJWTAuth wraps next. The default SkipPaths list ("/healthz",
// "/readyz", "/metrics", "/docs", "/openapi.yaml") is applied when
// cfg.SkipPaths is nil.
func NewJWTAuth(next http.Handler, cfg JWTAuthConfig) *JWTAuth {
	skip := map[string]bool{}
	var prefixes []string
	paths := cfg.SkipPaths
	if paths == nil {
		paths = []string{"/healthz", "/readyz", "/metrics", "/docs", "/docs/", "/openapi.yaml"}
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			prefixes = append(prefixes, p)
			continue
		}
		skip[p] = true
	}
	return &JWTAuth{next: next, issuer: cfg.Issuer, skip: skip, prefix: prefixes}
}

// ServeHTTP implements http.Handler.
func (j *JWTAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if j.isSkipped(r.URL.Path) {
		j.next.ServeHTTP(w, r)
		return
	}
	// Issuer not wired (test / dev) — fail closed so missing config
	// never accidentally opens the API.
	if j.issuer == nil {
		writeUnauthorized(w, "missing_auth_configuration")
		return
	}
	tok := extractBearer(r)
	if tok == "" {
		writeUnauthorized(w, "missing_token")
		return
	}
	claims, err := j.issuer.Verify(tok)
	if err != nil {
		writeUnauthorized(w, "invalid_token")
		return
	}
	if claims.TenantID == "" {
		writeUnauthorized(w, "missing_tenant_claim")
		return
	}
	ctx := r.Context()
	ctx = context.WithValue(ctx, ctxKeyTenantID, claims.TenantID)
	ctx = context.WithValue(ctx, ctxKeyClaims, claims)
	j.next.ServeHTTP(w, r.WithContext(ctx))
}

func (j *JWTAuth) isSkipped(path string) bool {
	if j.skip[path] {
		return true
	}
	for _, p := range j.prefix {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// extractBearer pulls the bearer token from the Authorization header.
// Returns "" when the header is missing or malformed.
func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// writeUnauthorized emits a structured 401 response. The reason code is
// intentionally short (no PII) so it can flow into logs and metrics.
func writeUnauthorized(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="sn360-es"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "unauthorized",
		"reason": reason,
	})
}
