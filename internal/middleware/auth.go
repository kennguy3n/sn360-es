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
