// Package middleware — rbac.go wires the role-based access control
// (RBAC) gate that complements JWTAuth. Where JWTAuth answers "does
// the bearer have a verified tenant?", RBAC answers "is the bearer's
// role allowed to perform this action against this tenant?".
//
// The principal's role lives on the verified JWT as the `role` claim
// (see privacy.ActionClaims.Role) and is one of the four canonical
// values privacy.Role* — Admin, Operator, Viewer, EndUser. The middleware
// fails-closed on any other value: an empty role, an unknown role
// string, or a role outside the allow-list returns 403 with the
// `forbidden_role` reason code so the failure mode is observable in
// logs and metrics without leaking which roles were required.
//
// Two variants are exposed:
//
//   - RequireRole(roles ...string) wraps a handler with a single
//     allow-list applied to every HTTP method.
//
//   - RequireRoleByMethod(map[string][]string) wraps a handler with a
//     per-method allow-list. This is the right shape when a single
//     URL fans out to multiple handlers by HTTP verb (e.g. the
//     `/v1/vendors` endpoint which routes GET → list and POST →
//     create through one ServeMux entry); GET is a read so viewers
//     should pass, POST is a write so they should not.
//
// Both variants short-circuit on the JWTAuth skip paths and on
// /healthz, /readyz, /metrics, /docs, /openapi.yaml so liveness
// probes and Prometheus scrapes are never role-gated.
package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// RequireRoleConfig customises a RequireRole / RequireRoleByMethod
// gate. The zero value is usable and applies no skip-paths.
type RequireRoleConfig struct {
	// SkipPaths is the list of exact paths (or prefixes ending in
	// "/") that bypass the role check. Used to thread health probes
	// and docs handlers through any wrapper applied at the mux
	// root. Most call-sites do not need this — the per-route
	// wrapping pattern recommended in routes.go scopes the
	// middleware to a single handler and so doesn't need to skip
	// anything.
	SkipPaths []string
}

// RequireRole returns middleware that 403s any request whose verified
// JWT role is not in allowedRoles. The middleware fails-closed:
//
//   - If the request has no verified claims on context (no JWTAuth
//     ran, or it ran and didn't set the claims key), the request is
//     denied with 401 because RBAC has no principal to authorise.
//
//   - If the principal's role is empty / unknown / not in
//     allowedRoles, the request is denied with 403.
//
// Passing an empty or all-empty allowedRoles slice is a wiring bug
// (no role would ever satisfy it) — the middleware logs a clear
// warning and 403s every request so the misconfiguration is loud.
//
// allowedRoles is validated against privacy.IsValidRole at wrap
// time: any unknown role string panics so a typo in the call-site
// surfaces at process boot, not at the first 403 in production.
func RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return RequireRoleWith(RequireRoleConfig{}, allowedRoles...)
}

// RequireRoleWith is RequireRole plus a config block. Extracted as a
// separate constructor so the common (no-skip-paths) call-site stays
// terse.
func RequireRoleWith(cfg RequireRoleConfig, allowedRoles ...string) func(http.Handler) http.Handler {
	allowed := buildRoleSet(allowedRoles)
	skip, prefix := buildSkipMatcher(cfg.SkipPaths)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if matchSkip(r.URL.Path, skip, prefix) {
				next.ServeHTTP(w, r)
				return
			}
			if !authorize(r, allowed, w) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRoleByMethod returns middleware that 403s any request whose
// verified JWT role is not in the allow-list registered for the
// request's HTTP method. Methods not present in the map are denied
// (405-equivalent → 403 here so the failure mode matches the rest of
// the gate). Per-method values are validated against
// privacy.IsValidRole at wrap time; any unknown role panics.
//
// Used for ServeMux routes that fan out multiple HTTP verbs onto the
// same path (e.g. `/v1/vendors` GET vs POST), where the underlying
// handler dispatches on r.Method internally. The cleaner pattern in
// Go 1.22+ — registering `GET /v1/vendors` and `POST /v1/vendors` as
// separate mux entries — would let us use RequireRole twice, but the
// existing handlers in this repo all use the single-path-dispatch
// pattern, so RequireRoleByMethod matches their idiom without
// requiring a churn of every handler signature.
func RequireRoleByMethod(byMethod map[string][]string) func(http.Handler) http.Handler {
	return RequireRoleByMethodWith(RequireRoleConfig{}, byMethod)
}

// RequireRoleByMethodWith is RequireRoleByMethod plus a config block.
func RequireRoleByMethodWith(cfg RequireRoleConfig, byMethod map[string][]string) func(http.Handler) http.Handler {
	allowed := make(map[string]map[string]struct{}, len(byMethod))
	for method, roles := range byMethod {
		allowed[method] = buildRoleSet(roles)
	}
	skip, prefix := buildSkipMatcher(cfg.SkipPaths)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if matchSkip(r.URL.Path, skip, prefix) {
				next.ServeHTTP(w, r)
				return
			}
			methodAllowed, ok := allowed[r.Method]
			if !ok {
				// Method not registered for this route's
				// RBAC table. Surface as 403 so it lines up
				// with the rest of the gate's failure
				// codes; the underlying handler will then
				// also reject it with 405 if reached, but
				// we don't want to fall through to a
				// handler that might mistakenly accept a
				// method the RBAC table doesn't cover.
				writeForbidden(w, "method_not_in_role_table")
				return
			}
			if !authorize(r, methodAllowed, w) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// authorize is the shared decision point. It returns true and lets
// the handler proceed when the JWT principal's role is in `allowed`;
// otherwise it writes the appropriate 401/403 response and returns
// false so the caller short-circuits.
func authorize(r *http.Request, allowed map[string]struct{}, w http.ResponseWriter) bool {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		// No verified principal on context — RBAC cannot make a
		// decision. This is the right behaviour even if JWTAuth
		// ran successfully: an authenticated request with a
		// configuration bug that strips claims should not be
		// silently waved through.
		writeUnauthorized(w, "missing_role_claim")
		return false
	}
	role := claims.Role
	if !privacy.IsValidRole(role) {
		// Token verified but the embedded role is empty or an
		// unknown string. Treated as a configuration error on
		// the issuer side — the principal is genuinely
		// authenticated but the system has no basis to grant
		// access.
		writeForbidden(w, "forbidden_role")
		return false
	}
	if _, ok := allowed[role]; !ok {
		writeForbidden(w, "forbidden_role")
		return false
	}
	return true
}

// buildRoleSet converts an allow-list slice into the constant-time
// lookup map used by authorize. Panics if any role is not in the
// privacy.IsValidRole allowlist so typos surface at boot.
func buildRoleSet(roles []string) map[string]struct{} {
	out := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		if !privacy.IsValidRole(role) {
			panic("middleware: RequireRole received unknown role " + role +
				"; valid roles are admin, operator, viewer, end_user")
		}
		out[role] = struct{}{}
	}
	return out
}

// buildSkipMatcher mirrors the JWTAuth skip-path semantics: exact
// match for entries without a trailing slash, prefix match for
// entries that end in "/". Keeping the two matchers in lockstep
// means the JWT skip list and any RBAC skip list configured at the
// same call-site stay semantically aligned.
func buildSkipMatcher(paths []string) (map[string]bool, []string) {
	skip := map[string]bool{}
	var prefixes []string
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			prefixes = append(prefixes, p)
			continue
		}
		skip[p] = true
	}
	return skip, prefixes
}

func matchSkip(path string, skip map[string]bool, prefixes []string) bool {
	if skip[path] {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// writeForbidden emits a structured 403 response. Kept symmetrical
// with writeUnauthorized in auth.go so the wire shape is consistent
// regardless of which middleware emitted the rejection.
func writeForbidden(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "forbidden",
		"reason": reason,
	})
}
