package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// RequireAdmin wraps next so that only requests carrying a JWT with
// `role: "admin"` (privacy.RoleAdmin) reach it. Anything else gets a
// uniform 403 with a {"error": ...} body — same shape as the
// JWTAuth 401 so client code only needs one error-decoder.
//
// JWTAuth MUST run before this middleware. If RequireAdmin is
// mounted on a path that bypasses JWTAuth (SkipPaths in
// JWTAuthConfig), it returns 403 unconditionally — the missing
// JWT means the request has no role information and we fail
// closed.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil || claims.Role != privacy.RoleAdmin {
			writeForbidden(w, "admin_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeForbidden emits the uniform 403 shape. Kept private so all
// admin-required routes share one error body.
func writeForbidden(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}
