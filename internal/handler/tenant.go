package handler

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/middleware"
)

// resolveTenant determines the effective tenant for a tenant-scoped read
// endpoint, treating the JWT-bound tenant as authoritative.
//
// The bound tenant (set by the JWTAuth/TenantConnBinder middleware) is
// the tenant whose rows Postgres RLS will actually expose, so it always
// wins. When it is present we use it and reject any query `tenant_id`
// that disagrees with a 403 — defence in depth so a caller can never
// even appear to request another tenant's data, on top of RLS already
// returning zero rows for a mismatched bind. When no bound tenant is
// present (in-memory/dev deployments on the auth-skip path) we fall back
// to the query param.
//
// On a policy failure it writes the response (403 on mismatch, 400 when
// no tenant can be determined) and returns ok=false; callers MUST stop
// processing the request when ok is false.
//
// This is shared by the dashboard and education-analytics handlers so
// the two endpoints can't drift apart on tenant enforcement.
func resolveTenant(w http.ResponseWriter, r *http.Request, logger *slog.Logger) (tenantID string, ok bool) {
	queryTenant := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	boundTenant := middleware.TenantIDFromContext(r.Context())

	tenantID = boundTenant
	if boundTenant == "" {
		tenantID = queryTenant
	} else if queryTenant != "" && queryTenant != boundTenant {
		logger.WarnContext(r.Context(), "tenant mismatch: query tenant_id disagrees with authenticated tenant",
			slog.String("bound_tenant", boundTenant),
			slog.String("query_tenant", queryTenant),
		)
		writeError(w, http.StatusForbidden, "tenant_id does not match authenticated tenant")
		return "", false
	}
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id is required")
		return "", false
	}
	return tenantID, true
}
