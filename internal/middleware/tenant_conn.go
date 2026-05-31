package middleware

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// TenantConnConfig wires TenantConnBinder.
type TenantConnConfig struct {
	// DB is the Postgres pool used to acquire the per-request bound
	// conn. May be nil — in that case TenantConnBinder is a no-op
	// pass-through, which is the right behaviour for dev/test runs
	// that wire up the HTTP stack without a real database (e.g.
	// in-memory repositories, unit tests of route registration).
	DB *postgres.DB
	// Logger receives any failure to acquire a conn or set the
	// tenant GUC. The request is rejected with 500 in that case
	// because RLS would silently zero-out reads on an unbound
	// session — failing closed at the middleware boundary is
	// safer than serving a request that quietly sees no data.
	Logger *slog.Logger
	// SkipPaths reuses the same skip-list convention as JWTAuth —
	// any request whose path matches an exact entry or a "/foo/"
	// prefix bypasses tenant-conn binding. Required for unauthed
	// probes (/healthz, /metrics) that have no tenant context.
	SkipPaths []string
}

// TenantConnBinder is the HTTP middleware that activates Postgres
// Row-Level Security on a per-request basis:
//
//  1. It runs AFTER JWTAuth so the request context already carries a
//     verified `tenant_id`.
//  2. It acquires a *sql.Conn from the pool, runs
//     `SELECT set_config('sn360.tenant_id', <tid>, false)` on it,
//     and attaches the bound conn to the request context via
//     postgres.WithBoundConn.
//  3. The downstream handler chain then runs every query through the
//     bound conn (see pkg/storage/postgres/postgres.go's
//     ExecContext / QueryContext fast path), so the RLS policy
//     installed by `migrations/0018_row_level_security.up.sql`
//     evaluates with the request's tenant in scope.
//  4. On response completion the deferred ReleaseFunc RESETs the GUC
//     and returns the conn to the pool.
//
// Without this middleware, every authenticated request would acquire
// a fresh pool conn for each query — the GUC would be unset and the
// RLS policy would deterministically return zero rows. Failing closed
// at the binding step (5xx on acquire-conn failure) is preferable to
// silently serving empty responses to a real user.
type TenantConnBinder struct {
	next   http.Handler
	db     *postgres.DB
	logger *slog.Logger
	skip   map[string]bool
	prefix []string
}

// NewTenantConnBinder wraps next.
func NewTenantConnBinder(next http.Handler, cfg TenantConnConfig) *TenantConnBinder {
	skip := map[string]bool{}
	var prefixes []string
	for _, p := range cfg.SkipPaths {
		if len(p) > 0 && p[len(p)-1] == '/' {
			prefixes = append(prefixes, p)
			continue
		}
		skip[p] = true
	}
	logger := cfg.Logger
	if logger == nil {
		// Discard rather than nil-dereference; the binder is
		// otherwise safe to wire with a zero-value logger field.
		logger = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	return &TenantConnBinder{
		next:   next,
		db:     cfg.DB,
		logger: logger,
		skip:   skip,
		prefix: prefixes,
	}
}

// ServeHTTP implements http.Handler.
func (t *TenantConnBinder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Skip when the binder is not wired (dev / tests with no DB) or
	// when the path is in the skip list (health probes, docs).
	if t.db == nil || t.isSkipped(r.URL.Path) {
		t.next.ServeHTTP(w, r)
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		// No tenant on the request — e.g. JWTAuth was bypassed
		// for this route or the test stubbed it out. Pass through
		// without binding; the downstream handler is responsible
		// for refusing the request if it needs a tenant.
		t.next.ServeHTTP(w, r)
		return
	}
	ctx, release, err := t.db.WithTenant(r.Context(), tenantID)
	if err != nil {
		t.logger.WarnContext(r.Context(), "sn360-es: tenant_conn: bind failed",
			slog.String("tenant_id", tenantID), slog.Any("error", err))
		writeTenantBindError(w)
		return
	}
	defer func() {
		if relErr := release(); relErr != nil {
			t.logger.WarnContext(r.Context(), "sn360-es: tenant_conn: release failed",
				slog.String("tenant_id", tenantID), slog.Any("error", relErr))
		}
	}()
	t.next.ServeHTTP(w, r.WithContext(ctx))
}

func (t *TenantConnBinder) isSkipped(path string) bool {
	if t.skip[path] {
		return true
	}
	for _, p := range t.prefix {
		if len(path) >= len(p) && path[:len(p)] == p {
			return true
		}
	}
	return false
}

// writeTenantBindError emits a JSON 500 mirroring the shape JWTAuth
// uses for its `*_token` errors, so SDK clients can branch on the
// `code` field consistently.
func writeTenantBindError(w http.ResponseWriter) {
	const body = `{"error":"internal_error","code":"tenant_bind_failed"}`
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(body))
}

// discardWriter is an io.Writer that swallows all writes. Used as a
// fallback when no logger is configured — the middleware still runs,
// the diagnostics just go nowhere.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// errTenantBindFailed is exported only as a documentation marker —
// production callers branch on HTTP status, not this sentinel. It's
// referenced from tests that want to assert binder behaviour without
// reaching for raw status codes.
var errTenantBindFailed = errors.New("tenant_bind_failed")

// ErrTenantBindFailed exposes the sentinel above.
func ErrTenantBindFailed() error { return errTenantBindFailed }
