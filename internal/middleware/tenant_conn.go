package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// RegionResolver is the small interface TenantConnBinder consumes to
// route a tenant's request to its regional pool (WS-7a). The real
// implementation lives in internal/service/tenant.CachedRegionResolver
// — the middleware accepts the interface so the package stays
// dependency-free of the resolver implementation. Returning a
// non-empty region and a nil error binds the request to that region's
// pool; any error fails closed with 5xx so the downstream handler
// does not see a misrouted request.
type RegionResolver interface {
	ResolveRegion(ctx context.Context, tenantID string) (string, error)
}

// TenantConnConfig wires TenantConnBinder.
type TenantConnConfig struct {
	// DB is the Postgres pool used to acquire the per-request bound
	// conn. May be nil — in that case TenantConnBinder is a no-op
	// pass-through, which is the right behaviour for dev/test runs
	// that wire up the HTTP stack without a real database (e.g.
	// in-memory repositories, unit tests of route registration).
	DB *postgres.DB
	// Regional, when non-nil, switches the binder into WS-7a
	// multi-region mode: tenant_id -> region via Resolver, then
	// region -> *DB via Regional.WithTenantInRegion. Leaving
	// Regional nil keeps the single-region code path — the default
	// for every deployment that has not set PG_REGION_MAP.
	Regional *postgres.RegionalDB
	// Resolver maps a tenant id to its region label. Required when
	// Regional is non-nil; ignored otherwise. The wiring layer
	// passes a CachedRegionResolver backed by the home-region
	// TenantRepository.
	Resolver RegionResolver
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
	next     http.Handler
	db       *postgres.DB
	regional *postgres.RegionalDB
	resolver RegionResolver
	logger   *slog.Logger
	skip     map[string]bool
	prefix   []string
}

// NewTenantConnBinder wraps next. Returns an error when the
// multi-region inputs are partially wired (Regional != nil with
// Resolver == nil, or the inverse) — a wiring-layer mistake that
// would otherwise silently fall back to the home-region pool for
// every tenant and violate data residency. Both fields must be
// supplied together or both must be nil (single-region mode).
func NewTenantConnBinder(next http.Handler, cfg TenantConnConfig) (*TenantConnBinder, error) {
	if (cfg.Regional == nil) != (cfg.Resolver == nil) {
		return nil, errors.New("middleware: TenantConnConfig.Regional and TenantConnConfig.Resolver must be set together (partial multi-region wiring would silently fall back to the home-region pool and violate data residency)")
	}
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
		next:     next,
		db:       cfg.DB,
		regional: cfg.Regional,
		resolver: cfg.Resolver,
		logger:   logger,
		skip:     skip,
		prefix:   prefixes,
	}, nil
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
	ctx, release, err := t.bind(r.Context(), tenantID)
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

// noopReleaseFunc is returned on every error path from bind / BindTenant so
// callers can unconditionally `defer release()` without nil-checking the
// release function — matching the convention enforced by
// (*postgres.DB).WithTenant / WithCrossTenant and
// (*postgres.RegionalDB).WithTenantInRegion (see noopRelease in
// pkg/storage/postgres/tenant_context.go:237). The middleware package
// can't reference the unexported noopRelease in postgres, so we declare
// a local equivalent — both forms compile to the same nil-error no-op.
func noopReleaseFunc() error { return nil }

// bind dispatches between the single-region path (t.db.WithTenant) and
// the multi-region path (resolve region -> t.regional.WithTenantInRegion).
// Extracted so the consumer-side wrapper in cmd/sn360-es/consumers.go
// can share the same routing decision via BindTenant.
//
// Returns noopReleaseFunc on every error path so callers may
// unconditionally `defer release()` — matches the postgres-layer
// convention used by WithTenant / WithCrossTenant / WithTenantInRegion.
func (t *TenantConnBinder) bind(ctx context.Context, tenantID string) (context.Context, postgres.ReleaseFunc, error) {
	if t.regional != nil && t.resolver != nil {
		region, err := t.resolver.ResolveRegion(ctx, tenantID)
		if err != nil {
			return ctx, noopReleaseFunc, err
		}
		return t.regional.WithTenantInRegion(ctx, region, tenantID)
	}
	// Single-region path. ServeHTTP guards t.db == nil at line 128
	// by passing the request through unbound (the right behaviour
	// for dev / unit-test wiring with no real DB); BindTenant has
	// no "pass through" notion — a caller asking for a bound conn
	// expects either one or a clear error. Surface the missing-DB
	// misconfig as a middleware-level error instead of relying on
	// (*postgres.DB).WithTenant's nil-receiver handling, so the
	// error message identifies the actual problem (no DB wired)
	// rather than the symptom (nil receiver method call).
	if t.db == nil {
		return ctx, noopReleaseFunc, errors.New("middleware: TenantConnBinder has no DB configured")
	}
	return t.db.WithTenant(ctx, tenantID)
}

// BindTenant exposes the binder's bind decision to non-HTTP call-sites
// (the NATS consumer wrapper in cmd/sn360-es/consumers.go in
// particular) so HTTP and consumer paths route through the same
// single-region / multi-region branch. The signature mirrors
// (*postgres.DB).WithTenant exactly — including the contract that
// the returned ReleaseFunc is non-nil even on error.
func (t *TenantConnBinder) BindTenant(ctx context.Context, tenantID string) (context.Context, postgres.ReleaseFunc, error) {
	if t == nil {
		return ctx, noopReleaseFunc, errors.New("middleware: TenantConnBinder is nil")
	}
	return t.bind(ctx, tenantID)
}

// Resolver returns the RegionResolver this binder was constructed with,
// or nil for a single-region binder. Exposed so the HTTP-path binder
// in wrapMiddleware (cmd/sn360-es/routes.go) can be constructed with
// the same resolver as the shared NATS-consumer binder — preserving
// the invariant that both entrypoints route through identical region
// resolution.
func (t *TenantConnBinder) Resolver() RegionResolver {
	if t == nil {
		return nil
	}
	return t.resolver
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
