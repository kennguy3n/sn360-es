package postgres

// Multi-region Postgres routing (WS-7a).
//
// RegionalDB owns one *DB per region plus a "home" region whose pool
// is shared with the primary single-region *DB the rest of the
// application already holds. The wiring contract:
//
//   - In single-region deployments (PG_REGION_MAP empty), the
//     application keeps using its primary *DB directly. No RegionalDB
//     is constructed; the middleware / consumer wrapper sees a nil
//     RegionalDB and falls back to db.WithTenant on the primary pool,
//     EXACTLY the existing single-region code path.
//
//   - In multi-region deployments, the wiring layer opens a *DB for
//     each entry in PG_REGION_MAP, hands the home-region entry to
//     RegionalDB (which reuses the primary *DB instance — no double
//     open against the same host), and wraps the remaining regional
//     *DB instances inside the same RegionalDB. WithTenantInRegion
//     looks up the right pool, runs WithTenant on it, and returns a
//     ctx carrying a tenant-bound conn from the regional pool.
//
// The conn from boundConnFromContext travels in ctx unchanged, so
// downstream code that calls primary.QueryContext(ctx, …) still
// routes through the regional bound conn. This is the property that
// keeps the RLS contract intact across regions: every query for a
// tenant runs on a conn bound to that tenant's region's pool.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
)

// RegionalDB is the multi-region router for tenant-bound Postgres
// connections. It is constructed by the wiring layer in
// cmd/sn360-es/app.go from a parsed PG_REGION_MAP plus an already-
// open primary *DB; the constructor reuses the primary *DB instance
// for the home region so we do not double-open against the same
// physical host.
//
// All exported methods are safe for concurrent use after
// construction. The internal map is not mutated post-New, so the
// type holds no mutex.
type RegionalDB struct {
	byRegion   map[string]*DB
	homeRegion string
	// owned tracks which regional *DB instances were created by
	// New (and must be closed by Close), versus the home-region
	// *DB which is shared with the primary and owned by the
	// wiring layer.
	owned map[string]bool
}

// NewRegionalDB constructs a RegionalDB from a home-region label, a
// shared primary *DB (used for the home region — typically the same
// instance the application already holds), and a region -> *DB map
// for any additional regions. The primary *DB is NOT closed by
// (*RegionalDB).Close — the wiring layer that opened it owns its
// lifecycle. Additional regional *DB instances passed in extras ARE
// closed by Close so a clean process shutdown drains every regional
// pool.
//
// Returns an error when:
//
//   - primary is nil.
//   - homeRegion is empty.
//   - extras contains an entry whose key equals homeRegion (that
//     entry would shadow the primary *DB and double-open against the
//     home-region host).
//   - extras contains a nil *DB value (the wiring layer should not
//     be calling NewRegionalDB until every regional pool successfully
//     opened — a nil here means the wiring contract was violated).
func NewRegionalDB(homeRegion string, primary *DB, extras map[string]*DB) (*RegionalDB, error) {
	if primary == nil {
		return nil, errors.New("postgres: NewRegionalDB: primary *DB must not be nil")
	}
	if homeRegion == "" {
		return nil, errors.New("postgres: NewRegionalDB: homeRegion must not be empty")
	}
	if _, ok := extras[homeRegion]; ok {
		return nil, fmt.Errorf("postgres: NewRegionalDB: extras must not contain home region %q (would double-open against the primary host)", homeRegion)
	}
	byRegion := make(map[string]*DB, len(extras)+1)
	owned := make(map[string]bool, len(extras)+1)
	byRegion[homeRegion] = primary
	owned[homeRegion] = false
	for region, db := range extras {
		if region == "" {
			return nil, errors.New("postgres: NewRegionalDB: region name must not be empty")
		}
		if db == nil {
			return nil, fmt.Errorf("postgres: NewRegionalDB: extras[%s] is nil (the wiring layer must open every regional pool before calling NewRegionalDB)", region)
		}
		byRegion[region] = db
		owned[region] = true
	}
	return &RegionalDB{
		byRegion:   byRegion,
		homeRegion: homeRegion,
		owned:      owned,
	}, nil
}

// HomeRegion returns the home-region label.
func (r *RegionalDB) HomeRegion() string {
	if r == nil {
		return ""
	}
	return r.homeRegion
}

// Regions returns the configured region names in lexicographic order
// (stable boot-log output, deterministic readiness probe payloads).
func (r *RegionalDB) Regions() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.byRegion))
	for region := range r.byRegion {
		out = append(out, region)
	}
	sort.Strings(out)
	return out
}

// DBForRegion returns the *DB serving the supplied region, or nil
// when the region is not configured. Callers MUST treat nil as a
// fail-closed signal (e.g. middleware rejects the request) — silently
// routing an unknown region to the home pool would defeat the
// data-residency contract the region map encodes.
func (r *RegionalDB) DBForRegion(region string) *DB {
	if r == nil {
		return nil
	}
	return r.byRegion[region]
}

// HasRegion reports whether the supplied region has a pool wired.
func (r *RegionalDB) HasRegion(region string) bool {
	return r.DBForRegion(region) != nil
}

// WithTenantInRegion routes the tenant binding through the regional
// pool corresponding to region. It is the multi-region analogue of
// (*DB).WithTenant — same signature, same release-func contract,
// same RLS guarantees (the bound conn is from the regional pool's
// write side, and the GUC set is scrubbed on release).
//
// Returns an error WITHOUT acquiring a conn when:
//
//   - r is nil (programmer bug — the wiring layer should not be
//     calling WithTenantInRegion on a nil RegionalDB).
//   - region is empty (the resolver returned an empty string — also
//     a programmer bug; the resolver's contract is to error on
//     missing/unknown tenants rather than return "").
//   - region is not in the configured map. The error names the
//     missing region and the configured set so an operator can
//     diff their PG_REGION_MAP against the tenant's region claim.
//
// The returned (ctx, release, err) tuple matches (*DB).WithTenant
// exactly, so call-sites can swap one for the other without churn.
func (r *RegionalDB) WithTenantInRegion(ctx context.Context, region, tenantID string) (context.Context, ReleaseFunc, error) {
	if r == nil {
		return ctx, noopRelease, errors.New("postgres: WithTenantInRegion: RegionalDB is nil")
	}
	if region == "" {
		return ctx, noopRelease, errors.New("postgres: WithTenantInRegion: region must not be empty")
	}
	db := r.DBForRegion(region)
	if db == nil {
		return ctx, noopRelease, fmt.Errorf("postgres: WithTenantInRegion: region %q is not configured (configured regions: %v)", region, r.Regions())
	}
	return db.WithTenant(ctx, tenantID)
}

// Close shuts down every regional pool that RegionalDB OWNS (those
// passed in via extras at construction time). The home-region *DB
// is NOT closed here because it is shared with the primary the
// wiring layer holds; the wiring layer's own deferred Close handles
// the primary pool. Errors from individual pool closes are joined
// into a single multi-error so the boot/shutdown log reports every
// failure, not just the first.
func (r *RegionalDB) Close() error {
	if r == nil {
		return nil
	}
	var errs []error
	for _, region := range r.Regions() {
		if !r.owned[region] {
			continue
		}
		if err := r.byRegion[region].Close(); err != nil {
			errs = append(errs, fmt.Errorf("region %s: %w", region, err))
		}
	}
	return errors.Join(errs...)
}

// PingContext pings every regional pool and joins the errors. Used
// by the readiness probe so an operator can see at a glance which
// regions are healthy and which are not.
func (r *RegionalDB) PingContext(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var errs []error
	for _, region := range r.Regions() {
		if err := r.byRegion[region].PingContext(ctx); err != nil {
			errs = append(errs, fmt.Errorf("region %s: %w", region, err))
		}
	}
	return errors.Join(errs...)
}

// LogBoot writes a structured summary of the regional topology at
// boot. Separated from construction so the wiring layer can pass a
// real *slog.Logger after it has been wired with the standard
// SN360-ES attributes (service, environment, etc.). The boot log is
// the operator's single-glance confirmation that multi-region
// routing is active and which regions are visible.
func (r *RegionalDB) LogBoot(logger *slog.Logger) {
	if r == nil || logger == nil {
		return
	}
	logger.Info("sn360-es: postgres multi-region routing active",
		slog.String("home_region", r.homeRegion),
		slog.Any("regions", r.Regions()),
	)
}
