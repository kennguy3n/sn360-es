package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// boundConnCtxKey is the unexported context-key type used to attach a
// pinned tenant-bound *sql.Conn to a request / message context. A
// typed empty struct avoids accidental clashes with any string-keyed
// values in the request context.
type boundConnCtxKey struct{}

// WithBoundConn returns ctx augmented with the supplied *sql.Conn so
// that subsequent calls to (*DB).ExecContext / QueryContext /
// QueryRowContext / BeginTx route through that single pinned conn
// instead of the connection pool.
//
// This is the linchpin of the Postgres RLS rollout in
// `migrations/0018_row_level_security.up.sql`: the policy on every
// tenant-scoped table reads `current_setting('sn360.tenant_id')`,
// which is a session-scoped GUC. Pool-acquired conns get a fresh
// session each time and have no GUC set — they would deterministically
// return zero rows. WithBoundConn lets the middleware / consumer
// dispatcher / worker bind one conn for the duration of a logical
// unit of work and run every query for that work on it.
//
// Callers MUST also be the ones to RESET the GUC and Close() the conn
// (via the cleanup func returned by WithTenant / WithCrossTenant) —
// WithBoundConn itself only smuggles the conn through ctx.
func WithBoundConn(ctx context.Context, conn *sql.Conn) context.Context {
	if conn == nil {
		return ctx
	}
	return context.WithValue(ctx, boundConnCtxKey{}, conn)
}

// boundConnFromContext returns the pinned *sql.Conn smuggled in via
// WithBoundConn, or nil if no conn is bound. The DB wrapper consults
// this from every Exec/Query/Begin call to decide whether to route
// through the pinned conn or the pool.
func boundConnFromContext(ctx context.Context) *sql.Conn {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(boundConnCtxKey{}).(*sql.Conn)
	return c
}

// BoundConnFromContext is the exported form of boundConnFromContext —
// it lets callers (e.g. middleware that needs to know whether a conn
// has already been bound on a nested context) introspect without
// having to import an internal symbol.
func BoundConnFromContext(ctx context.Context) *sql.Conn {
	return boundConnFromContext(ctx)
}

// ReleaseFunc unwinds a WithTenant / WithCrossTenant scope: it RESETs
// the session GUCs that bound the conn and Closes the conn back into
// the pool. Returning the underlying conn-close error means a caller
// who actually cares (e.g. tests, draining shutdown paths) can surface
// it; production callers usually `defer release()` and ignore the
// return.
type ReleaseFunc func() error

// WithTenant acquires a conn from the pool, binds the supplied tenant
// ID to the conn's `sn360.tenant_id` GUC, and returns:
//
//   - a derived ctx with the conn attached (see WithBoundConn);
//   - a ReleaseFunc the caller MUST `defer` to RESET the GUC and
//     return the conn to the pool;
//   - any error encountered while acquiring the conn or running the
//     SET (in which case ctx is the original ctx and ReleaseFunc is
//     a no-op safe to call).
//
// tenantID must be a non-empty UUID string. The function does not
// re-validate the UUID format — that's the caller's responsibility
// (JWTAuth already verifies the `tid` claim is a UUID via
// privacy.ActionClaims). An empty tenantID is rejected immediately so
// a typo at the call site fails loudly rather than silently binding
// `”` to the GUC and tripping every downstream RLS check.
//
// The GUC is set with is_local=false because we are NOT inside a
// transaction here — the GUC has to outlive any BeginTx the caller
// runs on the bound conn. RESET on release returns the conn to the
// pool with a clean slate so the next pool consumer doesn't inherit
// the binding.
func (d *DB) WithTenant(ctx context.Context, tenantID string) (context.Context, ReleaseFunc, error) {
	if d == nil || d.sqlDB == nil {
		return ctx, noopRelease, errors.New("postgres: WithTenant: DB is not initialised")
	}
	if tenantID == "" {
		return ctx, noopRelease, errors.New("postgres: WithTenant: tenantID is empty")
	}
	conn, err := d.sqlDB.Conn(ctx)
	if err != nil {
		return ctx, noopRelease, fmt.Errorf("postgres: WithTenant: acquire conn: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT set_config('sn360.tenant_id', $1, false)`, tenantID); err != nil {
		// Conn is unusable in an unknown state — discard rather than
		// hand it back to the pool with a partial binding.
		_ = conn.Close()
		return ctx, noopRelease, fmt.Errorf("postgres: WithTenant: set tenant_id GUC: %w", err)
	}
	release := func() error {
		// RESET on the conn before Close. We use a background ctx so
		// shutdown / cancellation of the caller's ctx does not skip
		// the RESET — the conn would otherwise return to the pool
		// still bound. Errors here are non-fatal (the conn is being
		// closed anyway) but worth bubbling up for telemetry.
		_, resetErr := conn.ExecContext(context.Background(), `RESET sn360.tenant_id`)
		closeErr := conn.Close()
		if resetErr != nil {
			return fmt.Errorf("postgres: WithTenant: reset tenant_id GUC: %w", resetErr)
		}
		return closeErr
	}
	return WithBoundConn(ctx, conn), release, nil
}

// WithCrossTenant acquires a conn from the pool and binds the
// `sn360.cross_tenant` GUC to the literal `'on'`, which makes the
// RLS policy installed by `migrations/0018_row_level_security.up.sql`
// admit rows across every tenant. Returns the bound ctx and a
// ReleaseFunc the caller MUST `defer` to RESET the GUC.
//
// This is the explicit escape hatch for genuine cross-tenant work
// (worker fan-out via IterateActive, boot-time provider-registry
// rebuild via PgTokenStore.ListAll, partition maintenance). Every
// call-site MUST be annotated with `// tenant-lint:cross-tenant` so
// the static analyser in `cmd/sn360-es-tenant-lint` accepts the
// unscoped SQL string at build time AND a code reviewer can audit
// which queries deliberately span tenants.
//
// The cleanup helper RESETs both GUCs (sn360.cross_tenant and
// sn360.tenant_id) so even if a previous WithTenant on the same conn
// was somehow short-circuited, the conn is fully scrubbed before
// returning to the pool.
func (d *DB) WithCrossTenant(ctx context.Context) (context.Context, ReleaseFunc, error) {
	if d == nil || d.sqlDB == nil {
		return ctx, noopRelease, errors.New("postgres: WithCrossTenant: DB is not initialised")
	}
	conn, err := d.sqlDB.Conn(ctx)
	if err != nil {
		return ctx, noopRelease, fmt.Errorf("postgres: WithCrossTenant: acquire conn: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT set_config('sn360.cross_tenant', 'on', false)`); err != nil {
		_ = conn.Close()
		return ctx, noopRelease, fmt.Errorf("postgres: WithCrossTenant: set cross_tenant GUC: %w", err)
	}
	release := func() error {
		_, resetCrossErr := conn.ExecContext(context.Background(), `RESET sn360.cross_tenant`)
		_, resetTenantErr := conn.ExecContext(context.Background(), `RESET sn360.tenant_id`)
		closeErr := conn.Close()
		if resetCrossErr != nil {
			return fmt.Errorf("postgres: WithCrossTenant: reset cross_tenant GUC: %w", resetCrossErr)
		}
		if resetTenantErr != nil {
			return fmt.Errorf("postgres: WithCrossTenant: reset tenant_id GUC: %w", resetTenantErr)
		}
		return closeErr
	}
	return WithBoundConn(ctx, conn), release, nil
}

// noopRelease is the zero-value ReleaseFunc returned alongside an
// error from WithTenant / WithCrossTenant so callers can
// unconditionally `defer release()` without nil-checking. Calling it
// after a successful acquire is a programmer bug — defend by always
// pairing one acquire with exactly one defer.
func noopRelease() error { return nil }
