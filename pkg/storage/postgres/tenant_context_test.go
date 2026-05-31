package postgres

import (
	"context"
	"database/sql"
	"testing"
)

// TestWithBoundConn_NilConn covers the defensive branch that returns
// ctx unchanged when conn is nil — a small but important guarantee
// because middleware that opportunistically calls WithBoundConn(ctx,
// maybeNilConn) should never have to nil-check itself.
func TestWithBoundConn_NilConn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	out := WithBoundConn(ctx, nil)
	if out != ctx {
		t.Fatalf("WithBoundConn(_, nil) must return the original ctx; got a derived ctx")
	}
	if got := BoundConnFromContext(out); got != nil {
		t.Fatalf("BoundConnFromContext on a ctx with no bound conn must return nil; got %v", got)
	}
}

// TestBoundConnFromContext_Unset asserts the read path returns nil
// (not a panic, not the zero value of *sql.Conn cast from something
// arbitrary) when nothing has been bound.
func TestBoundConnFromContext_Unset(t *testing.T) {
	t.Parallel()
	if got := BoundConnFromContext(context.Background()); got != nil {
		t.Fatalf("expected nil from unset ctx, got %v", got)
	}
	// nil ctx → nil conn, not a panic. This matches the defensive
	// branch in boundConnFromContext that guards against ctx==nil.
	if got := BoundConnFromContext(nil); got != nil { //nolint:staticcheck // SA1012: deliberately exercising the nil-ctx branch
		t.Fatalf("expected nil from nil ctx, got %v", got)
	}
}

// TestWithBoundConn_RoundTrip uses a non-nil *sql.Conn value as a
// sentinel — we don't dial Postgres in this unit test, we only
// verify the ctx key plumbing. We construct a *sql.Conn via the
// stdlib's sql.OpenDB on a never-pinged fake driver; the conn is
// never used for queries, only as an identity-equal sentinel that
// flows through ctx and back out again.
func TestWithBoundConn_RoundTrip(t *testing.T) {
	t.Parallel()
	// We construct a *sql.Conn by acquiring one from an *sql.DB
	// backed by the always-failing fake driver. We don't actually
	// run queries on it; it's a sentinel for identity-equality
	// checks through the ctx round-trip.
	db := sql.OpenDB(fakeConnector{})
	t.Cleanup(func() { _ = db.Close() })

	// Acquire a conn without round-tripping to a real database. The
	// fake driver's Open always returns a conn that errors on
	// every operation, so any actual query would fail; for this
	// test we only need a non-nil *sql.Conn value to thread.
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Skipf("acquire fake conn: %v (skipping ctx round-trip; the fake driver evolved)", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if conn == nil {
		t.Fatalf("acquired nil *sql.Conn from fake driver — test setup broken")
	}

	ctx := WithBoundConn(context.Background(), conn)
	got := BoundConnFromContext(ctx)
	if got != conn {
		t.Fatalf("ctx round-trip lost the conn identity: got=%p want=%p", got, conn)
	}
}

// TestWithTenant_EmptyTenantIDRejected proves the API fails closed on
// an empty tenantID rather than silently binding `”` to the GUC and
// tripping every downstream RLS check at query time. The check fires
// before we acquire a conn, so we can exercise it without a live DB.
func TestWithTenant_EmptyTenantIDRejected(t *testing.T) {
	t.Parallel()
	// Build a *DB whose underlying *sql.DB is real (we need
	// d.sqlDB != nil to clear the first guard) but is never dialled
	// — the empty-tenantID guard fires before any conn acquire.
	db := &DB{sqlDB: sql.OpenDB(fakeConnector{}), driver: "fake"}
	t.Cleanup(func() { _ = db.Close() })

	ctx, release, err := db.WithTenant(context.Background(), "")
	if err == nil {
		t.Fatalf("WithTenant(ctx, \"\") must return an error; got nil")
	}
	if ctx == nil {
		t.Fatalf("WithTenant must return the original ctx on error; got nil ctx")
	}
	if release == nil {
		t.Fatalf("WithTenant must return a non-nil ReleaseFunc even on error so callers can `defer release()`")
	}
	if relErr := release(); relErr != nil {
		t.Fatalf("noopRelease must be safe to call and return nil; got %v", relErr)
	}
}

// TestWithTenant_NilDBRejected covers the receiver-nil / uninit DB
// guard so a misuse fails loudly instead of NPE-ing on .sqlDB.Conn.
func TestWithTenant_NilDBRejected(t *testing.T) {
	t.Parallel()
	var db *DB
	ctx, release, err := db.WithTenant(context.Background(), "any-tenant")
	if err == nil {
		t.Fatalf("WithTenant on nil *DB must return an error")
	}
	if ctx == nil || release == nil {
		t.Fatalf("WithTenant must still return ctx + ReleaseFunc on error")
	}
}

// TestWithCrossTenant_NilDBRejected mirrors the above for the
// cross-tenant escape hatch.
func TestWithCrossTenant_NilDBRejected(t *testing.T) {
	t.Parallel()
	var db *DB
	ctx, release, err := db.WithCrossTenant(context.Background())
	if err == nil {
		t.Fatalf("WithCrossTenant on nil *DB must return an error")
	}
	if ctx == nil || release == nil {
		t.Fatalf("WithCrossTenant must still return ctx + ReleaseFunc on error")
	}
}
