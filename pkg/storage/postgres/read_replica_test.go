package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// TestDB_QueryRouting_NoReader exercises the WS-2a routing matrix
// (see the QueryContext doc comment) for the "no replica attached"
// case: every Query* call must fall through to the write pool. We
// detect routing by capturing which *sql.DB the call hit — the
// fake driver errors on every query, so the path is identified by
// whether the call returns the write-pool error or the read-pool
// error sentinel.
func TestDB_QueryRouting_NoReader(t *testing.T) {
	t.Parallel()

	writePool := sql.OpenDB(taggedConnector{tag: "writer"})
	t.Cleanup(func() { _ = writePool.Close() })
	db := &DB{sqlDB: writePool, driver: "fake"}

	_, err := db.QueryContext(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatalf("QueryContext on fake driver must surface an error; got nil")
	}
	if !errors.Is(err, errFromTag("writer")) {
		t.Fatalf("QueryContext without reader must route to write pool; got %v, want writer-tagged error", err)
	}
}

// TestDB_QueryRouting_WithReader is the core WS-2a assertion: when
// a read pool is attached AND no tenant-bound conn is in context,
// QueryContext / QueryRowContext route to the read pool. The fake
// driver's per-pool tag distinguishes the two pools without
// dialling a real database.
func TestDB_QueryRouting_WithReader(t *testing.T) {
	t.Parallel()

	writePool := sql.OpenDB(taggedConnector{tag: "writer"})
	readPool := sql.OpenDB(taggedConnector{tag: "reader"})
	t.Cleanup(func() { _ = writePool.Close() })
	t.Cleanup(func() { _ = readPool.Close() })
	db := &DB{sqlDB: writePool, sqlRead: readPool, readOwned: true, driver: "fake", readHost: "replica.local"}

	if !db.HasReader() {
		t.Fatal("HasReader must be true after sqlRead is attached")
	}
	if got := db.ReadHost(); got != "replica.local" {
		t.Fatalf("ReadHost = %q, want replica.local", got)
	}
	if got := db.SQLRead(); got == nil {
		t.Fatal("SQLRead must return the attached read pool")
	}

	_, err := db.QueryContext(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("QueryContext on fake driver must surface an error; got nil")
	}
	if !errors.Is(err, errFromTag("reader")) {
		t.Fatalf("QueryContext with reader must route to read pool; got %v, want reader-tagged error", err)
	}
}

// TestDB_QueryRouting_BoundConnAlwaysWins is the RLS-correctness
// half of the WS-2a contract: when a tenant-bound conn is in
// context, Query* MUST stick with that conn even if a read replica
// is attached. The session GUC `sn360.tenant_id` is pinned to the
// bound conn (on the write pool) and the replica's pool has no
// idea it was set; routing a tenant-scoped read to the replica
// would deterministically return zero rows.
func TestDB_QueryRouting_BoundConnAlwaysWins(t *testing.T) {
	t.Parallel()

	writePool := sql.OpenDB(taggedConnector{tag: "writer"})
	readPool := sql.OpenDB(taggedConnector{tag: "reader"})
	t.Cleanup(func() { _ = writePool.Close() })
	t.Cleanup(func() { _ = readPool.Close() })
	db := &DB{sqlDB: writePool, sqlRead: readPool, readOwned: true, driver: "fake"}

	// Acquire a bound conn from a separate, distinctly-tagged
	// pool so its error fingerprint can't be mistaken for either
	// of the main two pools. The bound conn wins regardless of
	// its origin — we only care about the routing predicate.
	boundSource := sql.OpenDB(taggedConnector{tag: "bound"})
	t.Cleanup(func() { _ = boundSource.Close() })
	conn, err := boundSource.Conn(context.Background())
	if err != nil {
		t.Fatalf("acquire bound conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx := WithBoundConn(context.Background(), conn)
	_, err = db.QueryContext(ctx, "SELECT 1")
	if err == nil {
		t.Fatal("QueryContext with bound conn must surface an error from the bound source")
	}
	if !errors.Is(err, errFromTag("bound")) {
		t.Fatalf("QueryContext with bound conn must route to bound conn; got %v, want bound-tagged error", err)
	}
}

// TestDB_ExecAlwaysWritePool checks that ExecContext + BeginTx
// never touch the read pool. Mutations on a replica would be
// silently dropped (PostgreSQL read-only standby refuses writes)
// and any kind of route-to-replica-on-write logic would be a real
// bug. The fake driver makes both operations error; we assert the
// error fingerprint belongs to the write pool.
func TestDB_ExecAlwaysWritePool(t *testing.T) {
	t.Parallel()

	writePool := sql.OpenDB(taggedConnector{tag: "writer"})
	readPool := sql.OpenDB(taggedConnector{tag: "reader"})
	t.Cleanup(func() { _ = writePool.Close() })
	t.Cleanup(func() { _ = readPool.Close() })
	db := &DB{sqlDB: writePool, sqlRead: readPool, readOwned: true, driver: "fake"}

	_, err := db.ExecContext(context.Background(), "UPDATE x SET y=1")
	if err == nil {
		t.Fatal("ExecContext on fake driver must surface an error; got nil")
	}
	if !errors.Is(err, errFromTag("writer")) {
		t.Fatalf("ExecContext must always hit write pool; got %v, want writer-tagged error", err)
	}

	_, err = db.BeginTx(context.Background(), nil)
	if err == nil {
		t.Fatal("BeginTx on fake driver must surface an error; got nil")
	}
	if !errors.Is(err, errFromTag("writer")) {
		t.Fatalf("BeginTx must always hit write pool; got %v, want writer-tagged error", err)
	}
}

// TestDB_AttachReader_EmptyHostNoOp asserts the partial-config
// safety: AttachReader with an empty Host returns nil and leaves
// the DB unchanged. This is what lets cmd/sn360-es/app.go call
// AttachReader unconditionally with the projected config; only
// PG_READ_HOST != "" actually wires the replica.
func TestDB_AttachReader_EmptyHostNoOp(t *testing.T) {
	t.Parallel()

	writePool := sql.OpenDB(taggedConnector{tag: "writer"})
	t.Cleanup(func() { _ = writePool.Close() })
	db := &DB{sqlDB: writePool, driver: "fake"}

	if err := db.AttachReader(context.Background(), Config{Host: "", Database: "x"}); err != nil {
		t.Fatalf("AttachReader with empty Host must be a no-op; got err=%v", err)
	}
	if db.HasReader() {
		t.Fatal("HasReader must remain false after no-op AttachReader")
	}
	if db.ReadHost() != "" {
		t.Fatalf("ReadHost must remain empty after no-op AttachReader; got %q", db.ReadHost())
	}
}

// TestDB_AttachReader_EmptyDatabaseRejected asserts that supplying
// a Host without a Database is a configuration bug and fails fast,
// rather than silently dialling a partial DSN that would surface
// later as an unhelpful pg error.
func TestDB_AttachReader_EmptyDatabaseRejected(t *testing.T) {
	t.Parallel()

	writePool := sql.OpenDB(taggedConnector{tag: "writer"})
	t.Cleanup(func() { _ = writePool.Close() })
	db := &DB{sqlDB: writePool, driver: "fake"}

	err := db.AttachReader(context.Background(), Config{Host: "replica.local", Database: ""})
	if err == nil {
		t.Fatal("AttachReader with Host but empty Database must return an error")
	}
}

// TestDB_AttachReader_NilDBRejected protects against use-before-Open
// (a programmer error). The wiring code calls AttachReader after
// Open so this path should never fire in production, but it costs
// nothing to guarantee a graceful error rather than NPE.
func TestDB_AttachReader_NilDBRejected(t *testing.T) {
	t.Parallel()

	var db *DB
	if err := db.AttachReader(context.Background(), Config{Host: "h", Database: "d"}); err == nil {
		t.Fatal("AttachReader on nil *DB must return an error")
	}
	db = &DB{}
	if err := db.AttachReader(context.Background(), Config{Host: "h", Database: "d"}); err == nil {
		t.Fatal("AttachReader on uninitialised *DB must return an error")
	}
}

// TestDB_SQLAccessors_NilSafe covers the small accessor surface
// added for WS-2a — SQLRead, HasReader, ReadHost — against the
// nil-receiver case so callers (e.g. healthcheck endpoints, boot
// logs) can introspect freely without a guard.
func TestDB_SQLAccessors_NilSafe(t *testing.T) {
	t.Parallel()

	var db *DB
	if got := db.SQLRead(); got != nil {
		t.Fatalf("nil-receiver SQLRead must return nil; got %v", got)
	}
	if db.HasReader() {
		t.Fatal("nil-receiver HasReader must return false")
	}
	if got := db.ReadHost(); got != "" {
		t.Fatalf("nil-receiver ReadHost must return empty; got %q", got)
	}
}
