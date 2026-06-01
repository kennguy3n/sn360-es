//go:build chaos
// +build chaos

// Postgres primary failover chaos scenario.
//
// Failure injected.
//
//	The chaos test boots TWO postgres:16-alpine containers
//	("primary" and "replica"), wires a sn360-es DB wrapper
//	via [postgres.Open] + [(*DB).AttachReader] (the same
//	construction sequence cmd/sn360-es/app.go uses when
//	PG_READ_HOST is set), seeds a verdict row into BOTH
//	databases so the replica has data to serve, and then
//	NATSContainer.Stop()s the primary mid-test. After the
//	stop, the wrapper is reopened with PG_HOST pointing at
//	the (still-running) replica — modelling an operator
//	promoting the replica and rolling the pods.
//
// Why two distinct containers rather than streaming replication.
//
//	Real Postgres streaming replication requires WAL receiver
//	processes, replication slots, and a configured archive
//	command. None of those are interesting to the WS-2a routing
//	contract being pinned here. The chaos test asserts the
//	BEHAVIOUR sn360-es operators rely on:
//
//	  - reads route to the replica pool when no bound conn is in
//	    context (read offload during primary outage);
//	  - writes that DO have a bound conn fail loudly when the
//	    primary is down (they are not silently dropped);
//	  - after a promotion, the wrapper rebinds tenant connections
//	    cleanly with no stale state.
//
//	Two ordinary Postgres containers seeded with the same rows
//	model the steady state of streaming replication for the
//	purpose of pinning that routing behaviour. The two-container
//	approach also keeps the test under its time budget — booting
//	a primary + standby + replication-config from cold takes
//	north of 45 s.
//
// Behaviour pinned by this test (the production contract).
//
//  1. With both nodes up: the wrapper's unbound QueryRowContext
//     routes to the replica pool (asserted via a per-pool sentinel
//     row that differs between primary and replica).
//  2. With the primary stopped: the unbound read STILL succeeds
//     (the replica continues to serve dashboard / investigation
//     reads).
//  3. With the primary stopped: a tenant-bound write fails fast
//     with a clear database error — never silently dropped, never
//     hung past a bounded timeout.
//  4. After the promoted-replica re-open: tenant-bound writes
//     succeed against the new primary; WithTenant cleanly binds a
//     fresh conn with the tenant GUC set, proving the pool
//     re-establishes session state from scratch.
//
// Cross-references.
//
//   - Production wiring:        cmd/sn360-es/app.go::buildApp
//     (PG_READ_HOST branch)
//   - Read-replica routing:     pkg/storage/postgres/postgres.go
//     ::QueryContext / ::QueryRowContext
//   - Bound-conn semantics:     pkg/storage/postgres/tenant_context.go
//   - Degradation doc:          internal/docs/DEGRADATION_MODES.md
package chaos_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// chaosPGTenantID encodes "Postgres failover #001" as hex
// (`c0a4af00001`) for the last segment. Must be all-hex; see
// chaosTier2TenantID for the encoding rationale.
const chaosPGTenantID = "00000000-0000-0000-0000-0c0a4af00001"

// TestChaos_PostgresPrimaryFailover pins the documented WS-2a
// failover contract — see the package-doc above for the full list
// of assertions.
func TestChaos_PostgresPrimaryFailover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), chaosTimeout)
	defer cancel()

	repoRoot := findRepoRoot(t)

	primaryContainer, primaryCfg := startPostgres(ctx, t)
	_, replicaCfg := startPostgres(ctx, t)

	applyMigrations(ctx, t, repoRoot, primaryCfg)
	applyMigrations(ctx, t, repoRoot, replicaCfg)

	seedTenant(ctx, t, primaryCfg, chaosPGTenantID)
	seedTenant(ctx, t, replicaCfg, chaosPGTenantID)

	// Seed a per-pool sentinel into each tenant row so a query
	// against the wrapper can prove which physical pool served the
	// read. The "primary"/"replica" string lives in the
	// display_name column because that's the only free-form field
	// the tenants table exposes at this migration level — we are
	// not modifying schema for the chaos test.
	tagPrimary, tagReplica := "chaos-primary", "chaos-replica"
	tagTenant(ctx, t, primaryCfg, chaosPGTenantID, tagPrimary)
	tagTenant(ctx, t, replicaCfg, chaosPGTenantID, tagReplica)

	// -----------------------------------------------------------------
	// Phase 1: Both nodes up. Wrapper open with replica attached.
	// -----------------------------------------------------------------
	db, err := postgres.Open(ctx, primaryCfg)
	if err != nil {
		t.Fatalf("open primary: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.AttachReader(ctx, replicaCfg); err != nil {
		t.Fatalf("attach replica reader: %v", err)
	}
	if !db.HasReader() {
		t.Fatalf("HasReader = false after AttachReader")
	}

	// Unbound read → must route to the replica pool. We poll a few
	// times because Postgres' background autovacuum on a fresh
	// container can stall the first query by a few hundred ms.
	if got := readTagViaWrapper(ctx, t, db, chaosPGTenantID); got != tagReplica {
		t.Fatalf("phase 1 unbound read: tag = %q, want %q (read should route to replica)", got, tagReplica)
	}

	// Bound-conn read → must route to the primary because that's
	// where the WithTenant call set the GUC. We use the bound
	// conn to also issue a WRITE so we can later observe that the
	// write failed during the primary outage.
	bctx, release, err := db.WithTenant(ctx, chaosPGTenantID)
	if err != nil {
		t.Fatalf("WithTenant pre-failover: %v", err)
	}
	if got := readTagViaCtx(bctx, t, db, chaosPGTenantID); got != tagPrimary {
		_ = release()
		t.Fatalf("phase 1 bound read: tag = %q, want %q (bound conn should pin to primary)", got, tagPrimary)
	}
	_ = release()

	// -----------------------------------------------------------------
	// Phase 2: Stop the primary container. Reads must still work.
	// -----------------------------------------------------------------
	grace := 2 * time.Second
	if err := primaryContainer.Stop(ctx, &grace); err != nil {
		t.Fatalf("stop primary: %v", err)
	}
	t.Logf("primary stopped — modelling crash-promotion event")

	// Bound the unbound-read assertion with a tight retry budget.
	// The replica continues to listen on its own mapped port, so
	// the read MUST succeed on the first attempt; we still poll a
	// few times to absorb a single transient connection blip.
	eventually(t, 10*time.Second, "post-failover replica read succeeds", func() bool {
		readCtx, c := context.WithTimeout(ctx, 3*time.Second)
		defer c()
		// MUST use the non-fatal variant — calling t.Fatalf
		// inside an eventually callback runtime.Goexit's the
		// test goroutine on the first transient blip and the
		// retry never runs.
		tag, err := tryReadTagViaWrapper(readCtx, db, chaosPGTenantID)
		return err == nil && tag == tagReplica
	})

	// -----------------------------------------------------------------
	// Phase 3: Writes block / fail (NOT silently dropped).
	// -----------------------------------------------------------------
	// A tenant-bound write goes through the primary pool. With
	// the primary down it must fail with a network-level error
	// inside a bounded timeout. Failure modes to detect:
	//   - silent success (the worst): write succeeded somewhere we
	//     did not expect. This is what this assertion exists to
	//     prevent. A "no error" return here is the regression.
	//   - hang: the call blocks indefinitely. The 5s context
	//     bound below catches this.
	writeCtx, writeCancel := context.WithTimeout(ctx, 5*time.Second)
	defer writeCancel()
	bctx2, release2, err := db.WithTenant(writeCtx, chaosPGTenantID)
	switch {
	case err == nil:
		_, execErr := db.ExecContext(bctx2,
			`UPDATE tenants SET display_name = $1 WHERE id = $2`,
			"chaos-should-not-write", chaosPGTenantID)
		_ = release2()
		if execErr == nil {
			t.Fatalf("phase 3: tenant-bound write SUCCEEDED with primary stopped — writes are being silently routed somewhere else")
		}
		t.Logf("phase 3: tenant-bound write failed as expected: %v", execErr)
	case isTimeout(err):
		t.Logf("phase 3: WithTenant hit the 5s deadline as expected: %v", err)
	default:
		t.Logf("phase 3: WithTenant rejected the bind as expected: %v", err)
	}

	// -----------------------------------------------------------------
	// Phase 4: Promote the replica. New wrapper, new pool.
	// -----------------------------------------------------------------
	// Operator promotes the replica: in production this is
	// pg_promote() on the replica plus a rolling sn360-es restart
	// with PG_HOST pointed at the promoted node. The test models
	// that promotion by closing the old wrapper and opening a new
	// one against replicaCfg. The new wrapper has no reader pool —
	// PG_READ_HOST is unset until a new replica catches up.
	if cerr := db.Close(); cerr != nil {
		t.Fatalf("close old wrapper: %v", cerr)
	}

	db2, err := postgres.Open(ctx, replicaCfg)
	if err != nil {
		t.Fatalf("open promoted wrapper: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	// Tenant connections rebind cleanly on the new pool. The GUC
	// is per-connection, so a stale GUC from the pre-promotion
	// wrapper would manifest as a query against the wrong tenant;
	// pinning that the WithTenant + SELECT returns the expected
	// row covers both the rebind and the GUC-set-cleanly invariants.
	pctx, prelease, err := db2.WithTenant(ctx, chaosPGTenantID)
	if err != nil {
		t.Fatalf("WithTenant on promoted primary: %v", err)
	}
	defer prelease()

	// Write succeeds on the new primary (the previously-replica
	// container is now serving writes).
	updated := "chaos-promoted-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := db2.ExecContext(pctx,
		`UPDATE tenants SET display_name = $1 WHERE id = $2`,
		updated, chaosPGTenantID); err != nil {
		t.Fatalf("phase 4: write to promoted primary failed: %v", err)
	}

	// Round-trip the value back via the bound conn — confirms the
	// write landed AND the read on the same conn sees its own
	// write (no stale snapshot from the old replica session).
	if got := readDisplayName(pctx, t, db2, chaosPGTenantID); got != updated {
		t.Fatalf("phase 4: round-trip display_name = %q, want %q", got, updated)
	}

	t.Logf("postgres failover scenario completed cleanly: replica served reads through the outage and the promoted primary absorbed writes after restart")
	_ = tcpgVerify(primaryContainer) // documentation tag — keeps the import live
}

// readTagViaWrapper executes an UNBOUND read against the wrapper —
// no bound conn in ctx — so the routing matrix in
// pkg/storage/postgres/postgres.go::QueryRowContext sends the read
// to the read pool when one is attached. Returns the per-pool tag
// the test seeded into tenants.display_name.
//
// Callers inside an eventually(...) retry loop MUST use
// tryReadTagViaWrapper instead — t.Fatalf calls runtime.Goexit, so
// the very first transient query error would tear the goroutine
// down before the retry budget elapses.
func readTagViaWrapper(ctx context.Context, t *testing.T, db *postgres.DB, tenantID string) string {
	t.Helper()
	tag, err := tryReadTagViaWrapper(ctx, db, tenantID)
	if err != nil {
		t.Fatalf("read tag: %v", err)
	}
	return tag
}

// tryReadTagViaWrapper is the error-returning variant of
// readTagViaWrapper. It is the version safe to call from inside
// eventually(...) — the caller can decide whether a transient
// error counts as "not yet ready" (return false, keep polling) or
// a hard failure.
func tryReadTagViaWrapper(ctx context.Context, db *postgres.DB, tenantID string) (string, error) {
	var got string
	err := db.QueryRowContext(ctx, `SELECT display_name FROM tenants WHERE id = $1`, tenantID).Scan(&got)
	return got, err
}

// readTagViaCtx executes a read on whatever conn is bound to ctx (a
// bound conn from WithTenant pins to the primary pool). Used to
// verify that bound-conn reads still hit the primary — and that
// post-promotion, the new wrapper's bound-conn reads see their own
// writes.
func readTagViaCtx(ctx context.Context, t *testing.T, db *postgres.DB, tenantID string) string {
	t.Helper()
	return readDisplayName(ctx, t, db, tenantID)
}

func readDisplayName(ctx context.Context, t *testing.T, db *postgres.DB, tenantID string) string {
	t.Helper()
	var got string
	err := db.QueryRowContext(ctx, `SELECT display_name FROM tenants WHERE id = $1`, tenantID).Scan(&got)
	if err != nil {
		t.Fatalf("read display_name: %v", err)
	}
	return got
}

// tagTenant stamps a per-pool sentinel into tenants.display_name on
// the target Postgres pool so the routing-assertion above can prove
// which pool served the read. We use display_name (not a new
// column) so the chaos test never has to mutate the schema.
func tagTenant(ctx context.Context, t *testing.T, cfg postgres.Config, tenantID, tag string) {
	t.Helper()
	db := openPgDB(ctx, t, cfg)
	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(execCtx,
		`UPDATE tenants SET display_name = $1 WHERE id = $2`,
		tag, tenantID); err != nil {
		t.Fatalf("tag tenant on %s: %v", cfg.Host, err)
	}
}

// isTimeout reports whether err represents a context-deadline /
// timeout failure. We treat both DeadlineExceeded and Canceled as
// timeouts because the inner WithTenant path may convert a context
// cancellation into a wrapped error.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	return false
}

// tcpgVerify is a no-op that exists solely so the tcpg import stays
// referenced when this file is compiled in isolation under the
// chaos build tag. Removing it would compile fine in package mode
// but the explicit reference keeps the dependency intent obvious.
func tcpgVerify(c *tcpg.PostgresContainer) bool {
	return c != nil
}
