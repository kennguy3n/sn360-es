// Structural tests for migration 0019 (WS-2b: HASH partition
// communication_histories by tenant_id into 32 partitions).
//
// These tests read the .sql files on disk and pin the structural
// guarantees of the migration WITHOUT requiring a running
// Postgres. The integration suite in rls_integration_test.go (build
// tag `integration`) exercises the SQL against a real PG, but
// integration runs are slow and gated on the `integration` build
// tag, so the structural pins below run in every `go test -short`
// invocation and catch the most common regressions (someone
// dropping the FORCE RLS, dropping the role-existence guard around
// the GRANT, dropping the partial-index predicate, accidentally
// switching MODULUS away from 32, etc.) before a CI integration
// run is ever attempted.
//
// The tests are intentionally not a full SQL parse — they regex /
// substring-check the textual structure. The trade-off is that
// they will tolerate cosmetic whitespace edits but will catch any
// edit that removes one of the structural invariants the WS-2b
// design depends on.

package postgres_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	migration0019Up   = "0019_hash_partition_comm_histories.up.sql"
	migration0019Down = "0019_hash_partition_comm_histories.down.sql"
)

// readMigration loads a migration file from the repo's
// /migrations directory. It assumes the test binary runs from
// pkg/storage/postgres/ — `go test ./...` always does, so we walk
// three levels up to the repo root.
func readMigration(t *testing.T, name string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	path := filepath.Join(repoRoot, "migrations", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// TestMigration0019Up_AtomicTransaction pins that the up
// migration is wrapped in a single BEGIN/COMMIT pair. A
// non-atomic up migration on a destructive rewrite would leave
// the database in a half-converted state on failure (e.g.
// communication_histories_legacy renamed aside but the new
// partitioned parent never created), which is unrecoverable
// without manual surgery.
func TestMigration0019Up_AtomicTransaction(t *testing.T) {
	body := readMigration(t, migration0019Up)
	upper := strings.ToUpper(body)
	if !strings.Contains(upper, "BEGIN;") {
		t.Error("migration 0019 up is missing BEGIN; — destructive rewrite must be atomic")
	}
	if !strings.Contains(upper, "COMMIT;") {
		t.Error("migration 0019 up is missing COMMIT; — destructive rewrite must be atomic")
	}
	// Sanity: BEGIN must come before COMMIT.
	if strings.Index(upper, "BEGIN;") >= strings.Index(upper, "COMMIT;") {
		t.Error("migration 0019 up has BEGIN; after COMMIT; — order is wrong")
	}
}

// TestMigration0019Up_HashPartitioning pins the partitioning
// scheme. The WS-2b design specifically chose HASH over LIST /
// RANGE because (a) HASH avoids the per-tenant operational
// burden of manual mapping, (b) HASH avoids the per-tuple move
// that RANGE-by-last_seen_at would cause on Upsert. Switching
// the scheme without re-evaluating the design is a regression.
func TestMigration0019Up_HashPartitioning(t *testing.T) {
	body := readMigration(t, migration0019Up)
	if !strings.Contains(body, "PARTITION BY HASH (tenant_id)") {
		t.Error("migration 0019 up is not declaring PARTITION BY HASH (tenant_id)")
	}
}

// TestMigration0019Up_ThirtyTwoPartitions pins MODULUS 32 and
// the 0..31 loop. Doubling or halving the partition count
// without re-running the cost-model analysis (target ~150
// tenants per partition at 5k tenants) is a regression we want
// reviewers to catch explicitly.
func TestMigration0019Up_ThirtyTwoPartitions(t *testing.T) {
	body := readMigration(t, migration0019Up)
	if !strings.Contains(body, "FOR bucket IN 0..31 LOOP") {
		t.Error("migration 0019 up is not iterating 0..31 for partition creation")
	}
	if !strings.Contains(body, "MODULUS 32, REMAINDER") {
		t.Error("migration 0019 up is not using MODULUS 32 in CREATE TABLE ... PARTITION OF")
	}
}

// TestMigration0019Up_PrimaryKeyIncludesTenantID pins the
// composite PK. PG REQUIRES that the partition key appears in
// every unique constraint on a partitioned table. If a future
// edit changes PK to (id) only, the CREATE TABLE will fail at
// migration time — but the test catches it earlier without
// needing a real PG.
func TestMigration0019Up_PrimaryKeyIncludesTenantID(t *testing.T) {
	body := readMigration(t, migration0019Up)
	if !regexp.MustCompile(`PRIMARY KEY\s*\(\s*id\s*,\s*tenant_id\s*\)`).MatchString(body) {
		t.Error("migration 0019 up does not declare PRIMARY KEY (id, tenant_id) on the partitioned parent")
	}
}

// TestMigration0019Up_UniqueIncludesTenantID pins the natural-
// key UNIQUE constraint. The original 0001 schema's unique key
// (tenant_id, sender_hash, recipient_hash) already includes the
// partition key as its first column, so it carries over
// unchanged. Losing this would break the Upsert correctness
// path in the repository layer.
func TestMigration0019Up_UniqueIncludesTenantID(t *testing.T) {
	body := readMigration(t, migration0019Up)
	if !regexp.MustCompile(`UNIQUE\s*\(\s*tenant_id\s*,\s*sender_hash\s*,\s*recipient_hash\s*\)`).MatchString(body) {
		t.Error("migration 0019 up does not declare UNIQUE (tenant_id, sender_hash, recipient_hash) on the partitioned parent")
	}
}

// TestMigration0019Up_PreservesAllIndexes pins the index set
// carried over from migrations 0001, 0004, 0016. Losing any of
// these would silently regress query performance under load.
func TestMigration0019Up_PreservesAllIndexes(t *testing.T) {
	body := readMigration(t, migration0019Up)
	want := []string{
		"idx_comm_hist_tenant_sender",
		"idx_comm_hist_tenant_recipient",
		"idx_comm_hist_relationship",
		"idx_comm_hist_tenant_sender_domain",
		"idx_comm_hist_tenant_last_seen",
	}
	for _, idx := range want {
		if !strings.Contains(body, idx) {
			t.Errorf("migration 0019 up is missing CREATE INDEX %s", idx)
		}
	}
}

// TestMigration0019Up_PreservesPartialIndexPredicate pins the
// WHERE sender_domain IS NOT NULL clause on the partial index.
// Without the predicate, PG would index NULL rows and balloon
// the index. This is a subtle regression — easy to forget when
// retyping the CREATE INDEX statement.
func TestMigration0019Up_PreservesPartialIndexPredicate(t *testing.T) {
	body := readMigration(t, migration0019Up)
	// The partial-index CREATE statement must mention both the
	// idx name AND the WHERE predicate.
	re := regexp.MustCompile(`(?is)CREATE\s+INDEX[^;]*idx_comm_hist_tenant_sender_domain[^;]*WHERE\s+sender_domain\s+IS\s+NOT\s+NULL`)
	if !re.MatchString(body) {
		t.Error("migration 0019 up dropped the WHERE sender_domain IS NOT NULL predicate on idx_comm_hist_tenant_sender_domain")
	}
}

// TestMigration0019Up_ReAppliesRLS pins the RLS re-apply. The
// DROP TABLE in step 5 drops the legacy policy along with the
// table; if step 7 forgets to re-enable / re-policy on the
// partitioned parent, the table will be readable cross-tenant
// in production. RLS on the partitioned parent propagates to
// every partition automatically (PG 11+).
func TestMigration0019Up_ReAppliesRLS(t *testing.T) {
	body := readMigration(t, migration0019Up)
	upper := strings.ToUpper(body)
	if !strings.Contains(upper, "ENABLE ROW LEVEL SECURITY") {
		t.Error("migration 0019 up is not re-enabling ROW LEVEL SECURITY on the partitioned parent")
	}
	if !strings.Contains(upper, "FORCE  ROW LEVEL SECURITY") &&
		!strings.Contains(upper, "FORCE ROW LEVEL SECURITY") {
		t.Error("migration 0019 up is not FORCEing RLS on the partitioned parent — table owners would bypass the policy without this")
	}
	if !strings.Contains(body, "CREATE POLICY tenant_isolation ON communication_histories") {
		t.Error("migration 0019 up is not re-creating the tenant_isolation policy on the partitioned parent")
	}
	// Policy must reference both the per-request GUC and the
	// cross-tenant escape hatch — mirroring 0018's policy.
	if !strings.Contains(body, "current_setting('sn360.tenant_id', true)") {
		t.Error("migration 0019 up RLS policy is not consulting sn360.tenant_id GUC")
	}
	if !strings.Contains(body, "current_setting('sn360.cross_tenant', true)") {
		t.Error("migration 0019 up RLS policy is not honouring the sn360.cross_tenant escape hatch")
	}
}

// TestMigration0019Up_RoleGuardedGrant pins the role-existence
// guard around GRANT. Fresh dev environments that never ran the
// 0018 role-creation block do not have sn360_app; a naive GRANT
// would fail at migration time. The DO $grant$ block makes the
// migration safe to run regardless of whether the role exists.
func TestMigration0019Up_RoleGuardedGrant(t *testing.T) {
	body := readMigration(t, migration0019Up)
	if !strings.Contains(body, "FROM pg_roles WHERE rolname = 'sn360_app'") {
		t.Error("migration 0019 up is not guarding the sn360_app GRANT with a pg_roles existence check")
	}
	if !strings.Contains(body, "GRANT SELECT, INSERT, UPDATE, DELETE ON communication_histories TO sn360_app") {
		t.Error("migration 0019 up is not re-granting the sn360_app privileges that the legacy table's DROP took with it")
	}
}

// TestMigration0019Up_RenamesLegacyAndDropsIt pins the
// rename-aside + drop pattern. This is the conversion strategy
// the design chose over ATTACH PARTITION (which cannot work for
// HASH — every existing row would have to hash to a single
// bucket for ATTACH to succeed).
func TestMigration0019Up_RenamesLegacyAndDropsIt(t *testing.T) {
	body := readMigration(t, migration0019Up)
	if !strings.Contains(body, "ALTER TABLE communication_histories RENAME TO communication_histories_legacy") {
		t.Error("migration 0019 up is not renaming the existing table aside before re-creating it partitioned")
	}
	if !strings.Contains(body, "DROP TABLE communication_histories_legacy") {
		t.Error("migration 0019 up is not dropping the legacy table after the INSERT...SELECT — would leave a stale heap behind")
	}
	if !strings.Contains(body, "INSERT INTO communication_histories") ||
		!strings.Contains(body, "FROM communication_histories_legacy") {
		t.Error("migration 0019 up is not copying rows from the legacy table into the partitioned parent")
	}
}

// TestMigration0019Down_AtomicTransaction pins the same
// transactional wrapper on the reverse migration. The reverse
// is just as destructive (un-partitions back to a heap) and a
// failure mid-flight would leave the schema in a half-state.
func TestMigration0019Down_AtomicTransaction(t *testing.T) {
	body := readMigration(t, migration0019Down)
	upper := strings.ToUpper(body)
	if !strings.Contains(upper, "BEGIN;") {
		t.Error("migration 0019 down is missing BEGIN; — destructive reverse rewrite must be atomic")
	}
	if !strings.Contains(upper, "COMMIT;") {
		t.Error("migration 0019 down is missing COMMIT; — destructive reverse rewrite must be atomic")
	}
}

// TestMigration0019Down_RestoresUnpartitionedHeap pins that the
// reverse direction actually un-partitions. The simplest way
// for a down migration to "look right" but be wrong is to drop
// the partitioned table without re-creating an un-partitioned
// equivalent.
func TestMigration0019Down_RestoresUnpartitionedHeap(t *testing.T) {
	body := readMigration(t, migration0019Down)
	if !strings.Contains(body, "ALTER TABLE communication_histories RENAME TO communication_histories_partitioned") {
		t.Error("migration 0019 down is not renaming the partitioned parent aside before re-creating an un-partitioned heap")
	}
	if strings.Contains(body, "PARTITION BY HASH") {
		t.Error("migration 0019 down is re-declaring PARTITION BY HASH on the new table — should be an un-partitioned heap")
	}
	if !strings.Contains(body, "CREATE TABLE communication_histories (") {
		t.Error("migration 0019 down is not re-creating the un-partitioned communication_histories heap")
	}
	if !strings.Contains(body, "DROP TABLE communication_histories_partitioned CASCADE") {
		t.Error("migration 0019 down is not dropping the partitioned remnant after the reverse copy (CASCADE needed to drop child partitions)")
	}
}

// TestMigration0019Down_PreservesSchemaShape pins that the
// un-partitioned heap re-created by the down migration matches
// the column shape an operator would see on a fresh database
// after migrations 0001 / 0004 / 0007 — i.e. the rollback
// state matches the pre-WS-2b state byte-for-byte (give or
// take semantic-irrelevant whitespace).
func TestMigration0019Down_PreservesSchemaShape(t *testing.T) {
	body := readMigration(t, migration0019Down)
	wantColumns := []string{
		"id                  UUID PRIMARY KEY DEFAULT gen_random_uuid()",
		"tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE",
		"sender_hash         BYTEA       NOT NULL",
		"recipient_hash      BYTEA       NOT NULL",
		"sender_domain_hash  BYTEA       NOT NULL",
		"sender_domain       TEXT",
		"first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()",
		"last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()",
		"typical_hour        INT                  DEFAULT -1",
		"volume_baseline_daily REAL               DEFAULT 0",
		"UNIQUE (tenant_id, sender_hash, recipient_hash)",
	}
	for _, col := range wantColumns {
		if !strings.Contains(body, col) {
			t.Errorf("migration 0019 down lost the original column / constraint: %q", col)
		}
	}
}
