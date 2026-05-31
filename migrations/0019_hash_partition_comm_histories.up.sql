-- 0019_hash_partition_comm_histories.up.sql
--
-- Converts `communication_histories` to PostgreSQL native HASH
-- partitioning by `tenant_id` into 32 partitions.
--
-- This migration was explicitly deferred from
-- 0017_partition_append_only_tables.up.sql (see the comment block
-- "Why NOT partition communication_histories" at line 27). The
-- short version is: `communication_histories` is an upsert /
-- aggregate table, not append-only, so RANGE partitioning by
-- `last_seen_at` (as used for evaluation_results / audit_logs /
-- feedback_events in 0017) would force PG to physically move the
-- tuple between partitions on every Upsert, dominating CPU and
-- WAL. HASH by tenant_id is the right scheme for this shape:
-- every (tenant_id, sender_hash, recipient_hash) row stays in the
-- same partition for its entire lifetime, all DML against a given
-- tenant prunes to a single partition, and the per-partition heap
-- stays small enough that index lookups remain hot in cache even
-- at 5 000 tenants.
--
-- Why HASH, not LIST, by tenant_id.
--   At 5 000 tenants, LIST partitioning would mean either
--   maintaining a manual mapping from every new tenant_id to a
--   partition (operational burden, race conditions on tenant
--   onboarding) or one partition per tenant (5 000 partitions →
--   pg_class explosion, autovacuum stress, planner overhead).
--   HASH gives the planner a fixed, declarative routing: it
--   computes `hashtext(tenant_id::text) mod 32` at plan time, prunes
--   to the matching partition, and only that partition is
--   considered for the scan. Onboarding a new tenant requires no
--   schema change.
--
-- Why 32 partitions.
--   The right number is a balance between
--     (a) per-partition heap size (smaller is better — index
--         lookups stay hot, autovacuum cycles are short, DROP /
--         TRUNCATE for tenant-offboarding is cheap), and
--     (b) total partition count (more partitions → larger pg_class,
--         more pg_attribute rows, longer planning time, more open
--         file descriptors).
--   At the 5 000-tenant target with a long-tail traffic
--   distribution, 32 partitions yields ~150 tenants per partition
--   on average and keeps per-partition row counts in the
--   single-digit millions even for the heaviest tenants. The
--   planner overhead for 32 partitions is negligible
--   (~microseconds per plan in PG 16). Doubling to 64 would have
--   minimal effect on either side of the balance.
--   The number is intentionally a power of two so that
--   `hashtext mod N` distributes evenly across the bit space; an
--   odd N would skew the distribution toward partition 0.
--
-- Conversion strategy: INSERT ... SELECT (not ATTACH PARTITION).
--   Unlike the RANGE conversion in 0017, ATTACH PARTITION cannot
--   work for HASH partitioning: every existing row would have to
--   hash to a single partition's bucket for ATTACH to succeed, but
--   real data has rows distributed across every bucket. The only
--   correct conversion is to recreate the table partitioned and
--   re-insert every row, letting PG route each row to the matching
--   HASH partition.
--
--   This is a destructive migration in the sense that it rewrites
--   the table heap. The migration runs inside a single transaction
--   so a failure leaves the schema untouched; the
--   `communication_histories_legacy` table is dropped only after
--   the INSERT ... SELECT succeeds. The cost is one full table
--   scan plus one full table rewrite — proportional to existing
--   row count. For a fresh deployment with zero or near-zero rows
--   this is instant. For a populated deployment this should run
--   during a quiet window; operators with very large existing
--   tables (tens of millions of rows) should consider running
--   `VACUUM (FULL)` on `communication_histories_legacy` first to
--   minimise the working set, and / or running the migration with
--   `lock_timeout` set so a stuck migration aborts rather than
--   blocking writers indefinitely.
--
-- RLS impact.
--   The RLS policy on the old `communication_histories` table is
--   dropped by `DROP TABLE` and must be re-created. The
--   `tenant_isolation` policy from migration 0018 is re-applied on
--   the new partitioned parent at the end of this migration; PG
--   propagates the policy to every existing and future partition
--   automatically (RLS policies on a partitioned parent apply to
--   all partitions; see PG docs "5.8.5. Row Security Policies and
--   Partitioning"). Re-stating the policy verbatim here avoids
--   coupling to whatever 0018 looked like at any historical point;
--   if 0018 evolves, an operator who runs the full migration set
--   ends up with both 0018 and 0019's policies applied in sequence,
--   with 0019's being the live one.
--
-- Indexes.
--   Indexes on the partitioned parent propagate to every partition
--   automatically (PG ≥ 11). We re-create exactly the index set
--   that the legacy table had — see migrations/0001_init.up.sql
--   lines 223-243, migrations/0004_communication_history_sender_domain.up.sql
--   line 19, and migrations/0016_comm_history_last_seen_index.up.sql
--   line 25. The partial-index predicate on `sender_domain` is
--   preserved (PG does propagate partial indexes from parent to
--   partitions).

BEGIN;

-- Step 1 — preserve existing rows under a legacy name. The legacy
-- table keeps all of its indexes, constraints, and FK to tenants
-- intact; we never write to it again, only SELECT from it once
-- during the INSERT below.
ALTER TABLE communication_histories RENAME TO communication_histories_legacy;

-- Step 2 — create the partitioned parent. The PRIMARY KEY MUST
-- include `tenant_id` (the partition key); we use the composite
-- (id, tenant_id) so that the existing id-based identity is
-- preserved and tenant_id is part of every uniqueness check, as
-- PG requires. The UNIQUE constraint on
-- (tenant_id, sender_hash, recipient_hash) already includes
-- tenant_id as its first column, so it carries over unchanged.
--
-- Constraints are EXPLICITLY NAMED to match the legacy table's
-- auto-generated names from migration 0001. Same reasoning as
-- 0017_partition_append_only_tables.up.sql: even though we use
-- INSERT...SELECT here (not ATTACH PARTITION), naming the FK
-- consistently means the down migration's `ALTER TABLE … RENAME
-- TO communication_histories` ends up with the same constraint
-- name an operator would see on a fresh-from-0001 database.
CREATE TABLE communication_histories (
    id                  UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL,
    sender_hash         BYTEA       NOT NULL,
    recipient_hash      BYTEA       NOT NULL,
    sender_domain_hash  BYTEA       NOT NULL,
    sender_domain       TEXT,
    count_7d            INT         NOT NULL DEFAULT 0,
    count_30d           INT         NOT NULL DEFAULT 0,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    relationship        TEXT        NOT NULL DEFAULT '',
    typical_hour        INT                  DEFAULT -1,
    volume_baseline_daily REAL               DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, tenant_id),
    UNIQUE (tenant_id, sender_hash, recipient_hash),
    CONSTRAINT communication_histories_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) PARTITION BY HASH (tenant_id);

-- Step 3 — create the 32 HASH partitions. The naming convention
-- `<table>_p<NN>` is intentionally short so it shows up cleanly in
-- pg_class, pg_stat_user_tables, and any operator-facing tooling
-- (pgAdmin, datadog-postgres, pg_partman if it ever wraps these).
-- The two-digit zero-padding keeps lexicographic sort identical to
-- numeric sort across all 32.
DO $partitions$
DECLARE
    bucket  INTEGER;
    part    TEXT;
BEGIN
    FOR bucket IN 0..31 LOOP
        part := format('communication_histories_p%s', lpad(bucket::text, 2, '0'));
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF communication_histories FOR VALUES WITH (MODULUS 32, REMAINDER %s)',
            part, bucket);
    END LOOP;
END
$partitions$;

-- Step 4 — copy existing rows into the partitioned parent. Each
-- INSERT routes through the partition map and lands in the
-- HASH-matched child partition automatically. We use a single
-- INSERT inside the migration's transaction so a failure rolls
-- back cleanly. ON CONFLICT DO NOTHING is a defence-in-depth
-- guard: the legacy table's UNIQUE constraint already excludes
-- duplicates, so the conflict path should never fire — but if a
-- partial earlier run somehow left orphaned rows behind, this
-- prevents a crash on re-run.
INSERT INTO communication_histories
    (id, tenant_id, sender_hash, recipient_hash, sender_domain_hash,
     sender_domain, count_7d, count_30d, first_seen_at, last_seen_at,
     relationship, typical_hour, volume_baseline_daily, updated_at)
SELECT
    id, tenant_id, sender_hash, recipient_hash, sender_domain_hash,
    sender_domain, count_7d, count_30d, first_seen_at, last_seen_at,
    relationship, typical_hour, volume_baseline_daily, updated_at
FROM communication_histories_legacy
ON CONFLICT (tenant_id, sender_hash, recipient_hash) DO NOTHING;

-- Step 5 — drop the legacy table. Indexes, RLS policy, and FK on
-- the legacy table are dropped automatically with it. The
-- transaction commits with `communication_histories` being the
-- one and only canonical name for the data.
DROP TABLE communication_histories_legacy;

-- Step 6 — re-create the index set on the partitioned parent. PG
-- propagates these to every existing partition and to any future
-- partition we might add (we won't, but the propagation is part
-- of the contract).
CREATE INDEX IF NOT EXISTS idx_comm_hist_tenant_sender
    ON communication_histories (tenant_id, sender_hash);
CREATE INDEX IF NOT EXISTS idx_comm_hist_tenant_recipient
    ON communication_histories (tenant_id, recipient_hash);
CREATE INDEX IF NOT EXISTS idx_comm_hist_relationship
    ON communication_histories (tenant_id, relationship);
CREATE INDEX IF NOT EXISTS idx_comm_hist_tenant_sender_domain
    ON communication_histories (tenant_id, sender_domain)
    WHERE sender_domain IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_comm_hist_tenant_last_seen
    ON communication_histories (tenant_id, last_seen_at DESC);

-- Step 7 — re-apply the RLS policy from migration 0018. ENABLE
-- and FORCE on the parent propagate to every partition. The
-- policy USING / WITH CHECK clauses are identical to the 0018
-- policy on the un-partitioned table. Cross-tenant admin reads
-- (the relationship worker fan-out, OAuth restore) continue to
-- work via the `sn360.cross_tenant=on` escape hatch.
ALTER TABLE communication_histories ENABLE ROW LEVEL SECURITY;
ALTER TABLE communication_histories FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON communication_histories
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

-- Step 8 — re-grant the privileges the migration 0018 sn360_app
-- role expects. The legacy table's grants were dropped along with
-- the table itself; without this re-grant, the app role would hit
-- "permission denied for table communication_histories" on the
-- first read after migration. Wrapped in a DO block so a fresh
-- environment where sn360_app has not yet been created (legacy
-- single-role deployments) does not fail; the grant only runs
-- when the role exists.
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sn360_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON communication_histories TO sn360_app;
    END IF;
END
$grant$;

COMMIT;
