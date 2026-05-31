-- 0019_hash_partition_comm_histories.down.sql
--
-- Reverts 0019: convert the HASH-partitioned
-- `communication_histories` table back to a single un-partitioned
-- heap.
--
-- The reverse direction is the same shape as the forward one:
-- rename the partitioned parent aside, create a fresh
-- un-partitioned table with the original schema, INSERT ... SELECT
-- the rows back, drop the partitioned remnant, re-apply the RLS
-- policy and grants. PG's INSERT ... SELECT against a partitioned
-- source automatically unions all partitions, so a single
-- statement collects every row.
--
-- This down migration exists so the standard
-- `make migrate-down` workflow keeps working in development; in
-- production an actual roll-back of an applied schema migration
-- is exceptional and should be reviewed manually before running.

BEGIN;

-- Step 1 — rename the partitioned parent aside. Its child
-- partitions follow the rename (PG manages the parent's namespace
-- but the children's names do not change).
ALTER TABLE communication_histories RENAME TO communication_histories_partitioned;

-- Step 2 — re-create the un-partitioned table with the original
-- 0001-init shape, plus the 0004 sender_domain column and the
-- 0007 typical_hour / volume_baseline_daily columns. The PK is
-- back to (id) only, matching what 0001 created.
CREATE TABLE communication_histories (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    UNIQUE (tenant_id, sender_hash, recipient_hash)
);

-- Step 3 — copy rows back. SELECT against the partitioned table
-- unions every partition automatically.
INSERT INTO communication_histories
    (id, tenant_id, sender_hash, recipient_hash, sender_domain_hash,
     sender_domain, count_7d, count_30d, first_seen_at, last_seen_at,
     relationship, typical_hour, volume_baseline_daily, updated_at)
SELECT
    id, tenant_id, sender_hash, recipient_hash, sender_domain_hash,
    sender_domain, count_7d, count_30d, first_seen_at, last_seen_at,
    relationship, typical_hour, volume_baseline_daily, updated_at
FROM communication_histories_partitioned
ON CONFLICT (tenant_id, sender_hash, recipient_hash) DO NOTHING;

-- Step 4 — drop the partitioned remnant. CASCADE removes every
-- child partition along with the parent.
DROP TABLE communication_histories_partitioned CASCADE;

-- Step 5 — re-create the original index set (from 0001 + 0004 +
-- 0016) on the un-partitioned table.
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

-- Step 6 — re-apply RLS and grants on the un-partitioned table.
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

DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sn360_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON communication_histories TO sn360_app;
    END IF;
END
$grant$;

COMMIT;
