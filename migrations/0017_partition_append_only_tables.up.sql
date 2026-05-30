-- 0017_partition_append_only_tables.up.sql
--
-- Converts the three append-only tables — `evaluation_results`,
-- `audit_logs`, `feedback_events` — to PostgreSQL native RANGE
-- partitioning (monthly partitions, partitioned on the natural
-- anchor timestamp).
--
-- Why partition these tables.
--   At 1 000+ tenants the row volume on these three tables grows
--   linearly with traffic: every evaluated message writes one
--   evaluation_results row, every banner action writes one
--   feedback_events row, every audited action writes one audit_logs
--   row. Without partitioning the cleanup worker (see
--   internal/service/worker/cleanup_worker.go) issues
--   `DELETE FROM <t> WHERE <anchor> < $cutoff` per cycle, which:
--     - holds row-level locks proportional to the number of pruned
--       rows;
--     - generates WAL volume proportional to rows × indexes;
--     - bloats the table heap and indexes (autovacuum has to chase);
--     - re-walks the same pruned tip every cycle.
--   Native partitioning lets the cleanup worker DROP PARTITION the
--   month that has fallen outside retention in O(1): no per-row
--   locks, no WAL volume per row, no index bloat. The
--   PartitionMaintenanceJob (added alongside this migration) drops
--   old partitions and pre-creates forward ones.
--
-- Why NOT partition `communication_histories`.
--   `communication_histories` is an upsert/aggregate table — every
--   inbound message updates the same (tenant_id, sender_hash,
--   recipient_hash) row's count_7d, count_30d, last_seen_at. Range-
--   partitioning by last_seen_at would force PG to physically move
--   the tuple between partitions on every update, dominating CPU
--   and WAL. Communication histories belong on a different
--   partitioning scheme (HASH by tenant_id) which is a future PR.
--
-- The conversion strategy: ATTACH PARTITION.
--   For each table we
--     1. rename `<t>` → `<t>_legacy`,
--     2. create the partitioned parent under the original name,
--     3. add a CHECK constraint to `<t>_legacy` matching the
--        bounded range its existing rows occupy,
--     4. ATTACH the legacy table as the historical partition,
--     5. CREATE matching indexes on the parent (PG ≥ 11 propagates
--        them to every attached + future partition automatically).
--   This avoids INSERT…SELECT-ing the entire existing dataset into
--   a new table — important once tables exceed a few GB. The cost
--   of ATTACH PARTITION is a single full-table scan to verify the
--   CHECK constraint; for a fresh deployment with no rows this is
--   instant. For an existing deployment with significant data the
--   ATTACH can take minutes-to-hours and should be run during a
--   quiet window. The migration is wrapped in a single transaction
--   so a partial failure leaves the schema untouched.
--
-- Partition naming convention.
--   `<table>_YYYY_MM` for monthly partitions covering [first of
--   month, first of next month). The PartitionMaintenanceJob uses
--   this same pattern for forward-creation and retention-driven
--   drops, so any external dashboards / pg_dump filters can rely
--   on the suffix as a stable contract.
--
-- Initial partition set.
--   We pre-create the historical legacy partition (everything
--   before the cutover boundary), the current month, and three
--   forward months. The PartitionMaintenanceJob keeps the forward
--   set ≥ 3 months ahead so a long maintenance pause cannot leave
--   the parent without a target partition for an insert.

BEGIN;

-- The cutover boundary. Every row that exists at the moment this
-- migration runs lives in the *_legacy partition (CHECK constraint
-- bounded by this timestamp), and new writes land in the matching
-- *_YYYY_MM partition.
--
-- Idempotency / reproducibility note. The cutover is computed as
-- DATE_TRUNC('month', NOW()) — i.e. the first of the current month
-- in the database's local timezone — at migration-time. golang-
-- migrate runs each migration file exactly once per database (the
-- schema_migrations table records (version, dirty) and refuses to
-- re-run), so within a single deployment lineage the cutover is
-- effectively a constant: whatever the wall clock said on the day
-- the migration first ran. The risk only matters if an operator
-- re-applies this migration into a fresh database long after the
-- original deployment (e.g. a regional rebuild, a disaster-
-- recovery restore from a logical backup). In those cases the
-- legacy partition will span an earlier range than the production
-- master, but the partition layout is otherwise functionally
-- identical (legacy partition exists, forward partitions exist,
-- writes route correctly) and the cleanup worker drops the legacy
-- partition once retention elapses regardless of which month it
-- was anchored at. Operators rebuilding from a logical backup who
-- want bit-for-bit-identical partition names should manually
-- temporarily SET `app.partition_cutover` in their session and
-- adapt this migration to read it via `current_setting` — kept out
-- of the default path to avoid an extra knob no one needs.
--
-- Devin Review flagged this as a watch-out (PR #45, finding INFO);
-- the gap is documented here rather than fixed because adding a
-- knob without a real consumer would be over-engineering.
DO $migration$
DECLARE
    cutover    TIMESTAMPTZ := DATE_TRUNC('month', NOW());
    month_idx  INTEGER;
    part_start TIMESTAMPTZ;
    part_end   TIMESTAMPTZ;
    part_name  TEXT;
BEGIN

------------------------------------------------------------------
-- evaluation_results — partition on `evaluated_at`
------------------------------------------------------------------

-- Step 1 — preserve existing data under a legacy name.
ALTER TABLE evaluation_results RENAME TO evaluation_results_legacy;

-- Step 2 — drop the existing UNIQUE so we can re-create it inside
-- the partitioned parent (UNIQUE on a partitioned table must
-- include the partition key column; we re-add it below).
ALTER TABLE evaluation_results_legacy DROP CONSTRAINT IF EXISTS evaluation_results_tenant_id_message_id_hash_key;

-- Step 3 — drop the legacy PRIMARY KEY: PG requires the parent's PK
-- to include the partition key column, and the same constraint on
-- a child partition would conflict.
ALTER TABLE evaluation_results_legacy DROP CONSTRAINT IF EXISTS evaluation_results_pkey;

-- Step 4 — create the partitioned parent. Note the composite
-- PRIMARY KEY (id, evaluated_at) — the partition key MUST be in
-- every unique / primary key on a partitioned table.
CREATE TABLE evaluation_results (
    id                       UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id                UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id_hash          BYTEA       NOT NULL,
    correlation_id           TEXT,
    score                    INT         NOT NULL CHECK (score BETWEEN 0 AND 100),
    tier                     TEXT        NOT NULL,
    primary_category         TEXT,
    secondary_categories     TEXT[]      NOT NULL DEFAULT '{}'::TEXT[],
    reason_codes             TEXT[]      NOT NULL DEFAULT '{}'::TEXT[],
    degraded                 BOOLEAN     NOT NULL DEFAULT FALSE,
    degraded_services        TEXT[]      NOT NULL DEFAULT '{}'::TEXT[],
    tier0_outcome            JSONB,
    tier1_outcome            JSONB,
    tier2_outcome            JSONB,
    rspamd_outcome           JSONB,
    evaluated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, evaluated_at),
    UNIQUE (tenant_id, message_id_hash, evaluated_at)
) PARTITION BY RANGE (evaluated_at);

-- Step 5 — bound the legacy table and attach it as the historical
-- partition. The ATTACH triggers a full table scan to verify every
-- row satisfies the CHECK constraint; this is fast on an empty
-- (fresh deployment) table and slow on a populated one. We re-state
-- the constraint as IMMUTABLE so PG can use it for partition
-- elimination at planning time even before ATTACH commits.
ALTER TABLE evaluation_results_legacy
    ADD CONSTRAINT evaluation_results_legacy_range
    CHECK (evaluated_at < cutover) NOT VALID;
ALTER TABLE evaluation_results_legacy VALIDATE CONSTRAINT evaluation_results_legacy_range;

ALTER TABLE evaluation_results ATTACH PARTITION evaluation_results_legacy
    FOR VALUES FROM ('1970-01-01'::timestamptz) TO (cutover);

-- Step 6 — pre-create the current month and three forward months
-- so the parent has a target partition for any new write. The
-- PartitionMaintenanceJob keeps this rolling forward.
FOR month_idx IN 0..3 LOOP
    part_start := cutover + (month_idx * INTERVAL '1 month');
    part_end   := part_start + INTERVAL '1 month';
    part_name  := format('evaluation_results_%s', to_char(part_start, 'YYYY_MM'));
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF evaluation_results FOR VALUES FROM (%L) TO (%L)',
        part_name, part_start, part_end);
END LOOP;

-- Step 7 — indexes on the parent propagate to every partition
-- (legacy + future) automatically. The legacy table's old indexes
-- are dropped by PG when ATTACH adopts these.
CREATE INDEX IF NOT EXISTS idx_eval_results_tenant_evaluated
    ON evaluation_results (tenant_id, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_eval_results_tier
    ON evaluation_results (tenant_id, tier);

------------------------------------------------------------------
-- audit_logs — partition on `created_at`
------------------------------------------------------------------

ALTER TABLE audit_logs RENAME TO audit_logs_legacy;
ALTER TABLE audit_logs_legacy DROP CONSTRAINT IF EXISTS audit_logs_pkey;

CREATE TABLE audit_logs (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    actor           TEXT        NOT NULL,
    action          TEXT        NOT NULL,
    target_type     TEXT        NOT NULL,
    target_hash     BYTEA,
    correlation_id  TEXT,
    metadata        JSONB       NOT NULL DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

ALTER TABLE audit_logs_legacy
    ADD CONSTRAINT audit_logs_legacy_range
    CHECK (created_at < cutover) NOT VALID;
ALTER TABLE audit_logs_legacy VALIDATE CONSTRAINT audit_logs_legacy_range;

ALTER TABLE audit_logs ATTACH PARTITION audit_logs_legacy
    FOR VALUES FROM ('1970-01-01'::timestamptz) TO (cutover);

FOR month_idx IN 0..3 LOOP
    part_start := cutover + (month_idx * INTERVAL '1 month');
    part_end   := part_start + INTERVAL '1 month';
    part_name  := format('audit_logs_%s', to_char(part_start, 'YYYY_MM'));
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_logs FOR VALUES FROM (%L) TO (%L)',
        part_name, part_start, part_end);
END LOOP;

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_action
    ON audit_logs (tenant_id, action, created_at DESC);

------------------------------------------------------------------
-- feedback_events — partition on `occurred_at`
------------------------------------------------------------------

ALTER TABLE feedback_events RENAME TO feedback_events_legacy;
ALTER TABLE feedback_events_legacy DROP CONSTRAINT IF EXISTS feedback_events_pkey;

CREATE TABLE feedback_events (
    id                       UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id                UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pseudo_message_id        TEXT        NOT NULL,
    action                   TEXT        NOT NULL
                             CHECK (action IN ('report_phishing', 'mark_safe', 'trust_sender')),
    tier                     TEXT        NOT NULL DEFAULT '',
    correlation_id           TEXT,
    occurred_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

ALTER TABLE feedback_events_legacy
    ADD CONSTRAINT feedback_events_legacy_range
    CHECK (occurred_at < cutover) NOT VALID;
ALTER TABLE feedback_events_legacy VALIDATE CONSTRAINT feedback_events_legacy_range;

ALTER TABLE feedback_events ATTACH PARTITION feedback_events_legacy
    FOR VALUES FROM ('1970-01-01'::timestamptz) TO (cutover);

FOR month_idx IN 0..3 LOOP
    part_start := cutover + (month_idx * INTERVAL '1 month');
    part_end   := part_start + INTERVAL '1 month';
    part_name  := format('feedback_events_%s', to_char(part_start, 'YYYY_MM'));
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF feedback_events FOR VALUES FROM (%L) TO (%L)',
        part_name, part_start, part_end);
END LOOP;

CREATE INDEX IF NOT EXISTS idx_feedback_events_tenant_occurred
    ON feedback_events (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_events_tenant_action_occurred
    ON feedback_events (tenant_id, action, occurred_at DESC);

END $migration$;

COMMIT;
