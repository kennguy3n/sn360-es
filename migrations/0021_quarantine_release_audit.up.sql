-- 0021_quarantine_release_audit.up.sql
--
-- WS-3a Quarantine self-service.
--
-- Adds two tables:
--   1. `tenant_release_policies` — per-tenant policy knob for the
--      quarantine self-service flow. Today this carries one column,
--      `quarantine_self_release_per_hour`, the per-recipient hourly
--      release cap (default 5). The table is a logical extension
--      point for future per-tenant self-service knobs (per-tier
--      eligibility, allow-list overrides, etc.) so we don't have
--      to widen `tenants` every time the policy surface grows.
--   2. `quarantine_release_audit` — append-only record of every
--      self-release attempt (success or failure) keyed by
--      (tenant_id, recipient_user_hash). Doubles as the source of
--      truth for the per-recipient rate-limit counter: the limit
--      check is `SELECT count(*) ... WHERE requested_at >= now() - '1 hour'`.
--      Audit-driven rate-limit (vs a separate token bucket) means
--      every observable release attempt is also a rate-limit input —
--      no split-brain between counter and audit.
--
-- Why HASH partition the audit table.
--   The audit table is append-only and the dominant query pattern
--   is `WHERE tenant_id = $1 AND recipient_user_hash = $2 AND
--   requested_at >= $3`. HASH(tenant_id) into 32 partitions matches
--   the convention established by `communication_histories` in
--   0019_hash_partition_comm_histories.up.sql, prunes single-tenant
--   reads to one partition, and keeps per-partition heap small
--   enough that the rate-limit lookup is hot in cache. Append-only
--   workloads don't suffer the partition-move pathology that
--   prevented RANGE partitioning on `communication_histories`.
--
-- Why a CHECK constraint on outcome.
--   The outcome enum has 8 known values
--   (released | rate_limited | tier2_blocked | release_refused |
--   token_expired | invalid_token | already_released | not_found).
--   `tier2_blocked` is reserved exclusively for the persisted
--   `Tier2Malicious=true` gate caught at lookup time;
--   `release_refused` covers the runner's re-evaluation
--   refusing release for any other reason (tier-1 score still
--   above threshold, fresh tier-2 verdict, policy gate, …) so
--   SOC queries `WHERE outcome = 'tier2_blocked'` get only
--   true tier-2 verdicts and `WHERE outcome = 'release_refused'`
--   get safety-stack refusals more broadly. A CHECK
--   constraint locks the wire surface against typos and lets the
--   planner treat outcome as a low-cardinality discrete column for
--   any future per-outcome rollup. We use a CHECK rather than a
--   PG ENUM type because enums require a migration to extend
--   (ALTER TYPE … ADD VALUE) and the outcome surface is expected
--   to evolve in lockstep with the service layer; a TEXT column +
--   CHECK is the lower-friction shape.
--
-- Why `recipient_user_hash` BYTEA (not UUID).
--   The recipient identity is the BLAKE2b-256 pseudonym of the
--   recipient mailbox address — the same shape `users.email_hash`
--   carries since 0001_init.up.sql. Storing the hash (not the raw
--   email) preserves the privacy invariant that the management
--   plane never sees plaintext recipient addresses; using BYTEA
--   matches the `communication_histories.recipient_hash` shape so
--   future joins (e.g. "what messages did Bob try to self-release
--   in the last 7 days") are SARGable on the same column shape.
--
-- RLS impact.
--   Both new tables are tenant-scoped and added to the RLS policy
--   set established in 0018_row_level_security.up.sql. The
--   `tenant_isolation` policy gates every read and write against
--   `current_setting('sn360.tenant_id')`. The matching entries in
--   `cmd/sn360-es-tenant-lint/main.go::tenantScopedTables` are
--   updated in the same PR so the drift test stays green.

BEGIN;

-- ----------------------------------------------------------------------
-- 1. tenant_release_policies — per-tenant self-service knobs
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenant_release_policies (
    tenant_id                          UUID        PRIMARY KEY
        REFERENCES tenants(id) ON DELETE CASCADE,
    -- Per-recipient hourly cap on self-service releases. 0 disables
    -- self-service for the tenant; the policy lookup treats the
    -- "no row" case as the default (5) so a fresh tenant gets the
    -- baseline experience without an extra migration.
    quarantine_self_release_per_hour   INT         NOT NULL DEFAULT 5
        CHECK (quarantine_self_release_per_hour >= 0),
    created_at                         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------------
-- 2. quarantine_release_audit — append-only self-release attempts
-- ----------------------------------------------------------------------

-- The partitioned parent. PK includes `tenant_id` because PG
-- requires the partition key in any uniqueness constraint on a
-- partitioned table. The composite (id, tenant_id) preserves the
-- (id) identity for any consumer that wants to look up a row by
-- its UUID while keeping tenant_id in the row uniqueness check —
-- same pattern as `communication_histories`.
CREATE TABLE quarantine_release_audit (
    id                    UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id             UUID        NOT NULL,
    pseudo_message_id     TEXT        NOT NULL,
    recipient_user_hash   BYTEA       NOT NULL,
    outcome               TEXT        NOT NULL
        CHECK (outcome IN (
            'released',
            'rate_limited',
            'tier2_blocked',
            'release_refused',
            'token_expired',
            'invalid_token',
            'already_released',
            'not_found'
        )),
    reason                TEXT        NOT NULL DEFAULT '',
    correlation_id        TEXT        NOT NULL DEFAULT '',
    requested_at          TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, tenant_id),
    CONSTRAINT quarantine_release_audit_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) PARTITION BY HASH (tenant_id);

-- 32 HASH partitions, two-digit zero-padded suffix so
-- lexicographic sort matches numeric sort across all 32. Same
-- naming convention as `communication_histories_pNN` from 0019.
DO $partitions$
DECLARE
    bucket  INTEGER;
    part    TEXT;
BEGIN
    FOR bucket IN 0..31 LOOP
        part := format('quarantine_release_audit_p%s', lpad(bucket::text, 2, '0'));
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF quarantine_release_audit FOR VALUES WITH (MODULUS 32, REMAINDER %s)',
            part, bucket);
    END LOOP;
END
$partitions$;

-- The rate-limit lookup walks (tenant_id, recipient_user_hash,
-- requested_at). The index supports both that hot path and
-- per-tenant timeline scans (operator views: "show me all
-- self-release activity for tenant X in the last 24h"). The
-- DESC ordering on requested_at lets `ORDER BY requested_at DESC
-- LIMIT N` use the index directly.
CREATE INDEX IF NOT EXISTS idx_qra_tenant_recipient_requested
    ON quarantine_release_audit (tenant_id, recipient_user_hash, requested_at DESC);

-- Per-message lookup index: "show me every self-release attempt
-- against pseudo_message_id X". Used by the message-trail
-- investigation view (WS-3b) to surface release history alongside
-- the verdict timeline.
CREATE INDEX IF NOT EXISTS idx_qra_tenant_message_requested
    ON quarantine_release_audit (tenant_id, pseudo_message_id, requested_at DESC);

-- ----------------------------------------------------------------------
-- 3. RLS — defence-in-depth tenant isolation
--    Both tables join the policy set from 0018_row_level_security.up.sql.
--    The same `tenant_isolation` policy predicate is applied so an
--    unbound session sees zero rows (fail closed) and a bound
--    session sees only its own tenant's rows.
-- ----------------------------------------------------------------------

ALTER TABLE tenant_release_policies     ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_release_policies     FORCE  ROW LEVEL SECURITY;
ALTER TABLE quarantine_release_audit    ENABLE ROW LEVEL SECURITY;
ALTER TABLE quarantine_release_audit    FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON tenant_release_policies;
CREATE POLICY tenant_isolation ON tenant_release_policies
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON quarantine_release_audit;
CREATE POLICY tenant_isolation ON quarantine_release_audit
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

-- ----------------------------------------------------------------------
-- 4. sn360_app grants — least-privilege per table.
--
-- 0018 granted full CRUD on every tenant-scoped table to sn360_app,
-- which is the right shape for general business tables that the app
-- mutates freely (users, vendors, scores, …). The two tables added
-- here intentionally narrow that pattern:
--
--   * tenant_release_policies — SELECT, INSERT, UPDATE. The
--     repository upserts via `INSERT … ON CONFLICT DO UPDATE`
--     (see internal/repository/tenant_release_policy.go) and never
--     issues a DELETE; revoking DELETE eliminates an entire
--     code path the app does not exercise.
--
--   * quarantine_release_audit — SELECT, INSERT only. The audit
--     table is documented as append-only and the repository
--     interface (Record / CountRecentByRecipient / ListByMessage)
--     exposes no update or delete entry point. Withholding UPDATE
--     and DELETE means a future bug, accidental EXEC, or
--     compromised app session cannot rewrite or erase audit rows
--     — exactly the defense-in-depth shape a security audit trail
--     needs. Tenant deletion (which would cascade-clean these
--     rows via the FK ON DELETE CASCADE) happens via a separate
--     admin role, not sn360_app, so the cascade path is
--     unaffected.
--
-- If the application ever genuinely needs to rewrite or expire
-- audit rows (e.g. a retention sweep), that operation should live
-- under a distinct role with explicit DELETE, not by widening the
-- production app's grants.
-- ----------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE         ON tenant_release_policies     TO sn360_app;
GRANT SELECT, INSERT                 ON quarantine_release_audit    TO sn360_app;

COMMIT;
