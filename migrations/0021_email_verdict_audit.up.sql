-- 0021_email_verdict_audit.up.sql
--
-- WS-5A.6 cross-repo escalation ticket resolution sync.
--
-- The producer (kennguy3n/sn360-security-platform services/soc-triage)
-- publishes IncidentResolved envelopes on `soc.incident.resolved`
-- when a SOC analyst closes an incident whose evidence carries an
-- email correlation. This migration provisions the consumer-side
-- persistence:
--
--   1. `evaluation_results.final_verdict` — an analyst-driven
--      verdict override that takes precedence over the platform's
--      automated verdict (derived from tier + primary_category).
--      Nullable: NULL means "use the platform's automated verdict".
--
--   2. `banner_state` — per-(tenant, message_id_hash) banner
--      delivery state. Stamped by the existing action.banner
--      consumer (cmd/sn360-es/consumers_action.go handleActionBanner)
--      after the provider InjectBanner returns success. The WS-5A.6
--      resolver gates banner-reopen on
--      `banner_state.delivered_at IS NOT NULL` per the spec
--      invariant ("don't trigger a banner for an email the user
--      never saw").
--
--   3. `email_verdict_audit` — INSERT-ON-CONFLICT(tenant_id, dedup_id)
--      idempotency + audit trail. Exactly one row per consumer
--      invocation (success or skip-with-reason), keyed off the
--      cross-repo length-prefixed sha256(incident_id|resolved_at_unix_nano)
--      DedupID emitted by the producer. INSERT-ON-CONFLICT is the
--      defence-in-depth path against double-delivery beyond the
--      JetStream 600s duplicate window (manual replay, DLQ drain).
--
-- Schema design notes
-- -------------------
--
-- final_verdict allowed values: 'malicious','suspicious','benign'.
-- 'quarantine' is an action, not a verdict — it's enforced at the
-- tier-decider layer and is orthogonal to what the SOC analyst
-- can override.
--
-- banner_state.delivered_at is nullable rather than timestamped at
-- row creation because a banner-action consumer may have queued a
-- delivery that the provider then refused (quota, blocked domain,
-- recipient invalid). A row with delivered_at IS NULL means
-- "banner injection was attempted or scheduled but not confirmed
-- delivered to the recipient"; the resolver MUST gate the reopen
-- on a non-NULL delivered_at to honour the invariant.
--
-- email_verdict_audit is INTENTIONALLY non-partitioned. Audit
-- volume is bounded by the SOC analyst close-rate, which is
-- orders of magnitude lower than evaluation_results' per-email
-- write rate. The single-partition design avoids the
-- multi-partition index probe cost on the dedup-id lookup
-- (one B-tree on the UNIQUE constraint suffices) without
-- meaningful storage cost.
--
-- pseudo_message_id is TEXT, not BYTEA, because the producer
-- side ships it as a string and the consumer side persists it
-- as such for audit-trail readability. Cross-referencing back
-- into evaluation_results uses `message_id_hash = pseudo_message_id::BYTEA`
-- which is the same contract the WS-3b investigation API uses.
--
-- Lock-acquisition discipline
-- ---------------------------
--
-- Mirrors migration 0020's discipline. ALTER TABLE ADD COLUMN
-- IF NOT EXISTS for a nullable column without a DEFAULT is a
-- metadata-only change in PG ≥ 11. CREATE TABLE IF NOT EXISTS is
-- a no-op on existing schemas. CREATE INDEX IF NOT EXISTS is
-- bounded by statement_timeout. lock_timeout / statement_timeout
-- are SET LOCAL so they unwind at the end of the migration's
-- implicit transaction without affecting unrelated sessions.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- ----------------------------------------------------------------------
-- 1. evaluation_results.final_verdict — analyst override slot
-- ----------------------------------------------------------------------

ALTER TABLE evaluation_results
    ADD COLUMN IF NOT EXISTS final_verdict TEXT NULL;

-- The CHECK constraint is added as a separate statement (rather
-- than inline on the ALTER TABLE … ADD COLUMN) because PG before
-- 18 does not support NOT VALID on the ADD COLUMN form. Using a
-- separate ALTER TABLE … ADD CONSTRAINT IF NOT EXISTS keeps the
-- constraint name predictable (we reference it explicitly in the
-- down migration) and idempotent across re-runs.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'evaluation_results_final_verdict_check'
    ) THEN
        ALTER TABLE evaluation_results
            ADD CONSTRAINT evaluation_results_final_verdict_check
            CHECK (final_verdict IS NULL OR final_verdict IN ('malicious', 'suspicious', 'benign'));
    END IF;
END $$;

-- ----------------------------------------------------------------------
-- 2. banner_state — per-(tenant, message_id_hash) delivery state
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS banner_state (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id_hash BYTEA       NOT NULL,
    -- Stamped by handleActionBanner on a confirmed-delivered
    -- provider injection. NULL = banner was rendered / queued but
    -- the user has not observed it; the WS-5A.6 reopen path is
    -- gated on a non-NULL value here per the spec invariant.
    delivered_at    TIMESTAMPTZ NULL,
    -- Stamped by the WS-5A.6 resolver when it reopens the banner
    -- with an "Updated by SOC analyst" reason. NULL until the
    -- first reopen.
    reopened_at     TIMESTAMPTZ NULL,
    -- The most-recent reason text shown on the banner. NULL until
    -- the first injection writes it. The audit trail's `reason`
    -- column carries the per-event reason; this column tracks the
    -- current-displayed-reason for read-after-write UIs that
    -- render the live banner state.
    last_reason     TEXT        NULL,
    -- LabelProviderKind that injected the banner ("gmail",
    -- "microsoft", "imap"). Persisted so the WS-5A.6 reopen
    -- path can route to the same provider without re-deriving
    -- it from tenant config (which may have changed since the
    -- original injection). Nullable because legacy rows
    -- written before the reopen path landed lack this value;
    -- the resolver falls back to "" → providerRegistry's
    -- registered fallback when so.
    provider        TEXT        NULL,
    -- Plaintext provider message-id stamped at delivery time
    -- so the reopen path can re-target the same mail item
    -- without re-deriving it from pseudonymised inputs.
    -- Nullable for legacy rows; reopens with no recorded
    -- message_id fall back to the producer-stamped pseudo.
    delivered_message_id TEXT   NULL,
    -- Recipient email mailbox the banner was delivered to.
    -- Required by the provider InjectBanner call to route the
    -- update; nullable for legacy rows / non-injecting paths.
    delivered_email TEXT        NULL,
    -- Bookkeeping. created_at = first time a banner was rendered
    -- for this (tenant, message); updated_at = most-recent delivery
    -- or reopen.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, message_id_hash)
);

CREATE INDEX IF NOT EXISTS idx_banner_state_tenant_updated
    ON banner_state (tenant_id, updated_at DESC);

-- ----------------------------------------------------------------------
-- 3. email_verdict_audit — cross-repo audit + idempotency
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS email_verdict_audit (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Cross-repo length-prefixed sha256(incident_id|resolved_at_unix_nano)
    -- emitted by sn360-security-platform's IncidentResolved producer.
    -- The UNIQUE (tenant_id, dedup_id) constraint below is the
    -- consumer-side idempotency key — re-deliveries that escape
    -- the JetStream 600s duplicate window produce zero net effect
    -- via INSERT-ON-CONFLICT.
    dedup_id           TEXT        NOT NULL,
    -- Pseudonymised message ID from the producer's EmailLink. May
    -- be empty when the resolver could not locate a matching
    -- EvaluationResult (cross-tenant, race against retention drop,
    -- mis-stamped evidence) — the audit row still persists so
    -- ops can see exactly one row per consumer invocation.
    pseudo_message_id  TEXT        NOT NULL DEFAULT '',
    -- Platform's automated verdict at the time of flip. NULL when
    -- the consumer skipped (cross-tenant, no row found).
    original_verdict   TEXT        NULL,
    -- Analyst-driven verdict after flip. NULL when the consumer
    -- took a no-op path (matching verdict, telemetry-only, skip).
    new_verdict        TEXT        NULL,
    -- Producer-side enum: confirmed_threat|false_positive|benign|inconclusive.
    resolution         TEXT        NOT NULL,
    -- Pseudonymised analyst identifier from the producer.
    resolved_by        TEXT        NOT NULL,
    -- Producer-side wall-clock of the disposition.
    resolved_at        TIMESTAMPTZ NOT NULL,
    -- Source incident UUID (producer-side identifier). Pinned in
    -- the audit row for forensic cross-repo trace; NOT used as a
    -- foreign key because the sn360-security-platform incident
    -- table lives in a different database.
    source_incident_id TEXT        NOT NULL,
    -- Free-form reason: analyst notes from the producer, plus
    -- (on skip paths) the consumer-side rationale (e.g.
    -- "cross-tenant: payload tenant T1 vs row tenant T2",
    -- "no evaluation_results row for pseudo_message_id=X").
    reason             TEXT        NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, dedup_id)
);

CREATE INDEX IF NOT EXISTS idx_email_verdict_audit_tenant_created
    ON email_verdict_audit (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_verdict_audit_pseudo
    ON email_verdict_audit (tenant_id, pseudo_message_id, created_at DESC)
    WHERE pseudo_message_id <> '';

-- ----------------------------------------------------------------------
-- 4. Row-Level Security (defense-in-depth — see migration 0018)
-- ----------------------------------------------------------------------

ALTER TABLE banner_state            ENABLE ROW LEVEL SECURITY;
ALTER TABLE banner_state            FORCE  ROW LEVEL SECURITY;
ALTER TABLE email_verdict_audit     ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_verdict_audit     FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON banner_state;
CREATE POLICY tenant_isolation ON banner_state
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON email_verdict_audit;
CREATE POLICY tenant_isolation ON email_verdict_audit
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );
