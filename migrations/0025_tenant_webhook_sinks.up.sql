-- 0025_tenant_webhook_sinks.up.sql
--
-- WS-5B.2: per-tenant webhook sinks for standalone deployments.
--
-- Customers running sn360-es WITHOUT the sn360-security-platform SOC
-- need an egress path for evaluation verdicts into their own SIEM
-- (Splunk HEC, Elastic webhook input, Sentinel Logic Apps, Chronicle
-- forwarder, etc.). The WS-5A.1 NATS bridge handles the SOC-attached
-- case; this migration provisions the schema for the standalone case:
--
--   1. `tenant_webhook_sinks` — per-tenant configuration: target URL
--      (HTTPS only), HMAC secret (AES-encrypted via the existing
--      privacy/Encryptor KMS envelope), output format (`ecs` or `cef`),
--      event filters (min-tier, categories, …), enabled flag.
--      UNIQUE (tenant_id, name) so a tenant can register multiple
--      named sinks (e.g. "splunk-prod", "elastic-staging") without
--      collisions.
--
--   2. `tenant_webhook_sink_audit` — change history + soft-delete
--      trail. INSERT-ON-CONFLICT idempotency on (tenant_id, dedup_id)
--      mirrors the email_verdict_audit pattern from migration 0021 so
--      the DLQ consumer (cmd/sn360-es/consumers_webhook_dlq.go) can
--      record final-failure rows without producing duplicates on
--      JetStream re-delivery. Records the sink ID + name only — the
--      HMAC secret is NEVER persisted to audit rows (see the no-secret
--      rule in pkg/sinks/webhook).
--
-- Schema design notes
-- -------------------
--
-- hmac_secret is stored as BYTEA holding the AES-GCM envelope blob
-- produced by privacy.Encryptor.Encrypt under the tenant's KMS key.
-- The plaintext 32-byte secret is shown to the customer exactly once
-- in the create response and is never recoverable from the database.
-- Rotating the secret requires a PATCH that generates a fresh secret
-- and returns it once.
--
-- format is constrained to the two SIEM-ingestion formats sn360-es
-- ships: 'ecs' (Elastic Common Schema, JSON) and 'cef' (ArcSight
-- Common Event Format, pipe-delimited). The CHECK constraint pins
-- the closed set so a typo doesn't silently fall through to a
-- "no-op formatter" code path.
--
-- url is TEXT, validated at write time by the handler. The DB-level
-- CHECK enforces the HTTPS-only invariant defence-in-depth so a
-- direct SQL insert (e.g. from a migration tool or admin REPL)
-- cannot bypass the application-layer validation.
--
-- event_filters is JSONB so additional filter knobs (min-tier,
-- primary-category allowlist, rate-limit override) can be added
-- without further migrations. The handler validates the shape;
-- unknown keys are ignored by the dispatcher so a forward-rolling
-- deployment can read rows written by a newer handler.
--
-- deleted_at is the soft-delete marker. The dispatcher only loads
-- enabled=true AND deleted_at IS NULL rows; the audit table
-- preserves the trail.
--
-- Lock-acquisition discipline mirrors migration 0021.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- ----------------------------------------------------------------------
-- 1. tenant_webhook_sinks — per-tenant SIEM webhook configuration
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenant_webhook_sinks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT        NOT NULL,
    -- HTTPS-only customer endpoint. Application layer enforces the
    -- scheme on POST/PATCH; the DB-level CHECK is defence-in-depth.
    url           TEXT        NOT NULL,
    -- AES-GCM envelope blob produced by privacy.Encryptor under the
    -- tenant's KMS key. The plaintext 32-byte HMAC secret is shown
    -- to the operator ONCE in the create response and never logged
    -- thereafter.
    hmac_secret   BYTEA       NOT NULL,
    format        TEXT        NOT NULL DEFAULT 'ecs',
    event_filters JSONB       NOT NULL DEFAULT '{}'::jsonb,
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at    TIMESTAMPTZ NULL,
    UNIQUE (tenant_id, name)
);

-- format closed-set: must stay in sync with pkg/sinks/webhook
-- FormatECS / FormatCEF Go constants. Tests assert.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'tenant_webhook_sinks_format_check'
    ) THEN
        ALTER TABLE tenant_webhook_sinks
            ADD CONSTRAINT tenant_webhook_sinks_format_check
            CHECK (format IN ('ecs', 'cef'));
    END IF;
END $$;

-- HTTPS-only: defence-in-depth against a direct SQL insert that
-- bypasses the handler's scheme validation. Case-insensitive prefix
-- check because RFC 3986 allows the scheme in any case.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'tenant_webhook_sinks_url_https_check'
    ) THEN
        ALTER TABLE tenant_webhook_sinks
            ADD CONSTRAINT tenant_webhook_sinks_url_https_check
            CHECK (url ILIKE 'https://%');
    END IF;
END $$;

-- Dispatcher hot-path index: load enabled sinks for a tenant.
-- Partial-index on (deleted_at IS NULL AND enabled = TRUE) keeps the
-- index small and the lookup an index-only scan.
CREATE INDEX IF NOT EXISTS idx_tenant_webhook_sinks_tenant_enabled
    ON tenant_webhook_sinks (tenant_id)
    WHERE deleted_at IS NULL AND enabled = TRUE;

-- ----------------------------------------------------------------------
-- 2. tenant_webhook_sink_audit — change history + DLQ final-fail trail
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenant_webhook_sink_audit (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The sink the audit row is for. We do NOT install a FK against
    -- tenant_webhook_sinks(id) because a hard-delete (future
    -- retention sweep) would orphan audit rows; the audit trail is
    -- intentionally durable beyond the sink lifecycle.
    sink_id       UUID        NOT NULL,
    sink_name     TEXT        NOT NULL,
    -- Closed-enum action: 'created', 'updated', 'deleted',
    -- 'secret_rotated', 'dispatch_failed' (DLQ final-fail emit).
    action        TEXT        NOT NULL,
    -- Free-form reason. For dispatch_failed: the last HTTP status +
    -- short cause string (no secrets, no payload). For
    -- update/secret_rotated: which fields changed.
    reason        TEXT        NULL,
    -- INSERT-ON-CONFLICT idempotency key. For CRUD audit rows the
    -- handler stamps a fresh UUID; for DLQ final-fail rows the
    -- consumer stamps sha256(sink_id|event_message_id|attempt) so a
    -- JetStream re-delivery of the same final-fail does not
    -- duplicate the row.
    dedup_id      TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, dedup_id)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'tenant_webhook_sink_audit_action_check'
    ) THEN
        ALTER TABLE tenant_webhook_sink_audit
            ADD CONSTRAINT tenant_webhook_sink_audit_action_check
            CHECK (action IN ('created', 'updated', 'deleted', 'secret_rotated', 'dispatch_failed'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_tenant_webhook_sink_audit_tenant_created
    ON tenant_webhook_sink_audit (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tenant_webhook_sink_audit_sink
    ON tenant_webhook_sink_audit (tenant_id, sink_id, created_at DESC);

-- ----------------------------------------------------------------------
-- 3. Row-Level Security (mandatory — matches every other tenant-scoped
--    table; tenant-lint enforces registration in
--    cmd/sn360-es-tenant-lint/main.go)
-- ----------------------------------------------------------------------

ALTER TABLE tenant_webhook_sinks         ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_webhook_sinks         FORCE  ROW LEVEL SECURITY;
ALTER TABLE tenant_webhook_sink_audit    ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_webhook_sink_audit    FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON tenant_webhook_sinks;
CREATE POLICY tenant_isolation ON tenant_webhook_sinks
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON tenant_webhook_sink_audit;
CREATE POLICY tenant_isolation ON tenant_webhook_sink_audit
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );
