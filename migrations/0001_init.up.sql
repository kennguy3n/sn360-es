-- 0001_init.up.sql
-- Initial SN360-ES schema. Tables are derived from `internal/dto/`,
-- `internal/service/` repository interfaces, and the Management Domain
-- section of ARCHITECTURE.md.
--
-- All sensitive columns are stored as Blake2-hashed pseudonyms or
-- AES-256-GCM-encrypted ciphertext per the privacy layer; this schema
-- only stores envelope metadata so that key rotation (and cryptographic
-- erasure on tenant delete) can operate without re-reading values.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------------
-- 1. Tenants
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT        NOT NULL UNIQUE,
    display_name    TEXT        NOT NULL,
    provider        TEXT        NOT NULL CHECK (provider IN ('gws', 'o365')),
    primary_domain  TEXT        NOT NULL,
    region          TEXT        NOT NULL DEFAULT 'ap-southeast-1',
    kms_key_arn     TEXT        NOT NULL,
    score_base      INT         NOT NULL DEFAULT 100,
    retention_days  INT         NOT NULL DEFAULT 90,
    locale          TEXT        NOT NULL DEFAULT 'en',
    status          TEXT        NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'suspended', 'deleted')),
    metadata        JSONB       NOT NULL DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenants_status      ON tenants (status);
CREATE INDEX IF NOT EXISTS idx_tenants_provider    ON tenants (provider);

-- ----------------------------------------------------------------------
-- 2. Users (pseudonymised — store hash only)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email_hash        BYTEA       NOT NULL,
    role              TEXT        NOT NULL DEFAULT 'user',
    department        TEXT,
    sensitivity_tier  TEXT        NOT NULL DEFAULT 'standard'
                      CHECK (sensitivity_tier IN ('standard', 'elevated', 'executive')),
    resilience_score  INT         NOT NULL DEFAULT 0
                      CHECK (resilience_score BETWEEN 0 AND 100),
    vulnerability     INT         NOT NULL DEFAULT 0
                      CHECK (vulnerability BETWEEN 0 AND 100),
    locale            TEXT        NOT NULL DEFAULT 'en',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, email_hash)
);

CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);

-- ----------------------------------------------------------------------
-- 3. Groups (organisational units)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS groups (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT        NOT NULL,
    description   TEXT,
    risk_class    TEXT        NOT NULL DEFAULT 'standard'
                  CHECK (risk_class IN ('standard', 'finance', 'executive', 'hr', 'it')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS group_memberships (
    group_id    UUID        NOT NULL REFERENCES groups(id)  ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, user_id)
);

-- ----------------------------------------------------------------------
-- 4. Labels (per-provider tier + category labels)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS labels (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider      TEXT        NOT NULL CHECK (provider IN ('gws', 'o365')),
    tier          TEXT        NOT NULL,
    category      TEXT,
    name          TEXT        NOT NULL,
    color_bg      TEXT,
    color_fg      TEXT,
    preset        INT,
    visible       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, tier, category)
);

CREATE INDEX IF NOT EXISTS idx_labels_tenant_provider ON labels (tenant_id, provider);

-- ----------------------------------------------------------------------
-- 5. Score engine (per-tenant scoring weights + thresholds)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS score_engine (
    tenant_id           UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    score_base          INT         NOT NULL DEFAULT 100,
    weight_ai           INT         NOT NULL DEFAULT 80,
    weight_rspamd       INT         NOT NULL DEFAULT 20,
    weight_attachments  INT         NOT NULL DEFAULT 0,
    weight_links        INT         NOT NULL DEFAULT 0,
    threshold_blocked   INT         NOT NULL DEFAULT 85,
    threshold_high      INT         NOT NULL DEFAULT 70,
    threshold_warning   INT         NOT NULL DEFAULT 50,
    threshold_caution   INT         NOT NULL DEFAULT 30,
    threshold_info      INT         NOT NULL DEFAULT 15,
    subject_tag_enabled BOOLEAN     NOT NULL DEFAULT FALSE,
    subject_tag_prefix  TEXT        NOT NULL DEFAULT 'SN360',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        threshold_blocked > threshold_high
        AND threshold_high > threshold_warning
        AND threshold_warning > threshold_caution
        AND threshold_caution > threshold_info
    )
);

-- ----------------------------------------------------------------------
-- 6. Email classifications (free / disposable / anonymous domain lists)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS email_classifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT        NOT NULL,
    classification  TEXT        NOT NULL
                    CHECK (classification IN ('FREE', 'DISPOSABLE', 'ANONYMOUS', 'CORPORATE')),
    source          TEXT        NOT NULL DEFAULT 'manual',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (domain, classification)
);

CREATE INDEX IF NOT EXISTS idx_email_classifications_domain ON email_classifications (domain);

-- ----------------------------------------------------------------------
-- 7. Vendors (per-tenant approved senders)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS vendors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain          TEXT        NOT NULL,
    display_name    TEXT,
    approved        BOOLEAN     NOT NULL DEFAULT FALSE,
    auto_discovered BOOLEAN     NOT NULL DEFAULT FALSE,
    confidence      NUMERIC(5,2) NOT NULL DEFAULT 0,
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_vendors_tenant   ON vendors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_vendors_approved ON vendors (tenant_id, approved);

-- ----------------------------------------------------------------------
-- 8. Evaluation results (pseudonymised; PII-free; encrypted reasons)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS evaluation_results (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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
    UNIQUE (tenant_id, message_id_hash)
);

CREATE INDEX IF NOT EXISTS idx_eval_results_tenant_evaluated
    ON evaluation_results (tenant_id, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_eval_results_tier
    ON evaluation_results (tenant_id, tier);

-- ----------------------------------------------------------------------
-- 9. Communication histories (sender-recipient relationship aggregate)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS communication_histories (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sender_hash         BYTEA       NOT NULL,
    recipient_hash      BYTEA       NOT NULL,
    sender_domain_hash  BYTEA       NOT NULL,
    count_7d            INT         NOT NULL DEFAULT 0,
    count_30d           INT         NOT NULL DEFAULT 0,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    relationship        TEXT        NOT NULL DEFAULT '',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, sender_hash, recipient_hash)
);

CREATE INDEX IF NOT EXISTS idx_comm_hist_tenant_sender
    ON communication_histories (tenant_id, sender_hash);
CREATE INDEX IF NOT EXISTS idx_comm_hist_tenant_recipient
    ON communication_histories (tenant_id, recipient_hash);
CREATE INDEX IF NOT EXISTS idx_comm_hist_relationship
    ON communication_histories (tenant_id, relationship);
-- Supports ListByTenant: `WHERE tenant_id=$1 AND last_seen_at >= $2
-- ORDER BY last_seen_at DESC`. The DESC on the index column lets
-- the planner return rows already-sorted, avoiding a per-tenant
-- sort step on top of the bitmap scan.
--
-- An identical CREATE INDEX IF NOT EXISTS also ships as a separate
-- numbered migration (0016_comm_history_last_seen_index) so
-- environments that already applied 0001 at an earlier revision
-- pick the index up via `migrate up`. IF NOT EXISTS makes both
-- paths idempotent: a fresh deployment creates the index here at
-- init time; 0016 becomes a no-op. An existing deployment skipped
-- this line when it ran 0001 at the older revision and creates the
-- index when it later applies 0016.
CREATE INDEX IF NOT EXISTS idx_comm_hist_tenant_last_seen
    ON communication_histories (tenant_id, last_seen_at DESC);

-- ----------------------------------------------------------------------
-- 10. Campaigns (phishing-simulation lifecycle)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS campaigns (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT        NOT NULL,
    template_id   TEXT        NOT NULL,
    difficulty    TEXT        NOT NULL CHECK (difficulty IN ('easy', 'medium', 'hard')),
    status        TEXT        NOT NULL DEFAULT 'draft'
                  CHECK (status IN ('draft', 'scheduled', 'sending', 'active', 'completed', 'cancelled')),
    target_group  UUID        REFERENCES groups(id) ON DELETE SET NULL,
    scheduled_at  TIMESTAMPTZ,
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    metadata      JSONB       NOT NULL DEFAULT '{}'::JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_status ON campaigns (tenant_id, status);

-- ----------------------------------------------------------------------
-- 11. Simulation results (per-target interaction tracking)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS simulation_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id     UUID        NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id)   ON DELETE CASCADE,
    target_hash     BYTEA       NOT NULL,
    delivered_at    TIMESTAMPTZ,
    opened          BOOLEAN     NOT NULL DEFAULT FALSE,
    clicked         BOOLEAN     NOT NULL DEFAULT FALSE,
    submitted_creds BOOLEAN     NOT NULL DEFAULT FALSE,
    reported        BOOLEAN     NOT NULL DEFAULT FALSE,
    ignored         BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (campaign_id, target_hash)
);

CREATE INDEX IF NOT EXISTS idx_simulation_results_tenant
    ON simulation_results (tenant_id, campaign_id);

-- ----------------------------------------------------------------------
-- 12. Escalation tickets (SN360 SecOps queue)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS escalation_tickets (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ticket_number     TEXT        NOT NULL UNIQUE,
    trigger_reason    TEXT        NOT NULL,
    priority          TEXT        NOT NULL DEFAULT 'normal'
                      CHECK (priority IN ('low', 'normal', 'high', 'critical')),
    status            TEXT        NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
    message_id_hash   BYTEA,
    correlation_id    TEXT,
    context           JSONB       NOT NULL DEFAULT '{}'::JSONB,
    assigned_to       TEXT,
    resolved_at       TIMESTAMPTZ,
    resolution        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_escalation_tickets_status   ON escalation_tickets (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_escalation_tickets_priority ON escalation_tickets (tenant_id, priority);

-- ----------------------------------------------------------------------
-- 13. Audit logs (append-only, no PII)
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    actor           TEXT        NOT NULL,
    action          TEXT        NOT NULL,
    target_type     TEXT        NOT NULL,
    target_hash     BYTEA,
    correlation_id  TEXT,
    metadata        JSONB       NOT NULL DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_action
    ON audit_logs (tenant_id, action, created_at DESC);

COMMIT;
