-- 0018_row_level_security.up.sql
--
-- Defence-in-depth tenant isolation: every tenant-scoped table is
-- gated by a Postgres Row-Level Security (RLS) policy that compares
-- the row's `tenant_id` against the session GUC `sn360.tenant_id`.
--
-- Today the application layer is the only thing preventing one
-- tenant from reading another tenant's rows. The static
-- `cmd/sn360-es-tenant-lint` analyser catches forgotten
-- `WHERE tenant_id = $N` clauses at build time, but that is a
-- *first* line of defence — a malicious query string that the
-- analyser didn't anticipate, or a future repository written by
-- someone who doesn't know the lint exists, would punch right
-- through. RLS closes the loop at the database boundary: the
-- planner refuses to return rows the session is not authorised
-- to see, regardless of what the SQL string requested.
--
-- Why FORCE.
--   `ALTER TABLE … FORCE ROW LEVEL SECURITY` makes RLS apply even
--   to the table owner. Without FORCE, RLS is silently disabled
--   for owners — and the sn360-es application historically
--   connects as the schema owner. FORCE turns the policy into a
--   real boundary instead of a developer-friendly hint.
--
-- The cross-tenant escape hatch.
--   A small set of queries are genuinely cross-tenant:
--     * worker fan-out (e.g. relationship_worker / cleanup_worker
--       iterating `IterateActive` to walk every tenant);
--     * boot-time OAuth provider-registry rebuild
--       (`internal/service/onboarding/token_store_pg.PgTokenStore.ListAll`);
--     * partition maintenance (CREATE/ATTACH/DETACH PARTITION runs
--       as DDL, separate from this policy, but listed here for
--       completeness).
--   These callers are already opt-in via the
--   `tenant-lint:cross-tenant` annotation and the application
--   layer asserts the cross-tenant contract before issuing the
--   query (e.g. ListAll returns (tenant_id, provider) tuples that
--   the registry re-keys per tenant downstream). To let those
--   queries continue working under RLS, the policy admits two
--   modes:
--
--     1. The normal mode — `current_setting('sn360.tenant_id')`
--        is set to a UUID and the row's `tenant_id` matches.
--     2. The cross-tenant mode — `current_setting('sn360.cross_tenant')`
--        is the literal string `'on'`. The Go DB wrapper sets
--        this GUC for the lifetime of a pinned connection inside
--        a `WithCrossTenant` scope, and unsets it on release.
--
--   Both GUCs are read with `current_setting(name, true)` so an
--   unset variable is `NULL` rather than an error — i.e. a
--   forgotten `WithTenant` binding deterministically returns
--   zero rows (fail closed), not a runtime error that crashes
--   the request.
--
-- Why we don't make `sn360_app` the connect role today.
--   This migration creates the `sn360_app` role but does NOT make
--   it the connect role automatically. A future infra PR (Helm /
--   Terraform) will provision a least-privilege login that
--   inherits from `sn360_app` and replace the existing connect
--   string. Doing both in one migration would require a
--   coordinated config-and-data-plane change; landing the role
--   here keeps the migration replayable and idempotent without
--   forcing an environment rotation.
--
-- Idempotence.
--   The DROP POLICY IF EXISTS / DO $$ … IF NOT EXISTS guards
--   make this migration safe to apply against an environment that
--   already has the role or policies — necessary for QA / UAT
--   environments that were patched manually during the rollout.

BEGIN;

-- ----------------------------------------------------------------------
-- 1. sn360_app role (NOLOGIN; the connect login GRANTs sn360_app TO it).
-- ----------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sn360_app') THEN
        CREATE ROLE sn360_app NOLOGIN;
    END IF;
END $$;

-- ----------------------------------------------------------------------
-- 2. Enable + FORCE RLS on every tenant-scoped table.
--    The 16 tables here MUST stay in sync with
--    `cmd/sn360-es-tenant-lint/main.go::tenantScopedTables`. A drift
--    test in `cmd/sn360-es-tenant-lint` asserts that every entry in
--    that map appears in this migration.
-- ----------------------------------------------------------------------

ALTER TABLE users                     ENABLE ROW LEVEL SECURITY;
ALTER TABLE users                     FORCE  ROW LEVEL SECURITY;
ALTER TABLE groups                    ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups                    FORCE  ROW LEVEL SECURITY;
ALTER TABLE labels                    ENABLE ROW LEVEL SECURITY;
ALTER TABLE labels                    FORCE  ROW LEVEL SECURITY;
ALTER TABLE score_engine              ENABLE ROW LEVEL SECURITY;
ALTER TABLE score_engine              FORCE  ROW LEVEL SECURITY;
ALTER TABLE vendors                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendors                   FORCE  ROW LEVEL SECURITY;
ALTER TABLE evaluation_results        ENABLE ROW LEVEL SECURITY;
ALTER TABLE evaluation_results        FORCE  ROW LEVEL SECURITY;
ALTER TABLE communication_histories   ENABLE ROW LEVEL SECURITY;
ALTER TABLE communication_histories   FORCE  ROW LEVEL SECURITY;
ALTER TABLE campaigns                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns                 FORCE  ROW LEVEL SECURITY;
ALTER TABLE simulation_results        ENABLE ROW LEVEL SECURITY;
ALTER TABLE simulation_results        FORCE  ROW LEVEL SECURITY;
ALTER TABLE escalation_tickets        ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalation_tickets        FORCE  ROW LEVEL SECURITY;
ALTER TABLE audit_logs                ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs                FORCE  ROW LEVEL SECURITY;
ALTER TABLE feedback_events           ENABLE ROW LEVEL SECURITY;
ALTER TABLE feedback_events           FORCE  ROW LEVEL SECURITY;
ALTER TABLE oauth_tokens              ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_tokens              FORCE  ROW LEVEL SECURITY;
ALTER TABLE sync_checkpoints          ENABLE ROW LEVEL SECURITY;
ALTER TABLE sync_checkpoints          FORCE  ROW LEVEL SECURITY;
ALTER TABLE user_behavioral_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_behavioral_baselines FORCE  ROW LEVEL SECURITY;
ALTER TABLE org_graphs                ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_graphs                FORCE  ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------
-- 3. tenant_isolation policy: row visible iff session tenant matches
--    OR cross-tenant bypass is explicitly active. Same predicate is
--    used for USING (read filter) and WITH CHECK (write filter) so
--    INSERTs / UPDATEs can never plant a row under another tenant's
--    UUID.
--
--    `current_setting(name, true)` returns NULL (not an error) when
--    the GUC is unset — combined with the OR clause that means an
--    unbound session deterministically sees zero rows. Fail closed.
--
--    The `nullif(..., '')` wrapper handles a Postgres quirk: once
--    a custom GUC (unregistered with DefineCustomVariable) is SET on
--    a session, RESETting it does NOT make `current_setting` return
--    NULL — it returns the literal empty string instead. That
--    matters here because the pool reuses connections: once a conn
--    has carried a `WithTenant` binding and been released back to
--    the pool, the next consumer's `current_setting` call returns
--    '' rather than NULL, and the cast `''::uuid` raises 22P02.
--    `nullif(x, '')` normalises both the "never set" and
--    "set then reset" cases to NULL, restoring the fail-closed
--    invariant.
-- ----------------------------------------------------------------------

DROP POLICY IF EXISTS tenant_isolation ON users;
CREATE POLICY tenant_isolation ON users
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON groups;
CREATE POLICY tenant_isolation ON groups
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON labels;
CREATE POLICY tenant_isolation ON labels
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON score_engine;
CREATE POLICY tenant_isolation ON score_engine
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON vendors;
CREATE POLICY tenant_isolation ON vendors
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON evaluation_results;
CREATE POLICY tenant_isolation ON evaluation_results
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON communication_histories;
CREATE POLICY tenant_isolation ON communication_histories
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON campaigns;
CREATE POLICY tenant_isolation ON campaigns
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON simulation_results;
CREATE POLICY tenant_isolation ON simulation_results
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON escalation_tickets;
CREATE POLICY tenant_isolation ON escalation_tickets
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON audit_logs;
CREATE POLICY tenant_isolation ON audit_logs
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON feedback_events;
CREATE POLICY tenant_isolation ON feedback_events
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

-- oauth_tokens is the one tenant-scoped table whose `tenant_id`
-- column was declared TEXT (migration 0005_oauth_tokens), not UUID.
-- A TEXT-to-UUID equality cannot use Postgres's implicit operator
-- resolution, so the policy expression has to compare in TEXT space.
-- Once a future migration normalises oauth_tokens.tenant_id to UUID,
-- this branch collapses to the same form as the other 15 tables.
DROP POLICY IF EXISTS tenant_isolation ON oauth_tokens;
CREATE POLICY tenant_isolation ON oauth_tokens
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON sync_checkpoints;
CREATE POLICY tenant_isolation ON sync_checkpoints
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON user_behavioral_baselines;
CREATE POLICY tenant_isolation ON user_behavioral_baselines
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

DROP POLICY IF EXISTS tenant_isolation ON org_graphs;
CREATE POLICY tenant_isolation ON org_graphs
    USING (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('sn360.tenant_id', true), '')::uuid
        OR coalesce(current_setting('sn360.cross_tenant', true), 'off') = 'on'
    );

-- ----------------------------------------------------------------------
-- 4. Grant table-level rights on every tenant-scoped table to
--    sn360_app. A future deployment-PR will provision a least-
--    privilege login that inherits from sn360_app; until then the
--    grants exist so role membership Just Works the day that rotation
--    lands.
-- ----------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE, DELETE ON users                     TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON groups                    TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON labels                    TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON score_engine              TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON vendors                   TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON evaluation_results        TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON communication_histories   TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON campaigns                 TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON simulation_results        TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON escalation_tickets        TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_logs                TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON feedback_events           TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_tokens              TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sync_checkpoints          TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_behavioral_baselines TO sn360_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON org_graphs                TO sn360_app;

COMMIT;
