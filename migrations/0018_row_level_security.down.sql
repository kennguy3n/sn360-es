-- 0018_row_level_security.down.sql
--
-- Reverse of 0018_row_level_security.up.sql.
--
-- Drops the per-table tenant_isolation policy, disables RLS, revokes
-- the tenant-scoped table grants from sn360_app, and finally drops
-- the role. Each step is wrapped in IF EXISTS / IF NOT EXISTS guards
-- so the migration is idempotent against environments that have
-- already been partially rolled back.
--
-- After this migration the database is back to the pre-RLS state:
-- the only thing enforcing tenant isolation is the application layer
-- (`WHERE tenant_id = $N`) + the build-time `cmd/sn360-es-tenant-lint`
-- analyser.

BEGIN;

-- ----------------------------------------------------------------------
-- 1. Drop the per-table tenant_isolation policies and disable RLS.
-- ----------------------------------------------------------------------

DROP POLICY IF EXISTS tenant_isolation ON users;
ALTER TABLE users                     DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON groups;
ALTER TABLE groups                    DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON labels;
ALTER TABLE labels                    DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON score_engine;
ALTER TABLE score_engine              DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON vendors;
ALTER TABLE vendors                   DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON evaluation_results;
ALTER TABLE evaluation_results        DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON communication_histories;
ALTER TABLE communication_histories   DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON campaigns;
ALTER TABLE campaigns                 DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON simulation_results;
ALTER TABLE simulation_results        DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON escalation_tickets;
ALTER TABLE escalation_tickets        DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON audit_logs;
ALTER TABLE audit_logs                DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON feedback_events;
ALTER TABLE feedback_events           DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON oauth_tokens;
ALTER TABLE oauth_tokens              DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON sync_checkpoints;
ALTER TABLE sync_checkpoints          DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON user_behavioral_baselines;
ALTER TABLE user_behavioral_baselines DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON org_graphs;
ALTER TABLE org_graphs                DISABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------
-- 2. Revoke sn360_app's table grants and drop the role.
--
-- Postgres has no `REVOKE ... IF EXISTS <role>` syntax, and bare
-- REVOKEs against a missing role raise ERROR which aborts the entire
-- BEGIN/COMMIT transaction — rolling back the policy drops above
-- alongside the failed REVOKEs. Wrap the REVOKEs (and the DROP ROLE)
-- in a single PL/pgSQL DO block that short-circuits when sn360_app is
-- already absent, so the down migration stays idempotent against
-- environments that have been partially rolled back manually.
-- ----------------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sn360_app') THEN
        REVOKE ALL ON users                     FROM sn360_app;
        REVOKE ALL ON groups                    FROM sn360_app;
        REVOKE ALL ON labels                    FROM sn360_app;
        REVOKE ALL ON score_engine              FROM sn360_app;
        REVOKE ALL ON vendors                   FROM sn360_app;
        REVOKE ALL ON evaluation_results        FROM sn360_app;
        REVOKE ALL ON communication_histories   FROM sn360_app;
        REVOKE ALL ON campaigns                 FROM sn360_app;
        REVOKE ALL ON simulation_results        FROM sn360_app;
        REVOKE ALL ON escalation_tickets        FROM sn360_app;
        REVOKE ALL ON audit_logs                FROM sn360_app;
        REVOKE ALL ON feedback_events           FROM sn360_app;
        REVOKE ALL ON oauth_tokens              FROM sn360_app;
        REVOKE ALL ON sync_checkpoints          FROM sn360_app;
        REVOKE ALL ON user_behavioral_baselines FROM sn360_app;
        REVOKE ALL ON org_graphs                FROM sn360_app;

        DROP ROLE sn360_app;
    END IF;
END
$$;

COMMIT;
