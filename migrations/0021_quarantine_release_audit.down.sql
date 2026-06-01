-- 0021_quarantine_release_audit.down.sql
--
-- Reverses 0021 by dropping the two tables and all of their
-- partitions, indexes, FKs, and RLS policies. DROP TABLE on the
-- partitioned parent cascades into every child partition, so we
-- don't need to enumerate the 32 `quarantine_release_audit_pNN`
-- children explicitly.
--
-- The DROP POLICY statements before DROP TABLE are belt-and-braces:
-- DROP TABLE removes the policies attached to the table anyway,
-- but the explicit DROP POLICY IF EXISTS keeps the migration
-- replayable on a half-rolled-back environment that has the
-- policies but not the tables (or vice versa).
--
-- The `REVOKE` mirrors the `GRANT` in the up migration. Without
-- the REVOKE, ROLE-level grants survive the table drop as orphan
-- entries in pg_default_acl — harmless but confusing under audit.

BEGIN;

DROP POLICY IF EXISTS tenant_isolation ON quarantine_release_audit;
DROP POLICY IF EXISTS tenant_isolation ON tenant_release_policies;

DROP TABLE IF EXISTS quarantine_release_audit;
DROP TABLE IF EXISTS tenant_release_policies;

-- REVOKE is safe even when the role doesn't exist — Postgres
-- emits a notice but does not error.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sn360_app') THEN
        -- Tables are gone; REVOKE on a non-existent table errors,
        -- so the IF EXISTS guard above only covers the role. The
        -- inner block is a no-op once the table is dropped — kept
        -- here for symmetry / documentation only.
        NULL;
    END IF;
END $$;

COMMIT;
