-- 0024_threat_intel_feeds.down.sql
--
-- Reverses 0024 by dropping the two tables. DROP TABLE on
-- intel_feeds cascades through the `feed_id` FK so every row in
-- intel_indicators that referenced a dropped feed disappears
-- in the same transaction — there are no orphan rows to clean
-- up explicitly.
--
-- Drop order is intentional: `intel_indicators` first, then
-- `intel_feeds`. Reversing the order would also work because of
-- the CASCADE on the FK, but explicit ordering keeps the
-- migration readable and matches the up-script section ordering
-- so the diff between up.sql and down.sql is symmetric.
--
-- The DO-block REVOKE mirrors the up-script GRANT. It is wrapped
-- in `IF EXISTS (SELECT 1 FROM pg_roles ...)` because rolling
-- back in an environment that never had the sn360_app role
-- (single-user dev DBs, restored snapshots from older
-- environments) should not error.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sn360_app') THEN
        -- REVOKE before DROP keeps pg_default_acl tidy. DROP
        -- TABLE removes table-level grants implicitly but an
        -- environment that drops + re-runs the migration would
        -- otherwise accrue duplicate ACL rows under audit.
        REVOKE ALL ON intel_indicators FROM sn360_app;
        REVOKE ALL ON intel_feeds      FROM sn360_app;
    END IF;
END $$;

DROP TABLE IF EXISTS intel_indicators;
DROP TABLE IF EXISTS intel_feeds;

COMMIT;
