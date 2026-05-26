-- 0015_expand_provider_check.down.sql
-- Revert tenants.provider and labels.provider to the original two-value
-- allowlist. The caller is responsible for migrating data away from
-- the new provider values; any row that still references zoho /
-- fastmail / workmail will cause the ADD CONSTRAINT to fail.
--
-- Uses the same dynamic constraint-name lookup as the up migration so
-- a renamed-constraint environment still rolls back cleanly.

BEGIN;

DO $$
DECLARE
    cn text;
BEGIN
    FOR cn IN
        SELECT con.conname
        FROM   pg_constraint con
        JOIN   pg_class      rel  ON rel.oid = con.conrelid
        JOIN   pg_namespace  nsp  ON nsp.oid = rel.relnamespace
        JOIN   pg_attribute  att  ON att.attrelid = con.conrelid
                                 AND att.attnum   = ANY (con.conkey)
        WHERE  con.contype  = 'c'
          AND  nsp.nspname  = current_schema()
          AND  rel.relname  = 'tenants'
          AND  att.attname  = 'provider'
          AND  cardinality(con.conkey) = 1
    LOOP
        EXECUTE format('ALTER TABLE tenants DROP CONSTRAINT %I', cn);
    END LOOP;

    FOR cn IN
        SELECT con.conname
        FROM   pg_constraint con
        JOIN   pg_class      rel  ON rel.oid = con.conrelid
        JOIN   pg_namespace  nsp  ON nsp.oid = rel.relnamespace
        JOIN   pg_attribute  att  ON att.attrelid = con.conrelid
                                 AND att.attnum   = ANY (con.conkey)
        WHERE  con.contype  = 'c'
          AND  nsp.nspname  = current_schema()
          AND  rel.relname  = 'labels'
          AND  att.attname  = 'provider'
          AND  cardinality(con.conkey) = 1
    LOOP
        EXECUTE format('ALTER TABLE labels DROP CONSTRAINT %I', cn);
    END LOOP;
END $$;

ALTER TABLE tenants ADD CONSTRAINT tenants_provider_check
    CHECK (provider IN ('gws', 'o365'));

ALTER TABLE labels ADD CONSTRAINT labels_provider_check
    CHECK (provider IN ('gws', 'o365'));

COMMIT;
