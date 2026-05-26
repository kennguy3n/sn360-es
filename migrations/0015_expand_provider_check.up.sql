-- 0015_expand_provider_check.up.sql
-- Expand the tenants.provider and labels.provider CHECK constraints to
-- accept the three new provider integrations shipped alongside this
-- migration: Zoho Mail, Fastmail (JMAP), and Amazon WorkMail.
--
-- The original constraints were declared inline on the column in
-- 0001_init.up.sql so PostgreSQL auto-named them
-- tenants_provider_check / labels_provider_check by default. To
-- stay safe even if an environment renamed them (manual DDL, an
-- intermediate migration, dump-and-restore round-trips), we look the
-- constraints up dynamically by their target column rather than by
-- the assumed name and drop whichever ones we find.

BEGIN;

DO $$
DECLARE
    cn text;
BEGIN
    -- Drop every CHECK constraint that gates the tenants.provider
    -- column, regardless of name. There is only ever supposed to be
    -- one but a loop is safer than assuming the cardinality.
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
    CHECK (provider IN ('gws', 'o365', 'zoho', 'fastmail', 'workmail'));

ALTER TABLE labels ADD CONSTRAINT labels_provider_check
    CHECK (provider IN ('gws', 'o365', 'zoho', 'fastmail', 'workmail'));

COMMIT;
