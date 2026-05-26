-- 0015_expand_provider_check.up.sql
-- Expand the tenants.provider and labels.provider CHECK constraints to
-- accept the three new provider integrations shipped alongside this
-- migration: Zoho Mail, Fastmail (JMAP), and Amazon WorkMail.
--
-- The original constraints were inline (anonymous) on the columns, so
-- PostgreSQL named them tenants_provider_check and labels_provider_check
-- by default. We drop the old constraints and re-add them with the
-- expanded provider allowlist.

BEGIN;

ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_provider_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_provider_check
    CHECK (provider IN ('gws', 'o365', 'zoho', 'fastmail', 'workmail'));

ALTER TABLE labels DROP CONSTRAINT IF EXISTS labels_provider_check;
ALTER TABLE labels ADD CONSTRAINT labels_provider_check
    CHECK (provider IN ('gws', 'o365', 'zoho', 'fastmail', 'workmail'));

COMMIT;
