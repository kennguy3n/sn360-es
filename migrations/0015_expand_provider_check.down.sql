-- 0015_expand_provider_check.down.sql
-- Revert tenants.provider and labels.provider to the original two-value
-- allowlist (gws, o365). This down migration assumes no rows exist with
-- the new provider values; the caller is responsible for migrating data
-- out before rolling back.

BEGIN;

ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_provider_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_provider_check
    CHECK (provider IN ('gws', 'o365'));

ALTER TABLE labels DROP CONSTRAINT IF EXISTS labels_provider_check;
ALTER TABLE labels ADD CONSTRAINT labels_provider_check
    CHECK (provider IN ('gws', 'o365'));

COMMIT;
