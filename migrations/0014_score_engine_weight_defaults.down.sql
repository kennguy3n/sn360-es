-- 0014_score_engine_weight_defaults.down.sql
-- Restore the 0001_init.up.sql defaults (80/20/0/0 with
-- subject_tag_prefix='SN360'). Note: this only changes the column
-- DEFAULTs; existing rows already populated by the onboarding agent
-- keep their seeded values.

BEGIN;

ALTER TABLE score_engine
    ALTER COLUMN weight_ai SET DEFAULT 80,
    ALTER COLUMN weight_rspamd SET DEFAULT 20,
    ALTER COLUMN weight_attachments SET DEFAULT 0,
    ALTER COLUMN weight_links SET DEFAULT 0,
    ALTER COLUMN subject_tag_prefix SET DEFAULT 'SN360';

COMMIT;
