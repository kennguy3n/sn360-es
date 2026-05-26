-- 0014_score_engine_weight_defaults.up.sql
-- Align the score_engine column defaults with the values the
-- onboarding agent seeds (internal/service/agent/onboarding.go:
-- DefaultWeights = {AI: 0.60, Rspamd: 0.10, Attachments: 0.15,
-- Links: 0.15}). The original 0001_init.up.sql defaults (80/20/0/0
-- with subject_tag_prefix='SN360') predated the
-- attachments+links scoring categories and the empty default prefix;
-- new tenants whose row gets created without the onboarding agent
-- (e.g. manual SQL insert, test fixtures) were silently inheriting
-- the legacy weights and a stale prefix, drifting from production.

BEGIN;

ALTER TABLE score_engine
    ALTER COLUMN weight_ai SET DEFAULT 60,
    ALTER COLUMN weight_rspamd SET DEFAULT 10,
    ALTER COLUMN weight_attachments SET DEFAULT 15,
    ALTER COLUMN weight_links SET DEFAULT 15,
    ALTER COLUMN subject_tag_prefix SET DEFAULT '';

COMMIT;
