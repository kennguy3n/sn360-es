-- 0023_score_engine_tier2_provider.down.sql

BEGIN;

ALTER TABLE score_engine
    DROP COLUMN IF EXISTS tier2_provider;

COMMIT;
