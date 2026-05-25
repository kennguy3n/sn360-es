-- 0013_score_engine_tier1_thresholds.down.sql
-- Reverse of 0013_score_engine_tier1_thresholds.up.sql.

BEGIN;

ALTER TABLE score_engine
    DROP CONSTRAINT IF EXISTS chk_score_engine_tier1_pass_below_lt_flag_above;

ALTER TABLE score_engine
    DROP COLUMN IF EXISTS threshold_tier1_pass_below,
    DROP COLUMN IF EXISTS threshold_tier1_flag_above;

COMMIT;
