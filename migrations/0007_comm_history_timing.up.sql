-- 0007_comm_history_timing.up.sql
-- Adds communication timing and volume baseline columns.

BEGIN;

ALTER TABLE communication_histories ADD COLUMN IF NOT EXISTS typical_hour INT DEFAULT -1;
ALTER TABLE communication_histories ADD COLUMN IF NOT EXISTS volume_baseline_daily REAL DEFAULT 0;

COMMIT;
