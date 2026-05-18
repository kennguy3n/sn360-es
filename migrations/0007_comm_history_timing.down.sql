-- 0007_comm_history_timing.down.sql
BEGIN;
ALTER TABLE communication_histories DROP COLUMN IF EXISTS volume_baseline_daily;
ALTER TABLE communication_histories DROP COLUMN IF EXISTS typical_hour;
COMMIT;
