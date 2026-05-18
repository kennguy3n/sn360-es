-- 0006_user_sensitivity_confidence.down.sql
BEGIN;
ALTER TABLE users DROP COLUMN IF EXISTS needs_review;
ALTER TABLE users DROP COLUMN IF EXISTS sensitivity_confidence;
COMMIT;
