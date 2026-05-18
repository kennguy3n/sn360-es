-- 0006_user_sensitivity_confidence.up.sql
-- Adds sensitivity confidence scoring and admin review flag to users.

BEGIN;

ALTER TABLE users ADD COLUMN IF NOT EXISTS sensitivity_confidence REAL DEFAULT 1.0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS needs_review BOOLEAN DEFAULT FALSE;

COMMIT;
