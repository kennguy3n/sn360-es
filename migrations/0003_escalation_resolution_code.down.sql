-- 0003_escalation_resolution_code.down.sql
-- Reverse of 0003_escalation_resolution_code.up.sql.

BEGIN;

DROP INDEX IF EXISTS idx_escalation_tickets_resolution_code;

ALTER TABLE escalation_tickets
    DROP COLUMN IF EXISTS resolution_code;

COMMIT;
