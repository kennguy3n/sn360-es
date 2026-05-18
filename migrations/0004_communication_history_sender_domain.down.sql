-- 0004_communication_history_sender_domain.down.sql
-- Reverse of 0004_communication_history_sender_domain.up.sql.

BEGIN;

DROP INDEX IF EXISTS idx_comm_hist_tenant_sender_domain;

ALTER TABLE communication_histories
    DROP COLUMN IF EXISTS sender_domain;

COMMIT;
