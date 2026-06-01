-- 0020_evaluation_results_sender_recipient_hash.down.sql
--
-- Reverses 0020 by dropping the WS-3b investigation-API indexes
-- and columns. Safe to run on a populated table — DROP INDEX is
-- a metadata change, and DROP COLUMN on a nullable column without
-- a DEFAULT is also a metadata change (no heap rewrite).
--
-- Dropping the index first is intentional: dropping the column
-- automatically invalidates any dependent index, but doing it
-- explicitly keeps the rollback log auditable.

DROP INDEX IF EXISTS idx_eval_results_tenant_sender_evaluated;

ALTER TABLE evaluation_results
    DROP COLUMN IF EXISTS recipient_hash,
    DROP COLUMN IF EXISTS sender_hash;
