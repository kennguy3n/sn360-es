-- 0004_communication_history_sender_domain.up.sql
-- Adds a plaintext `sender_domain` column to `communication_histories`
-- so vendor discovery and dashboard aggregations can match on the
-- actual domain string. The pre-existing `sender_domain_hash` column
-- stores a SHA-256 hash and is unsuitable for plaintext lookups —
-- earlier code that converted the raw hash bytes to a string with
-- `string(SenderDomainHash)` produced binary gibberish that broke
-- vendor matching.
--
-- The column is nullable to keep the migration online-safe; existing
-- rows leave it NULL and the worker treats NULL/empty values as
-- "domain unknown" and skips them when building observations.

BEGIN;

ALTER TABLE communication_histories
    ADD COLUMN IF NOT EXISTS sender_domain TEXT;

CREATE INDEX IF NOT EXISTS idx_comm_hist_tenant_sender_domain
    ON communication_histories (tenant_id, sender_domain)
    WHERE sender_domain IS NOT NULL;

COMMIT;
