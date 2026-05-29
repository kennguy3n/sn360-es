-- 0016_comm_history_last_seen_index.down.sql
-- Reverse of 0016_comm_history_last_seen_index.up.sql. Dropping the
-- index is safe: the ListByTenant query still functions without it,
-- just with a less efficient plan (Seq Scan + in-memory Sort).

BEGIN;

DROP INDEX IF EXISTS idx_comm_hist_tenant_last_seen;

COMMIT;
