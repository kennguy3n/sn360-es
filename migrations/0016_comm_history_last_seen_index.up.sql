-- 0016_comm_history_last_seen_index.up.sql
-- Add a composite index that supports the ListByTenant query shape:
--
--     SELECT ... FROM communication_histories
--     WHERE tenant_id = $1 AND last_seen_at >= $2
--     ORDER BY last_seen_at DESC LIMIT $3
--
-- The pg_comm_history.ListByTenant path now always passes a concrete
-- LIMIT (clampCommHistoryLimit caps at 10_000), so the planner can
-- terminate the scan early as long as it can walk last_seen_at in
-- descending order without a Sort step. The leading column
-- tenant_id makes the index usable as the bitmap-scan entry point,
-- and the DESC on last_seen_at means the planner returns rows
-- already in the requested order.
--
-- IF NOT EXISTS is intentional: an identical declaration also lives
-- in 0001_init.up.sql so a fresh deployment picks the index up at
-- init time without needing to apply this migration. This file is
-- what gets existing deployments — which already applied
-- 0001_init at an older revision that did NOT include this index —
-- onto the same schema via `migrate up`.

BEGIN;

CREATE INDEX IF NOT EXISTS idx_comm_hist_tenant_last_seen
    ON communication_histories (tenant_id, last_seen_at DESC);

COMMIT;
