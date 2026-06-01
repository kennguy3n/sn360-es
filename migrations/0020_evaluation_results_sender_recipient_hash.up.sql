-- 0020_evaluation_results_sender_recipient_hash.up.sql
--
-- WS-3b Investigation API support.
--
-- Adds two pseudonymised participant-identity columns to
-- `evaluation_results` so the investigation API can answer the
-- per-sender query
--
--    GET /v1/investigation/sender/{sender_hash}
--
-- without resorting to a non-indexed scan across the partitioned
-- table, and so the per-message query
--
--    GET /v1/investigation/message/{pseudo_id}
--
-- can join straight onto `communication_histories` for the
-- relationship snapshot without going back through the bridge to
-- re-derive the (sender, recipient) hashes.
--
-- Why nullable, not NOT NULL.
--   Legacy rows (everything written before this migration lands)
--   have no usable participant-identity information persisted —
--   the bridge only started carrying the hashes on the wire in
--   PR #61 (WS-4a, dto.EvaluateResult.{SenderHash,RecipientHash}).
--   Backfilling them post-hoc is not possible because the raw
--   addresses were never persisted (privacy invariant), so the
--   pseudonymiser has no input. The columns are therefore left
--   nullable so legacy rows remain readable; new rows written by
--   the WS-3b-aware code path always populate both columns. A
--   later migration may add NOT NULL once legacy rows have aged
--   out of the retention window.
--
-- Why BYTEA, not a fixed-width type.
--   The pseudonymiser produces a hex-encoded BLAKE2b-256 digest
--   (64 hex characters) and stores it as the byte slice of that
--   hex string, matching the shape of `communication_histories.sender_hash`
--   / `recipient_hash` in `0001_init.up.sql` (BYTEA). Using the same
--   shape on both sides means the equality predicate in the WS-3b
--   service layer
--
--       WHERE tenant_id = $1 AND sender_hash = $2
--
--   reuses the same SARGable hash comparison both backends already
--   exercise on `communication_histories` — no per-row decode and
--   no implicit cast at the planner.
--
-- Why a partial index.
--   The investigation API never queries by sender_hash IS NULL;
--   the only consumers are the WS-3b service-layer
--   `ListBySender(tenantID, senderHash, ...)` and any future
--   reverse-lookup. A WHERE-clause partial index keeps the legacy
--   rows out of the index entirely, shrinking the index size and
--   leaving the planner's existing tenant-only path
--   (`idx_eval_results_tenant_evaluated` from
--   `0017_partition_append_only_tables.up.sql`) authoritative for
--   the full-tenant scan.
--
-- Operational notes.
--   ADD COLUMN on a partitioned table cascades through every child
--   partition transparently; PG does not rewrite the heap when the
--   added column is nullable with no DEFAULT, so this is an
--   instantaneous metadata change. The CREATE INDEX runs against a
--   brand-new column with a partial-WHERE that matches zero rows,
--   so the index *build* itself is effectively instantaneous on
--   every partition.
--
--   The remaining production risk is *lock acquisition*: both DDL
--   operations need ACCESS EXCLUSIVE locks on the parent and every
--   partition, and on a busy table that lock can queue behind a
--   long-running transaction (and in turn block every later reader
--   queued behind it — the "lock queue jam"). PostgreSQL does not
--   support CREATE INDEX CONCURRENTLY directly on a partitioned
--   parent (only on partition leaves with a manual ATTACH dance),
--   so we cap the worst-case wait with lock_timeout + statement_timeout
--   instead of splitting this into a multi-step operator runbook.
--   If either bound trips, the migration aborts cleanly and ops
--   re-runs it from the next quieter deploy window with no half-applied
--   state (both ADD COLUMN and CREATE INDEX are idempotent via
--   IF NOT EXISTS).
--
--   Tuning rationale:
--     lock_timeout = 5s  — long enough to outwait normal OLTP
--       transactions (per the 1s p99 budget on evaluation writes),
--       short enough that a stuck statement aborts within one
--       deployment health-check interval.
--     statement_timeout = 60s — generous cap on the index build
--       itself; on an empty partial subset the build is sub-second,
--       but the bound protects against unexpected planner regressions.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

ALTER TABLE evaluation_results
    ADD COLUMN IF NOT EXISTS sender_hash    BYTEA,
    ADD COLUMN IF NOT EXISTS recipient_hash BYTEA;

CREATE INDEX IF NOT EXISTS idx_eval_results_tenant_sender_evaluated
    ON evaluation_results (tenant_id, sender_hash, evaluated_at DESC)
    WHERE sender_hash IS NOT NULL;
