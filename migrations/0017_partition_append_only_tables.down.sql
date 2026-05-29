-- 0017_partition_append_only_tables.down.sql
--
-- Reverses the partitioning conversion in 0017. Strategy:
--   1. Detach every monthly partition (current + forward) from the
--      partitioned parent and drop them. New rows in those
--      partitions are sacrificed by the rollback — operators should
--      take a backup before running this.
--   2. Detach the legacy partition, leaving it standing as a plain
--      table with its original-but-still-renamed name.
--   3. Drop the now-empty partitioned parent.
--   4. Rename `<t>_legacy` back to `<t>` and re-create the original
--      PK / UNIQUE constraints + indexes so the schema matches the
--      0001 / 0002 baseline exactly.
--
-- The rollback is deliberately conservative: any rows that landed
-- in a forward-dated partition between the UP migration and the
-- DOWN migration are lost. We do NOT silently INSERT them into the
-- legacy table because the legacy table's CHECK constraint
-- (`evaluated_at < cutover`) would reject them, and lifting the
-- constraint mid-rollback would be a worse outcome (the legacy
-- table would no longer have a stable invariant for the next
-- partitioning attempt). Operators who need to preserve those rows
-- should COPY them out before running this migration.

BEGIN;

DO $rollback$
DECLARE
    rec     RECORD;
BEGIN

------------------------------------------------------------------
-- evaluation_results
------------------------------------------------------------------

-- Detach + drop every non-legacy partition.
FOR rec IN
    SELECT inhrelid::regclass AS part_name
    FROM pg_inherits
    WHERE inhparent = 'evaluation_results'::regclass
      AND inhrelid::regclass::text <> 'evaluation_results_legacy'
LOOP
    EXECUTE format('ALTER TABLE evaluation_results DETACH PARTITION %s', rec.part_name);
    EXECUTE format('DROP TABLE %s', rec.part_name);
END LOOP;

-- Detach the legacy partition. It still exists as a plain table.
ALTER TABLE evaluation_results DETACH PARTITION evaluation_results_legacy;

-- Drop the partitioned parent.
DROP TABLE evaluation_results;

-- Rename legacy back to the canonical name.
ALTER TABLE evaluation_results_legacy RENAME TO evaluation_results;
ALTER TABLE evaluation_results DROP CONSTRAINT IF EXISTS evaluation_results_legacy_range;
ALTER TABLE evaluation_results ADD PRIMARY KEY (id);
ALTER TABLE evaluation_results ADD CONSTRAINT evaluation_results_tenant_id_message_id_hash_key
    UNIQUE (tenant_id, message_id_hash);

------------------------------------------------------------------
-- audit_logs
------------------------------------------------------------------

FOR rec IN
    SELECT inhrelid::regclass AS part_name
    FROM pg_inherits
    WHERE inhparent = 'audit_logs'::regclass
      AND inhrelid::regclass::text <> 'audit_logs_legacy'
LOOP
    EXECUTE format('ALTER TABLE audit_logs DETACH PARTITION %s', rec.part_name);
    EXECUTE format('DROP TABLE %s', rec.part_name);
END LOOP;

ALTER TABLE audit_logs DETACH PARTITION audit_logs_legacy;
DROP TABLE audit_logs;
ALTER TABLE audit_logs_legacy RENAME TO audit_logs;
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_legacy_range;
ALTER TABLE audit_logs ADD PRIMARY KEY (id);

------------------------------------------------------------------
-- feedback_events
------------------------------------------------------------------

FOR rec IN
    SELECT inhrelid::regclass AS part_name
    FROM pg_inherits
    WHERE inhparent = 'feedback_events'::regclass
      AND inhrelid::regclass::text <> 'feedback_events_legacy'
LOOP
    EXECUTE format('ALTER TABLE feedback_events DETACH PARTITION %s', rec.part_name);
    EXECUTE format('DROP TABLE %s', rec.part_name);
END LOOP;

ALTER TABLE feedback_events DETACH PARTITION feedback_events_legacy;
DROP TABLE feedback_events;
ALTER TABLE feedback_events_legacy RENAME TO feedback_events;
ALTER TABLE feedback_events DROP CONSTRAINT IF EXISTS feedback_events_legacy_range;
ALTER TABLE feedback_events ADD PRIMARY KEY (id);

END $rollback$;

COMMIT;
