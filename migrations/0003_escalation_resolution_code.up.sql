-- 0003_escalation_resolution_code.up.sql
-- Adds a structured `resolution_code` column to `escalation_tickets`
-- so dashboard FP/FN aggregations no longer rely on ILIKE pattern
-- matching against the free-form `resolution` text column.
--
-- The accepted values mirror dto.EscalationOutcome:
--   - confirmed_phishing
--   - false_positive
--   - requires_hunting
--   - closed_no_action
--
-- Existing rows (if any) leave resolution_code NULL; the dashboard
-- counters treat NULL as "no structured outcome" and exclude them
-- from the FP/FN totals.

BEGIN;

ALTER TABLE escalation_tickets
    ADD COLUMN IF NOT EXISTS resolution_code TEXT
        CHECK (resolution_code IS NULL OR resolution_code IN (
            'confirmed_phishing',
            'false_positive',
            'requires_hunting',
            'closed_no_action'
        ));

CREATE INDEX IF NOT EXISTS idx_escalation_tickets_resolution_code
    ON escalation_tickets (tenant_id, resolution_code, resolved_at DESC)
    WHERE resolution_code IS NOT NULL;

COMMIT;
