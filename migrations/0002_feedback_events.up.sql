-- 0002_feedback_events.up.sql
-- Adds the `feedback_events` table, which records every verified
-- one-click banner action (report_phishing / mark_safe / trust_sender)
-- that the FeedbackService publishes onto `es.action.feedback.*`.
--
-- The dashboard PostgresSource reads aggregates from this table to
-- populate dto.FeedbackStats; the v1 schema (0001) had no dedicated
-- table for this, so the Feedback() method returned zeros. This
-- migration closes that gap.
--
-- Privacy: only the pseudonymised message id is stored (no message
-- content, sender, recipient, or URLs). The pseudonym is a Blake2-
-- derived identifier shared with evaluation_results, so a tenant
-- admin can join feedback to verdicts without recovering any PII.

BEGIN;

CREATE TABLE IF NOT EXISTS feedback_events (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pseudo_message_id        TEXT        NOT NULL,
    action                   TEXT        NOT NULL
                             CHECK (action IN ('report_phishing', 'mark_safe', 'trust_sender')),
    tier                     TEXT        NOT NULL DEFAULT '',
    correlation_id           TEXT,
    occurred_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feedback_events_tenant_occurred
    ON feedback_events (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_events_tenant_action_occurred
    ON feedback_events (tenant_id, action, occurred_at DESC);

COMMIT;
