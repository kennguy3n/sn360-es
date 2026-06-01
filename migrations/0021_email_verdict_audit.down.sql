-- 0021_email_verdict_audit.down.sql
--
-- Reverses 0021 by dropping the WS-5A.6 cross-repo escalation
-- sync tables, the evaluation_results.final_verdict column, and
-- the supporting RLS policies. Safe to run on a populated
-- schema — DROP TABLE / DROP COLUMN against nullable columns
-- without DEFAULT and DROP POLICY are all metadata-only
-- operations (no heap rewrite).
--
-- Order matters: drop the RLS policies first, then the audit
-- table and banner_state table, then the final_verdict
-- constraint and column. Dropping the table implicitly drops
-- the policies, but doing them explicitly keeps the rollback
-- log auditable.

DROP POLICY IF EXISTS tenant_isolation ON email_verdict_audit;
DROP POLICY IF EXISTS tenant_isolation ON banner_state;

DROP INDEX IF EXISTS idx_email_verdict_audit_pseudo;
DROP INDEX IF EXISTS idx_email_verdict_audit_tenant_created;
DROP INDEX IF EXISTS idx_banner_state_tenant_updated;

DROP TABLE IF EXISTS email_verdict_audit;
DROP TABLE IF EXISTS banner_state;

ALTER TABLE evaluation_results
    DROP CONSTRAINT IF EXISTS evaluation_results_final_verdict_check;
ALTER TABLE evaluation_results
    DROP COLUMN IF EXISTS final_verdict;
