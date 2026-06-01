-- 0025_tenant_webhook_sinks.down.sql
--
-- Reverses 0025 by dropping the WS-5B.2 per-tenant webhook sink
-- configuration and audit tables. Order: RLS policies, then indices,
-- then tables (dropping the table implicitly drops policies, but
-- explicit drops keep the rollback log auditable).

DROP POLICY IF EXISTS tenant_isolation ON tenant_webhook_sink_audit;
DROP POLICY IF EXISTS tenant_isolation ON tenant_webhook_sinks;

DROP INDEX IF EXISTS idx_tenant_webhook_sink_audit_sink;
DROP INDEX IF EXISTS idx_tenant_webhook_sink_audit_tenant_created;
DROP INDEX IF EXISTS idx_tenant_webhook_sinks_tenant_enabled;

DROP TABLE IF EXISTS tenant_webhook_sink_audit;
DROP TABLE IF EXISTS tenant_webhook_sinks;
