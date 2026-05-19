-- 0011_cascade_tenant_fks.down.sql
-- Reverts ON DELETE CASCADE back to the default (RESTRICT/NO ACTION).

BEGIN;

ALTER TABLE sync_checkpoints
    DROP CONSTRAINT sync_checkpoints_tenant_id_fkey,
    ADD CONSTRAINT sync_checkpoints_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE user_behavioral_baselines
    DROP CONSTRAINT user_behavioral_baselines_tenant_id_fkey,
    ADD CONSTRAINT user_behavioral_baselines_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE org_graphs
    DROP CONSTRAINT org_graphs_tenant_id_fkey,
    ADD CONSTRAINT org_graphs_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);

COMMIT;
