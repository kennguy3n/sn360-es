-- 0011_cascade_tenant_fks.up.sql
-- Adds ON DELETE CASCADE to tenant_id foreign keys in tables created
-- by migrations 0008-0010. Without CASCADE, tenant deletion (used
-- during cryptographic erasure) would fail with FK constraint
-- violations for any tenant that has sync checkpoints, behavioral
-- baselines, or org graph snapshots.

BEGIN;

-- sync_checkpoints (0008): composite PK, tenant_id is part of it
ALTER TABLE sync_checkpoints
    DROP CONSTRAINT sync_checkpoints_tenant_id_fkey,
    ADD CONSTRAINT sync_checkpoints_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- user_behavioral_baselines (0009)
ALTER TABLE user_behavioral_baselines
    DROP CONSTRAINT user_behavioral_baselines_tenant_id_fkey,
    ADD CONSTRAINT user_behavioral_baselines_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- org_graphs (0010)
ALTER TABLE org_graphs
    DROP CONSTRAINT org_graphs_tenant_id_fkey,
    ADD CONSTRAINT org_graphs_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

COMMIT;
