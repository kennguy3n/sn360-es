-- 0008_sync_checkpoints.up.sql
-- Stores delta/incremental sync tokens per (tenant, provider) so
-- directory sync can resume from where it left off instead of
-- re-enumerating the full user list on every cycle.

BEGIN;

CREATE TABLE sync_checkpoints (
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    provider    TEXT NOT NULL,
    delta_token TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider)
);

COMMIT;
