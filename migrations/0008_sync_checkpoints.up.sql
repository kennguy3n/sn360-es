CREATE TABLE sync_checkpoints (
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    provider    TEXT NOT NULL,
    delta_token TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider)
);
