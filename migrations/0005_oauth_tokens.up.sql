-- 0005_oauth_tokens.up.sql
-- Stores encrypted OAuth tokens for multi-tenant onboarding.

BEGIN;

CREATE TABLE IF NOT EXISTS oauth_tokens (
    tenant_id   TEXT NOT NULL,
    provider    TEXT NOT NULL,
    ciphertext  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider)
);

COMMIT;
