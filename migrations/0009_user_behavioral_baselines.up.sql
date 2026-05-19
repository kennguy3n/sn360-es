CREATE TABLE user_behavioral_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_email_hash BYTEA NOT NULL,
    sender_domain_hash BYTEA NOT NULL,
    typical_send_hours INT[] DEFAULT '{}',
    typical_device_types TEXT[] DEFAULT '{}',
    avg_messages_per_week FLOAT DEFAULT 0,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, user_email_hash, sender_domain_hash)
);
