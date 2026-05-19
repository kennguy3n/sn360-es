CREATE TABLE org_graphs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    built_at TIMESTAMPTZ NOT NULL,
    graph_json JSONB NOT NULL,
    high_risk_user_ids TEXT[] DEFAULT '{}',
    department_count INT DEFAULT 0,
    employee_count INT DEFAULT 0,
    group_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id)
);
