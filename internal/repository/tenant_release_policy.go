package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// DefaultQuarantineSelfReleasePerHour is the per-recipient hourly cap
// applied when a tenant has no row in `tenant_release_policies` —
// 5 releases per recipient per hour. Matches the DEFAULT clause on
// the column in migration 0022. The constant exists in Go too so the
// memory repository and the handler share the same source of truth
// when a tenant hasn't customised the policy.
const DefaultQuarantineSelfReleasePerHour = 5

// TenantReleasePolicy carries the per-tenant knobs that govern the
// WS-3a quarantine self-service flow. Today this is just the
// per-recipient hourly cap; future knobs (per-tier eligibility,
// suspend self-service entirely, allow-list overrides) extend this
// struct without widening the `tenants` table.
type TenantReleasePolicy struct {
	TenantID                     string
	QuarantineSelfReleasePerHour int
	CreatedAt                    time.Time
	UpdatedAt                    time.Time
}

// TenantReleasePolicyRepository persists per-tenant self-service
// policy knobs.
//
// Get is the only documented hot-path entry point: the self-release
// handler calls it on every request to determine the recipient's
// hourly cap. The "no row" case is collapsed into the default
// policy (DefaultQuarantineSelfReleasePerHour, 5/hour) so a
// freshly-onboarded tenant gets the baseline experience without
// an explicit row write.
type TenantReleasePolicyRepository interface {
	// Get returns the policy for tenantID, or the default policy
	// when no row exists. ErrNotFound is NEVER returned for a
	// missing row — the contract is "always returns a policy".
	// Genuine DB errors (connection lost, planner failure) bubble
	// through.
	Get(ctx context.Context, tenantID string) (TenantReleasePolicy, error)
	// Upsert installs (or replaces) the policy row for a tenant.
	// Operator / onboarding flows call this; the self-release
	// handler does not.
	Upsert(ctx context.Context, policy TenantReleasePolicy) error
}

// pgTenantReleasePolicy implements TenantReleasePolicyRepository
// against Postgres.
type pgTenantReleasePolicy struct {
	db *postgres.DB
}

// NewPgTenantReleasePolicy constructs a Postgres-backed policy
// repository. RLS enforces tenant isolation at the row level so
// callers must have bound the connection via WithTenant before
// invoking Get/Upsert from production code.
func NewPgTenantReleasePolicy(db *postgres.DB) TenantReleasePolicyRepository {
	return &pgTenantReleasePolicy{db: db}
}

// Get looks up the policy. A missing row maps to the default policy
// (no error). Any other error is wrapped and returned.
func (p *pgTenantReleasePolicy) Get(ctx context.Context, tenantID string) (TenantReleasePolicy, error) {
	if tenantID == "" {
		return TenantReleasePolicy{}, fmt.Errorf("tenant_release_policy: tenant_id is required")
	}
	var pol TenantReleasePolicy
	err := p.db.QueryRowContext(ctx, `
SELECT tenant_id, quarantine_self_release_per_hour, created_at, updated_at
FROM tenant_release_policies
WHERE tenant_id = $1`, tenantID).Scan(
		&pol.TenantID,
		&pol.QuarantineSelfReleasePerHour,
		&pol.CreatedAt,
		&pol.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		// "No row" is the documented default. Return a
		// zero-row policy with the constant default cap so the
		// caller never has to special-case missing-row.
		return TenantReleasePolicy{
			TenantID:                     tenantID,
			QuarantineSelfReleasePerHour: DefaultQuarantineSelfReleasePerHour,
		}, nil
	}
	if err != nil {
		return TenantReleasePolicy{}, fmt.Errorf("tenant_release_policy: get: %w", err)
	}
	return pol, nil
}

// Upsert installs the row. updated_at is rewritten on every call so
// operator-facing tools can surface "last edited" without an
// explicit column write.
func (p *pgTenantReleasePolicy) Upsert(ctx context.Context, policy TenantReleasePolicy) error {
	if policy.TenantID == "" {
		return fmt.Errorf("tenant_release_policy: tenant_id is required")
	}
	if policy.QuarantineSelfReleasePerHour < 0 {
		return fmt.Errorf("tenant_release_policy: quarantine_self_release_per_hour must be >= 0")
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO tenant_release_policies (tenant_id, quarantine_self_release_per_hour)
VALUES ($1, $2)
ON CONFLICT (tenant_id) DO UPDATE
   SET quarantine_self_release_per_hour = EXCLUDED.quarantine_self_release_per_hour,
       updated_at = NOW()`,
		policy.TenantID, policy.QuarantineSelfReleasePerHour)
	if err != nil {
		return fmt.Errorf("tenant_release_policy: upsert: %w", err)
	}
	return nil
}

// memoryTenantReleasePolicy implements the repository in-memory for
// unit tests.
type memoryTenantReleasePolicy struct {
	mu sync.RWMutex
	m  map[string]TenantReleasePolicy
}

// NewMemoryTenantReleasePolicy constructs an in-memory policy
// repository for tests.
func NewMemoryTenantReleasePolicy() TenantReleasePolicyRepository {
	return &memoryTenantReleasePolicy{m: map[string]TenantReleasePolicy{}}
}

func (m *memoryTenantReleasePolicy) Get(_ context.Context, tenantID string) (TenantReleasePolicy, error) {
	if tenantID == "" {
		return TenantReleasePolicy{}, fmt.Errorf("tenant_release_policy: tenant_id is required")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	pol, ok := m.m[tenantID]
	if !ok {
		return TenantReleasePolicy{
			TenantID:                     tenantID,
			QuarantineSelfReleasePerHour: DefaultQuarantineSelfReleasePerHour,
		}, nil
	}
	return pol, nil
}

func (m *memoryTenantReleasePolicy) Upsert(_ context.Context, policy TenantReleasePolicy) error {
	if policy.TenantID == "" {
		return fmt.Errorf("tenant_release_policy: tenant_id is required")
	}
	if policy.QuarantineSelfReleasePerHour < 0 {
		return fmt.Errorf("tenant_release_policy: quarantine_self_release_per_hour must be >= 0")
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.m[policy.TenantID]
	if !ok {
		policy.CreatedAt = now
	} else {
		policy.CreatedAt = existing.CreatedAt
	}
	policy.UpdatedAt = now
	m.m[policy.TenantID] = policy
	return nil
}
