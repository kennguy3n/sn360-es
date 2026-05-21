package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// AuditEntry represents one row in the audit_logs table.
type AuditEntry struct {
	ID            string
	TenantID      string
	Actor         string
	Action        string
	TargetType    string
	TargetHash    []byte
	CorrelationID string
	Metadata      map[string]any
	CreatedAt     time.Time
}

// AuditLogRepository persists audit log entries.
type AuditLogRepository interface {
	Record(ctx context.Context, entry AuditEntry) error
	ListByTenant(ctx context.Context, tenantID string, since time.Time, limit int) ([]AuditEntry, error)
}

// pgAuditLogs implements AuditLogRepository against Postgres.
type pgAuditLogs struct {
	db *postgres.DB
}

// NewPgAuditLogs constructs a Postgres-backed audit log repository.
func NewPgAuditLogs(db *postgres.DB) AuditLogRepository {
	return &pgAuditLogs{db: db}
}

// Record inserts an audit entry.
func (p *pgAuditLogs) Record(ctx context.Context, entry AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	meta, err := json.Marshal(entry.Metadata)
	if err != nil {
		meta = []byte("{}")
	}
	_, err = p.db.ExecContext(ctx, `
INSERT INTO audit_logs (id, tenant_id, actor, action, target_type, target_hash, correlation_id, metadata, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.ID, entry.TenantID, entry.Actor, entry.Action,
		entry.TargetType, entry.TargetHash, entry.CorrelationID,
		meta, entry.CreatedAt)
	if err != nil {
		return fmt.Errorf("audit_log: record: %w", err)
	}
	return nil
}

// ListByTenant returns audit entries for a tenant since the given time.
//
// LIMIT NULLIF($3, 0) treats limit=0 as "no limit" by collapsing the
// parameter to NULL (PostgreSQL accepts NULL as an unbounded LIMIT).
// Keeps the query fully parameterized so the planner can cache one
// prepared plan instead of one per distinct limit value.
func (p *pgAuditLogs) ListByTenant(ctx context.Context, tenantID string, since time.Time, limit int) ([]AuditEntry, error) {
	const query = `
SELECT id, tenant_id, actor, action, target_type, target_hash, correlation_id, metadata, created_at
FROM audit_logs
WHERE tenant_id=$1 AND created_at >= $2
ORDER BY created_at DESC
LIMIT NULLIF($3, 0)`
	rows, err := p.db.QueryContext(ctx, query, tenantID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("audit_log: list: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var meta []byte
		if err := rows.Scan(&e.ID, &e.TenantID, &e.Actor, &e.Action,
			&e.TargetType, &e.TargetHash, &e.CorrelationID, &meta, &e.CreatedAt); err != nil {
			return nil, err
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &e.Metadata)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// memoryAuditLogs implements AuditLogRepository in memory for tests.
type memoryAuditLogs struct {
	entries []AuditEntry
}

// NewMemoryAuditLogs constructs an in-memory audit log.
func NewMemoryAuditLogs() AuditLogRepository {
	return &memoryAuditLogs{}
}

func (m *memoryAuditLogs) Record(_ context.Context, entry AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	m.entries = append(m.entries, entry)
	return nil
}

func (m *memoryAuditLogs) ListByTenant(_ context.Context, tenantID string, since time.Time, limit int) ([]AuditEntry, error) {
	var out []AuditEntry
	for i := len(m.entries) - 1; i >= 0; i-- {
		e := m.entries[i]
		if e.TenantID != tenantID {
			continue
		}
		if !since.IsZero() && e.CreatedAt.Before(since) {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}
