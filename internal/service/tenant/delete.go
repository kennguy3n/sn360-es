// Package tenant hosts tenant-lifecycle services. Today it provides
// deletion (with cryptographic erasure); future work will add creation,
// update, and discovery wrappers.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// AuditWriter persists tenant audit-log entries (deletion, creation,
// configuration change, etc.). The interface is intentionally minimal
// so a Postgres, S3, or in-memory implementation can satisfy it.
type AuditWriter interface {
	Write(ctx context.Context, event AuditEvent) error
}

// AuditEvent is the canonical audit-log shape.
type AuditEvent struct {
	TenantID   string         `json:"tenant_id"`
	Action     string         `json:"action"`
	OccurredAt time.Time      `json:"occurred_at"`
	Actor      string         `json:"actor,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

// TenantWriter marks a tenant as deleted in the canonical metadata
// store. Concrete implementations live alongside the PostgreSQL
// repositories.
type TenantWriter interface {
	MarkDeleted(ctx context.Context, tenantID string, at time.Time) error
}

// DeleteServiceConfig holds the inputs to NewDeleteService.
type DeleteServiceConfig struct {
	Eraser  *privacy.Eraser
	Tenants TenantWriter
	Audit   AuditWriter
	Actor   string
	Logger  *slog.Logger
}

// DeleteService orchestrates cryptographic erasure plus metadata cleanup
// on tenant deletion. It is safe for concurrent use as long as the
// underlying components are.
type DeleteService struct {
	cfg DeleteServiceConfig
	log *slog.Logger
}

// NewDeleteService constructs the service. Eraser and Tenants are
// required.
func NewDeleteService(cfg DeleteServiceConfig) (*DeleteService, error) {
	if cfg.Eraser == nil {
		return nil, errors.New("tenant: Eraser is required")
	}
	if cfg.Tenants == nil {
		return nil, errors.New("tenant: TenantWriter is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &DeleteService{cfg: cfg, log: cfg.Logger}, nil
}

// Delete erases all encrypted data for tenantID, marks the tenant as
// deleted in the metadata store, and emits an audit-log entry. The
// operation is best-effort transactional: cleanup hooks run first, then
// the KMS forget happens last, so partial failures leave data
// recoverable.
func (s *DeleteService) Delete(ctx context.Context, tenantID, reason string) error {
	if tenantID == "" {
		return errors.New("tenant: tenant ID is required")
	}
	s.log.Info("tenant: delete starting",
		slog.String("tenant_id", tenantID),
		slog.String("reason", reason))
	now := time.Now().UTC()
	rec, err := s.cfg.Eraser.Erase(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("tenant: erase: %w", err)
	}
	if err := s.cfg.Tenants.MarkDeleted(ctx, tenantID, now); err != nil {
		return fmt.Errorf("tenant: mark deleted: %w", err)
	}
	if s.cfg.Audit != nil {
		_ = s.cfg.Audit.Write(ctx, AuditEvent{
			TenantID:   tenantID,
			Action:     "tenant.deleted",
			OccurredAt: now,
			Actor:      s.cfg.Actor,
			Details: map[string]any{
				"reason":       reason,
				"hooks_run":    rec.HooksRun,
				"started_at":   rec.StartedAt,
				"completed_at": rec.CompletedAt,
			},
		})
	}
	return nil
}
