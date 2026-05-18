package privacy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// RotationConfig wires the key rotation worker.
type RotationConfig struct {
	KMS           KMSClient
	Encryptor     Encryptor
	AuditLog      RotationAuditLog
	Logger        *slog.Logger
	Clock         func() time.Time
	// Interval between rotation cycles. Defaults to 90 days.
	Interval      time.Duration
	// KeyIDFor returns the KMS key alias for a tenant. Defaults to
	// "sn360-tenant-<tenantID>".
	KeyIDFor      func(tenantID string) string
}

// RotationAuditLog records key rotation events for compliance.
type RotationAuditLog interface {
	LogRotation(ctx context.Context, event RotationEvent) error
}

// RotationEvent is the audit record for a key rotation.
type RotationEvent struct {
	TenantID    string    `json:"tenant_id"`
	KeyID       string    `json:"key_id"`
	RotatedAt   time.Time `json:"rotated_at"`
	Status      string    `json:"status"` // "success" or "failed"
	Error       string    `json:"error,omitempty"`
}

// RotationResult summarises a rotation run.
type RotationResult struct {
	TenantsProcessed int
	Succeeded        int
	Failed           int
	Duration         time.Duration
}

// KeyRotator is the periodic worker that rotates per-tenant DEKs.
// It generates a new data key via KMS, re-encrypts active data with
// the new key, and logs the rotation event to the audit trail.
type KeyRotator struct {
	kms      KMSClient
	enc      Encryptor
	audit    RotationAuditLog
	log      *slog.Logger
	now      func() time.Time
	interval time.Duration
	keyIDFor func(string) string
	mu       sync.Mutex
}

// NewKeyRotator constructs the rotator.
func NewKeyRotator(cfg RotationConfig) (*KeyRotator, error) {
	if cfg.KMS == nil {
		return nil, fmt.Errorf("key_rotation: KMS client is required")
	}
	if cfg.Encryptor == nil {
		return nil, fmt.Errorf("key_rotation: Encryptor is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 90 * 24 * time.Hour
	}
	if cfg.KeyIDFor == nil {
		cfg.KeyIDFor = func(tenantID string) string {
			return "sn360-tenant-" + tenantID
		}
	}
	return &KeyRotator{
		kms:      cfg.KMS,
		enc:      cfg.Encryptor,
		audit:    cfg.AuditLog,
		log:      cfg.Logger,
		now:      cfg.Clock,
		interval: cfg.Interval,
		keyIDFor: cfg.KeyIDFor,
	}, nil
}

// RotateTenant generates a new DEK for the given tenant, flushes the
// old cached key, and logs the rotation event.
func (r *KeyRotator) RotateTenant(ctx context.Context, tenantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	keyID := r.keyIDFor(tenantID)

	// Generate a new data key via KMS.
	_, _, err := r.kms.GenerateDataKey(ctx, keyID)
	if err != nil {
		r.logRotation(ctx, tenantID, keyID, "failed", err)
		return fmt.Errorf("key_rotation: generate data key: %w", err)
	}

	// Flush the cached plaintext DEK so the next encrypt/decrypt
	// operation fetches the new key from KMS.
	r.enc.Forget(tenantID)

	r.logRotation(ctx, tenantID, keyID, "success", nil)

	r.log.InfoContext(ctx, "key_rotation: rotated",
		slog.String("tenant", tenantID),
		slog.String("key_id", keyID))

	return nil
}

// RotateAll rotates keys for all provided tenants.
func (r *KeyRotator) RotateAll(ctx context.Context, tenantIDs []string) RotationResult {
	start := r.now()
	result := RotationResult{TenantsProcessed: len(tenantIDs)}

	for _, tid := range tenantIDs {
		if err := r.RotateTenant(ctx, tid); err != nil {
			result.Failed++
			r.log.WarnContext(ctx, "key_rotation: tenant rotation failed",
				slog.String("tenant", tid),
				slog.Any("error", err))
		} else {
			result.Succeeded++
		}
	}
	result.Duration = r.now().Sub(start)
	return result
}

// Run starts the periodic rotation loop. It blocks until ctx is cancelled.
func (r *KeyRotator) Run(ctx context.Context, tenantIDs func() []string) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			ids := tenantIDs()
			result := r.RotateAll(ctx, ids)
			r.log.InfoContext(ctx, "key_rotation: cycle complete",
				slog.Int("processed", result.TenantsProcessed),
				slog.Int("succeeded", result.Succeeded),
				slog.Int("failed", result.Failed),
				slog.Duration("duration", result.Duration))
		}
	}
}

func (r *KeyRotator) logRotation(ctx context.Context, tenantID, keyID, status string, err error) {
	if r.audit == nil {
		return
	}
	evt := RotationEvent{
		TenantID:  tenantID,
		KeyID:     keyID,
		RotatedAt: r.now(),
		Status:    status,
	}
	if err != nil {
		evt.Error = err.Error()
	}
	if aerr := r.audit.LogRotation(ctx, evt); aerr != nil {
		r.log.WarnContext(ctx, "key_rotation: audit log failed",
			slog.Any("error", aerr))
	}
}

// MemoryRotationAuditLog is an in-memory audit log for dev/test.
type MemoryRotationAuditLog struct {
	mu     sync.Mutex
	events []RotationEvent
}

// NewMemoryRotationAuditLog creates a new in-memory audit log.
func NewMemoryRotationAuditLog() *MemoryRotationAuditLog {
	return &MemoryRotationAuditLog{}
}

func (l *MemoryRotationAuditLog) LogRotation(_ context.Context, event RotationEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	return nil
}

// Events returns all logged rotation events. For testing.
func (l *MemoryRotationAuditLog) Events() []RotationEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]RotationEvent, len(l.events))
	copy(out, l.events)
	return out
}


