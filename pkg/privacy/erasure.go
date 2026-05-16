package privacy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Eraser performs cryptographic erasure on a tenant by forgetting the
// tenant's DEK (in the KMS) and evicting any cached plaintext copies in
// the Encryptor. After erasure every ciphertext blob produced for that
// tenant is permanently unreadable.
//
// The Eraser also fans out cleanup hooks for tenant-scoped non-encrypted
// state (Redis keys, vendor lists, etc.) so all references are removed
// in a single transaction-style call.
type Eraser struct {
	enc     Encryptor
	kms     ForgettableKMS
	hooks   []CleanupHook
	keyIDFn func(string) string
	log     *slog.Logger
}

// ForgettableKMS extends KMSClient with the ability to forget a key. The
// real AWS KMS adapter implements this by scheduling key deletion; the
// MockKMS implements it by dropping the in-memory key.
type ForgettableKMS interface {
	KMSClient
	ForgetKey(keyID string)
}

// CleanupHook removes additional tenant state during erasure. Hooks are
// invoked sequentially and any error stops the erasure (the KMS forget
// is performed last so failed cleanup leaves data still encrypted but
// recoverable).
type CleanupHook interface {
	Cleanup(ctx context.Context, tenantID string) error
}

// CleanupHookFunc is a function adapter for CleanupHook.
type CleanupHookFunc func(ctx context.Context, tenantID string) error

// Cleanup implements CleanupHook.
func (f CleanupHookFunc) Cleanup(ctx context.Context, tenantID string) error {
	return f(ctx, tenantID)
}

// EraserConfig configures a new Eraser.
type EraserConfig struct {
	Encryptor Encryptor
	KMS       ForgettableKMS
	KeyIDFor  func(tenantID string) string
	Hooks     []CleanupHook
	Logger    *slog.Logger
}

// NewEraser constructs an Eraser. Encryptor and KMS are required.
func NewEraser(cfg EraserConfig) (*Eraser, error) {
	if cfg.Encryptor == nil {
		return nil, errors.New("privacy: eraser requires an Encryptor")
	}
	if cfg.KMS == nil {
		return nil, errors.New("privacy: eraser requires a ForgettableKMS")
	}
	if cfg.KeyIDFor == nil {
		cfg.KeyIDFor = func(t string) string { return "sn360-tenant-" + t }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Eraser{
		enc:     cfg.Encryptor,
		kms:     cfg.KMS,
		hooks:   cfg.Hooks,
		keyIDFn: cfg.KeyIDFor,
		log:     cfg.Logger,
	}, nil
}

// ErasureRecord is a structured audit record describing a single erasure.
type ErasureRecord struct {
	TenantID    string    `json:"tenant_id"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	HooksRun    int       `json:"hooks_run"`
}

// Erase runs every CleanupHook in order, evicts the cached DEK from the
// encryptor, then forgets the KMS key. Returns an ErasureRecord suitable
// for the audit log on success.
func (e *Eraser) Erase(ctx context.Context, tenantID string) (ErasureRecord, error) {
	rec := ErasureRecord{TenantID: tenantID, StartedAt: time.Now().UTC()}
	if tenantID == "" {
		return rec, errors.New("privacy: tenant ID is required")
	}
	e.log.Info("privacy: erasure starting", slog.String("tenant_id", tenantID))

	for i, h := range e.hooks {
		if err := h.Cleanup(ctx, tenantID); err != nil {
			return rec, fmt.Errorf("privacy: cleanup hook %d for tenant %q: %w", i, tenantID, err)
		}
		rec.HooksRun++
	}
	e.enc.Forget(tenantID)
	e.kms.ForgetKey(e.keyIDFn(tenantID))
	rec.CompletedAt = time.Now().UTC()
	e.log.Info("privacy: erasure complete",
		slog.String("tenant_id", tenantID),
		slog.Int("hooks_run", rec.HooksRun),
		slog.Duration("elapsed", rec.CompletedAt.Sub(rec.StartedAt)))
	return rec, nil
}
