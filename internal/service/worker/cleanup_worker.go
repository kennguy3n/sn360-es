package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Pruner is the small interface that backs the cleanup worker. The
// concrete pg-backed and Redis-backed pruners live next to this
// file; the worker only cares about the side-effect contract.
type Pruner interface {
	// Name identifies the pruner in logs and metrics. Should be a
	// short stable string (e.g. "evaluation_results").
	Name() string
	// Prune deletes rows older than `before` and returns the
	// number of rows affected.
	Prune(ctx context.Context, before time.Time) (int64, error)
}

// CleanupJobConfig wires the data-retention cleanup worker.
type CleanupJobConfig struct {
	Interval      time.Duration
	RetentionDays int
	Pruners       []Pruner
	Logger        *slog.Logger
	// Binder pins a Postgres conn to cross-tenant scope so the
	// retention DELETE statements below — which legitimately span
	// every tenant in a single statement — are not silently
	// zero-filtered by the RLS policy installed in
	// `migrations/0018_row_level_security.up.sql`. Nil is a valid
	// no-op for in-memory tests.
	Binder TenantBinder
}

// CleanupJob walks every configured Pruner once per cycle and
// deletes rows older than `now - RetentionDays * 24h`. The worker
// is intentionally additive — adding a new persistence table to the
// retention story only requires registering a new Pruner.
type CleanupJob struct {
	interval  time.Duration
	retention time.Duration
	pruners   []Pruner
	logger    *slog.Logger
	binder    TenantBinder
}

// NewCleanupJob constructs the job and applies defaults.
func NewCleanupJob(cfg CleanupJobConfig) (*CleanupJob, error) {
	if cfg.Interval <= 0 {
		return nil, errors.New("worker: cleanup interval must be > 0")
	}
	if len(cfg.Pruners) == 0 {
		return nil, errors.New("worker: cleanup requires at least one pruner")
	}
	retentionDays := cfg.RetentionDays
	if retentionDays <= 0 {
		retentionDays = 90
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &CleanupJob{
		interval:  cfg.Interval,
		retention: time.Duration(retentionDays) * 24 * time.Hour,
		pruners:   cfg.Pruners,
		logger:    logger,
		binder:    cfg.Binder,
	}, nil
}

// Name implements Job.
func (j *CleanupJob) Name() string { return "cleanup" }

// Interval implements Job.
func (j *CleanupJob) Interval() time.Duration { return j.interval }

// Run implements Job.
//
// The whole cycle runs inside a single cross-tenant scope. Each
// Pruner issues a `DELETE ... WHERE created_at < $1` that
// intentionally spans every tenant in one statement, so the RLS
// policy from `migrations/0018_row_level_security.up.sql` would
// see an unset `sn360.tenant_id` GUC and match zero rows. The
// cross-tenant scope is the explicit opt-out for that pattern;
// retention itself is a global operation, not a per-tenant one.
func (j *CleanupJob) Run(ctx context.Context) error {
	cutoff := time.Now().UTC().Add(-j.retention)
	var firstErr error

	// tenant-lint:cross-tenant — retention DELETE statements
	// intentionally cross tenants; per-row tenant_id is irrelevant
	// to the cutoff predicate.
	if j.binder != nil {
		boundCtx, release, berr := j.binder.WithCrossTenant(ctx)
		if berr != nil {
			return fmt.Errorf("worker.cleanup: cross-tenant scope: %w", berr)
		}
		defer func() { _ = release() }()
		ctx = boundCtx
	}

	for _, p := range j.pruners {
		if err := ctx.Err(); err != nil {
			return err
		}
		removed, err := p.Prune(ctx, cutoff)
		if err != nil {
			j.logger.Warn("worker.cleanup: prune failed",
				slog.String("pruner", p.Name()), slog.Any("error", err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		j.logger.Info("worker.cleanup: pruned",
			slog.String("pruner", p.Name()),
			slog.Int64("removed", removed))
	}
	return firstErr
}

// PrunerFunc adapts a plain function to the Pruner interface.
type PrunerFunc struct {
	name string
	fn   func(ctx context.Context, before time.Time) (int64, error)
}

// NewPruner builds a Pruner from a name + function. Useful for
// wiring in adapter functions that close over a database handle.
func NewPruner(name string, fn func(ctx context.Context, before time.Time) (int64, error)) Pruner {
	return &PrunerFunc{name: name, fn: fn}
}

// Name implements Pruner.
func (p *PrunerFunc) Name() string { return p.name }

// Prune implements Pruner.
func (p *PrunerFunc) Prune(ctx context.Context, before time.Time) (int64, error) {
	if p.fn == nil {
		return 0, nil
	}
	return p.fn(ctx, before)
}
