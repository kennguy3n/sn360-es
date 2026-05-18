package worker

import (
	"context"
	"errors"
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
	}, nil
}

// Name implements Job.
func (j *CleanupJob) Name() string { return "cleanup" }

// Interval implements Job.
func (j *CleanupJob) Interval() time.Duration { return j.interval }

// Run implements Job.
func (j *CleanupJob) Run(ctx context.Context) error {
	cutoff := time.Now().UTC().Add(-j.retention)
	var firstErr error
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
