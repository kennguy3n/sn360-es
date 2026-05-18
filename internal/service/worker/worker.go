// Package worker hosts SN360-ES's periodic-job runtime: a small
// scheduler that drives Relationship aggregation, Vendor discovery
// and the data-retention Cleanup loop on a fixed cadence. Each
// worker acquires a distributed Redis lock before running so only
// one replica executes a cycle at a time.
//
// The package deliberately stays infrastructure-free — concrete
// workers depend on small interfaces declared here so tests can
// inject in-memory fakes without pulling Redis / Postgres in.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// DistributedLock is the subset of pkg/storage/redis.DistributedLock
// the workers require. Splitting the surface area out keeps the
// worker package decoupled from the concrete Redis implementation.
type DistributedLock interface {
	// Acquire tries to take the lock; (false, nil) means another
	// holder has it.
	Acquire(ctx context.Context) (bool, error)
	// Release best-effort releases the lock.
	Release(ctx context.Context) error
}

// LockFactory builds a lock with a stable name per worker. The
// returned lock should embed a TTL slightly longer than the
// expected cycle duration so a crashed worker's lock auto-expires.
type LockFactory func(name string) DistributedLock

// Job is one unit of recurring work. Run returns an error so the
// runner can surface failures via metrics + structured logging; the
// runner never propagates the error to the next cycle.
type Job interface {
	Name() string
	Interval() time.Duration
	Run(ctx context.Context) error
}

// MetricsRecorder is the slim metrics surface every worker emits to.
// The cmd/sn360-es package adapts pkg/telemetry to this interface so
// the worker package never imports telemetry directly.
type MetricsRecorder interface {
	ObserveCycle(name string, duration time.Duration, err error)
}

// Runner drives a Job on its declared interval. It is safe to start
// a single Runner per Job; multiple replicas can run concurrent
// Runners with the same lock name and only one will execute each
// cycle.
type Runner struct {
	job     Job
	logger  *slog.Logger
	locks   LockFactory
	metrics MetricsRecorder
	clock   func() time.Time
}

// RunnerConfig wires the Runner.
type RunnerConfig struct {
	Job     Job
	Logger  *slog.Logger
	Locks   LockFactory
	Metrics MetricsRecorder
	// Clock is mainly for tests. Defaults to time.Now.
	Clock func() time.Time
}

// NewRunner constructs a runner. Job is required; everything else
// has sensible defaults so callers can omit fields they don't need.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Job == nil {
		return nil, errors.New("worker: job is required")
	}
	if cfg.Job.Name() == "" {
		return nil, errors.New("worker: job name is required")
	}
	if cfg.Job.Interval() <= 0 {
		return nil, errors.New("worker: job interval must be > 0")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Runner{
		job:     cfg.Job,
		logger:  logger,
		locks:   cfg.Locks,
		metrics: cfg.Metrics,
		clock:   clock,
	}, nil
}

// Run blocks until ctx is cancelled, executing one cycle every
// job.Interval(). The first cycle fires immediately on start so
// freshly-deployed binaries do not have to wait `Interval` for the
// first run.
func (r *Runner) Run(ctx context.Context) error {
	r.runCycle(ctx)
	ticker := time.NewTicker(r.job.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.runCycle(ctx)
		}
	}
}

// runCycle executes a single cycle, handling lock acquisition,
// metrics emission and structured logging.
func (r *Runner) runCycle(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	name := r.job.Name()
	logger := r.logger.With(slog.String("worker", name))

	var lock DistributedLock
	if r.locks != nil {
		lock = r.locks(name)
	}
	if lock != nil {
		acquired, err := lock.Acquire(ctx)
		if err != nil {
			logger.Warn("worker: lock acquire failed; skipping cycle", slog.Any("error", err))
			return
		}
		if !acquired {
			logger.Debug("worker: skipping cycle, another replica holds the lock")
			return
		}
		defer func() {
			if rerr := lock.Release(ctx); rerr != nil {
				logger.Warn("worker: lock release failed", slog.Any("error", rerr))
			}
		}()
	}

	start := r.clock()
	err := r.job.Run(ctx)
	dur := r.clock().Sub(start)
	if r.metrics != nil {
		r.metrics.ObserveCycle(name, dur, err)
	}
	if err != nil {
		logger.Warn("worker: cycle failed",
			slog.Duration("duration", dur),
			slog.Any("error", err))
		return
	}
	logger.Info("worker: cycle completed", slog.Duration("duration", dur))
}
