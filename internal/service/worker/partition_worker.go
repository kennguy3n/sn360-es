package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// PartitionManager is the small DB-side surface the
// PartitionMaintenanceJob needs. It is satisfied by the
// PostgresPartitionManager living in internal/repository/postgres.go;
// splitting it out lets tests inject an in-memory fake without
// pulling pgx into the worker package.
type PartitionManager interface {
	// ListPartitions returns every partition currently attached to
	// `parent`, in ascending order of upper bound. The returned
	// entries carry the partition table name and the inclusive
	// lower / exclusive upper bound as RFC3339 timestamps so
	// downstream comparisons are timezone-stable.
	ListPartitions(ctx context.Context, parent string) ([]Partition, error)
	// CreatePartition attaches a new partition to `parent`
	// covering [lower, upper). Implementations MUST be idempotent
	// (CREATE TABLE IF NOT EXISTS PARTITION OF …) so a re-run of
	// the cycle does not error on already-existing names.
	CreatePartition(ctx context.Context, parent, partition string, lower, upper time.Time) error
	// DropPartition detaches and drops `partition`. The job calls
	// this only for partitions whose upper bound is strictly
	// before the retention cutoff, so this should never affect a
	// partition with live rows.
	DropPartition(ctx context.Context, parent, partition string) error
}

// Partition describes one attached partition of a partitioned
// parent table.
type Partition struct {
	// Name is the partition's table name, e.g.
	// `evaluation_results_2026_06`.
	Name string
	// Lower is the inclusive lower bound of the partition range.
	Lower time.Time
	// Upper is the exclusive upper bound of the partition range.
	// For the historical `_legacy` partition this equals the
	// cutover timestamp; for monthly partitions it is the first of
	// the following month.
	Upper time.Time
	// Legacy is true if this is the historical (pre-cutover)
	// partition created by the 0017 migration. The maintenance
	// job intentionally never drops a legacy partition — operators
	// archive + drop it manually so an automated retention sweep
	// cannot silently destroy the entire pre-partitioning history.
	Legacy bool
}

// PartitionedTable describes one parent partitioned table the
// maintenance job manages.
type PartitionedTable struct {
	// Parent is the partitioned parent's table name.
	Parent string
	// NamePrefix is the literal prefix used for forward-month
	// partition names. The full name is built as
	// `<prefix>_<YYYY_MM>` to match the migration's naming
	// convention.
	NamePrefix string
	// PartitionKey is the column name used in the parent table's
	// PARTITION BY RANGE (...) declaration. The maintenance job
	// itself does not consume this — it routes retention via
	// DropPartition on the parsed bound — but downstream code that
	// builds a row-level retention fallback (the cleanup worker on
	// the `partitionRunner == nil` path) MUST issue DELETEs against
	// this same column so the two retention mechanisms apply
	// identical semantics. A row-level DELETE against any other
	// timestamp column (e.g. an audit `created_at` on a table
	// partitioned by `evaluated_at`) would diverge from the
	// partition-drop behaviour on rows where the two columns are
	// not equal (back-filled imports, retroactive evaluation, etc.)
	// and would lose partition-pruning at the query planner.
	PartitionKey string
	// RetentionMonths is the number of monthly partitions to keep.
	// Partitions whose upper bound is older than
	// `now - RetentionMonths` are eligible for drop. Must be > 0
	// or the table is treated as "keep forever" (the worker logs
	// and skips drops for that parent).
	RetentionMonths int
}

// PartitionMaintenanceConfig wires the maintenance worker.
type PartitionMaintenanceConfig struct {
	// Interval is how often the job runs. The cadence does not
	// need to be tight: missing a cycle only delays the creation
	// of the next forward partition by one tick. A daily run is
	// typical.
	Interval time.Duration
	// LookaheadMonths controls how far ahead the worker pre-
	// creates monthly partitions. The default (3) leaves
	// generous headroom even if the job misses several cycles.
	LookaheadMonths int
	// Tables is the set of parents to manage. The job is a no-op
	// when the slice is empty.
	Tables []PartitionedTable
	// Manager is the DB-side surface. Required.
	Manager PartitionManager
	// Logger receives structured cycle logs. Defaults to
	// slog.Default().
	Logger *slog.Logger
	// Clock is mainly for tests. Defaults to time.Now.UTC.
	Clock func() time.Time
}

// PartitionMaintenanceJob is a periodic worker that
//
//  1. pre-creates monthly partitions LookaheadMonths ahead of the
//     current time so no INSERT can fail because the target
//     partition does not exist; and
//  2. drops partitions whose upper bound is older than the parent's
//     RetentionMonths window, freeing storage in O(1) instead of
//     the row-by-row DELETE the legacy cleanup_worker did.
//
// The job is intentionally idempotent: CREATE uses IF NOT EXISTS;
// DROP is gated on a freshly-computed cutoff and partition-by-
// partition comparison so re-running a cycle is safe.
type PartitionMaintenanceJob struct {
	interval        time.Duration
	lookaheadMonths int
	tables          []PartitionedTable
	manager         PartitionManager
	logger          *slog.Logger
	clock           func() time.Time
}

// NewPartitionMaintenanceJob constructs the job and applies
// defaults.
func NewPartitionMaintenanceJob(cfg PartitionMaintenanceConfig) (*PartitionMaintenanceJob, error) {
	if cfg.Interval <= 0 {
		return nil, errors.New("worker: partition interval must be > 0")
	}
	if cfg.Manager == nil {
		return nil, errors.New("worker: partition manager is required")
	}
	if len(cfg.Tables) == 0 {
		return nil, errors.New("worker: partition tables is required (empty slice)")
	}
	for i, t := range cfg.Tables {
		if t.Parent == "" {
			return nil, fmt.Errorf("worker: tables[%d].Parent is empty", i)
		}
		if t.NamePrefix == "" {
			return nil, fmt.Errorf("worker: tables[%d].NamePrefix is empty", i)
		}
	}
	lookahead := cfg.LookaheadMonths
	if lookahead <= 0 {
		lookahead = 3
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &PartitionMaintenanceJob{
		interval:        cfg.Interval,
		lookaheadMonths: lookahead,
		tables:          cfg.Tables,
		manager:         cfg.Manager,
		logger:          logger,
		clock:           clock,
	}, nil
}

// Name implements Job.
func (j *PartitionMaintenanceJob) Name() string { return "partition_maintenance" }

// Interval implements Job.
func (j *PartitionMaintenanceJob) Interval() time.Duration { return j.interval }

// Run implements Job.
//
// One cycle visits every configured table, creates any missing
// forward-month partitions, then drops partitions older than the
// retention cutoff. Errors on one table do not stop processing of
// the next — the first error is returned so the runner can surface
// it via metrics, but subsequent tables still get a chance to
// reconcile their partition sets.
func (j *PartitionMaintenanceJob) Run(ctx context.Context) error {
	now := j.clock()
	var firstErr error
	for _, t := range j.tables {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := j.reconcile(ctx, now, t); err != nil {
			j.logger.Warn("worker.partition: reconcile failed",
				slog.String("parent", t.Parent),
				slog.Any("error", err))
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// reconcile is the per-table half of a cycle. It is exported for
// tests via the unexported method-on-a-public-receiver convention.
func (j *PartitionMaintenanceJob) reconcile(ctx context.Context, now time.Time, t PartitionedTable) error {
	existing, err := j.manager.ListPartitions(ctx, t.Parent)
	if err != nil {
		return fmt.Errorf("list partitions: %w", err)
	}
	// Index by name for fast existence checks during forward
	// creation.
	have := make(map[string]Partition, len(existing))
	for _, p := range existing {
		have[p.Name] = p
	}

	// Create LookaheadMonths months ahead of *current* month.
	curStart := monthStart(now)
	for offset := 0; offset <= j.lookaheadMonths; offset++ {
		lower := curStart.AddDate(0, offset, 0)
		upper := lower.AddDate(0, 1, 0)
		name := fmt.Sprintf("%s_%s", t.NamePrefix, lower.Format("2006_01"))
		if _, exists := have[name]; exists {
			continue
		}
		if err := j.manager.CreatePartition(ctx, t.Parent, name, lower, upper); err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		j.logger.Info("worker.partition: created",
			slog.String("parent", t.Parent),
			slog.String("partition", name),
			slog.Time("lower", lower),
			slog.Time("upper", upper))
	}

	// Drop partitions older than retention.
	if t.RetentionMonths <= 0 {
		j.logger.Debug("worker.partition: retention disabled; skipping drop sweep",
			slog.String("parent", t.Parent))
		return nil
	}
	cutoff := curStart.AddDate(0, -t.RetentionMonths, 0)
	// Iterate a stable order so logs are deterministic across
	// runs and so any first-error-out behaviour is reproducible.
	stable := make([]Partition, len(existing))
	copy(stable, existing)
	sort.Slice(stable, func(i, k int) bool { return stable[i].Upper.Before(stable[k].Upper) })
	for _, p := range stable {
		if p.Legacy {
			continue
		}
		// Drop when the partition's exclusive upper bound is at-or-
		// before the cutoff — i.e. every row in the partition is
		// strictly older than `now - RetentionMonths`. Using
		// `!Upper.After(cutoff)` (rather than `Before`) is the
		// correct boundary: a partition whose Upper equals cutoff
		// contains rows entirely in the OLD half of the boundary
		// and is droppable. The next-younger partition starts AT
		// cutoff and is preserved.
		if p.Upper.After(cutoff) {
			continue
		}
		if err := j.manager.DropPartition(ctx, t.Parent, p.Name); err != nil {
			return fmt.Errorf("drop %s: %w", p.Name, err)
		}
		j.logger.Info("worker.partition: dropped",
			slog.String("parent", t.Parent),
			slog.String("partition", p.Name),
			slog.Time("upper", p.Upper),
			slog.Time("cutoff", cutoff))
	}
	return nil
}

// monthStart returns the first instant of the UTC calendar month
// that contains t. Used to align partition bounds onto month
// boundaries so the worker's cadence never matters (running at
// 23:59 vs 00:01 the next day produces the same partition names).
func monthStart(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// SanitizePartitionName trims and validates a partition / table
// identifier for use in dynamically-built DDL. Postgres identifiers
// are at most 63 bytes and we restrict to [A-Za-z0-9_] so the
// composed name can never be exploited through user-controlled
// strings — even though the only producer today is the migration /
// worker itself.
func SanitizePartitionName(name string) (string, error) {
	if len(name) == 0 || len(name) > 63 {
		return "", fmt.Errorf("partition name %q has invalid length", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
			// ok
		default:
			return "", fmt.Errorf("partition name %q contains invalid character %q", name, r)
		}
	}
	if !startsWithLetterOrUnderscore(name) {
		return "", fmt.Errorf("partition name %q must start with a letter or underscore", name)
	}
	return strings.ToLower(name), nil
}

func startsWithLetterOrUnderscore(s string) bool {
	if s == "" {
		return false
	}
	r := s[0]
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
