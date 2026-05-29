package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/service/worker"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// partitionedAppendOnlyTables is the authoritative list of parent
// partitioned tables the maintenance worker manages. The slice
// MUST mirror the parents declared in
// migrations/0017_partition_append_only_tables.up.sql; adding a
// table to one and not the other is a footgun, so both sides
// reference each other by comment.
//
// Each entry binds:
//   - Parent: the partitioned parent table name.
//   - NamePrefix: the literal prefix every monthly partition name
//     uses ("<prefix>_<YYYY_MM>"). Matches the migration's
//     `to_char(part_start, 'YYYY_MM')` naming exactly.
func partitionedAppendOnlyTables() []worker.PartitionedTable {
	return []worker.PartitionedTable{
		{Parent: "evaluation_results", NamePrefix: "evaluation_results"},
		{Parent: "audit_logs", NamePrefix: "audit_logs"},
		{Parent: "feedback_events", NamePrefix: "feedback_events"},
	}
}

// pgPartitionManager is the Postgres-backed implementation of
// worker.PartitionManager. It reads partition state from the
// catalog (pg_inherits + pg_class) and issues
// CREATE/DROP PARTITION DDL through the same *postgres.DB handle
// the application uses for everything else.
//
// Every DDL command is built via format() with %I quoting and
// constant-string templates — no user-controlled identifier is ever
// concatenated into the SQL. SanitizePartitionName runs as a belt-
// and-braces check on every name passed in, so even a future code
// path that forwarded an attacker-controlled string would be
// rejected at the worker layer before reaching the catalog.
type pgPartitionManager struct {
	db     *postgres.DB
	logger *slog.Logger
}

// NewPgPartitionManager builds a worker.PartitionManager bound to
// the given *postgres.DB. The returned value is safe for concurrent
// use; the underlying *sql.DB pool handles serialisation.
func NewPgPartitionManager(db *postgres.DB, logger *slog.Logger) worker.PartitionManager {
	return &pgPartitionManager{db: db, logger: logger}
}

// ListPartitions queries the catalog for every partition currently
// attached to `parent`. Each row also yields the partition's
// inclusive lower / exclusive upper bound parsed out of the partition
// expression so the worker can run retention math against
// timezone-stable timestamptz values.
//
// `pg_get_expr(c.relpartbound, c.oid)` returns the canonical
// `FOR VALUES FROM ('lo') TO ('hi')` form for a RANGE partition.
// We parse that with a small pure-Go helper rather than trusting a
// regex because the bound timestamps are timezone-formatted by
// Postgres and the helper produces a clear error on shapes the
// migration would never emit.
func (m *pgPartitionManager) ListPartitions(ctx context.Context, parent string) ([]worker.Partition, error) {
	if _, err := worker.SanitizePartitionName(parent); err != nil {
		return nil, fmt.Errorf("ListPartitions: invalid parent %q: %w", parent, err)
	}
	const q = `
		SELECT
		    c.relname,
		    pg_get_expr(c.relpartbound, c.oid)
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = $1::regclass
	`
	rows, err := m.db.QueryContext(ctx, q, parent)
	if err != nil {
		return nil, fmt.Errorf("list partitions for %s: %w", parent, err)
	}
	defer rows.Close()
	out := make([]worker.Partition, 0, 8)
	for rows.Next() {
		var name, expr string
		if err := rows.Scan(&name, &expr); err != nil {
			return nil, fmt.Errorf("scan partition row: %w", err)
		}
		lower, upper, perr := parsePartitionBound(expr)
		if perr != nil {
			m.logger.Warn("worker.partition: cannot parse bound; skipping partition in retention sweep",
				slog.String("parent", parent),
				slog.String("partition", name),
				slog.String("expr", expr),
				slog.Any("error", perr))
			// Surface the partition with zero bounds + Legacy
			// set so the worker treats it as untouchable. The
			// 0001-01-01 zero value will compare strictly after
			// any plausible cutoff (Time.Zero predates 1970 but
			// `Time.After(zero)` is true for any later time), so
			// the drop path's `Upper.After(cutoff)` will see
			// zero-value Upper as `false`. Forcing Legacy=true
			// belts that with an explicit skip.
			out = append(out, worker.Partition{Name: name, Legacy: true})
			continue
		}
		// Detect the historical "_legacy" partition (created by
		// the 0017 migration) by name suffix. We never auto-drop
		// the legacy partition no matter how old it is — operator
		// archives + drops it manually.
		legacy := hasSuffix(name, "_legacy")
		out = append(out, worker.Partition{
			Name:   name,
			Lower:  lower,
			Upper:  upper,
			Legacy: legacy,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate partition rows: %w", err)
	}
	return out, nil
}

// CreatePartition attaches a new partition covering [lower, upper)
// to `parent`. Idempotent: a duplicate name is silently accepted
// via `CREATE TABLE IF NOT EXISTS`.
func (m *pgPartitionManager) CreatePartition(ctx context.Context, parent, partition string, lower, upper time.Time) error {
	sanitisedParent, err := worker.SanitizePartitionName(parent)
	if err != nil {
		return fmt.Errorf("CreatePartition: invalid parent %q: %w", parent, err)
	}
	sanitisedPart, err := worker.SanitizePartitionName(partition)
	if err != nil {
		return fmt.Errorf("CreatePartition: invalid partition %q: %w", partition, err)
	}
	// format() with %I quotes identifiers; the timestamps are
	// passed as text literals which Postgres interprets in the
	// server's timezone — we use UTC RFC3339 so the timezone never
	// matters.
	const tmpl = `
		SELECT format(
		    'CREATE TABLE IF NOT EXISTS %%I PARTITION OF %%I FOR VALUES FROM (%%L) TO (%%L)',
		    $1::text, $2::text, $3::text, $4::text
		)
	`
	var ddl string
	if err := m.db.QueryRowContext(ctx, tmpl,
		sanitisedPart,
		sanitisedParent,
		lower.UTC().Format(time.RFC3339),
		upper.UTC().Format(time.RFC3339),
	).Scan(&ddl); err != nil {
		return fmt.Errorf("compose partition DDL: %w", err)
	}
	if _, err := m.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("execute CREATE PARTITION: %w", err)
	}
	return nil
}

// DropPartition detaches and drops `partition` from `parent`. The
// worker guards against dropping a legacy partition by checking
// Partition.Legacy upstream; the manager-side check sanitises the
// identifier so a misconfigured caller can't reach attacker-
// controlled DDL.
func (m *pgPartitionManager) DropPartition(ctx context.Context, parent, partition string) error {
	sanitisedParent, err := worker.SanitizePartitionName(parent)
	if err != nil {
		return fmt.Errorf("DropPartition: invalid parent %q: %w", parent, err)
	}
	sanitisedPart, err := worker.SanitizePartitionName(partition)
	if err != nil {
		return fmt.Errorf("DropPartition: invalid partition %q: %w", partition, err)
	}
	const tmpl = `SELECT format('ALTER TABLE %%I DETACH PARTITION %%I', $1::text, $2::text)`
	var detach string
	if err := m.db.QueryRowContext(ctx, tmpl, sanitisedParent, sanitisedPart).Scan(&detach); err != nil {
		return fmt.Errorf("compose DETACH DDL: %w", err)
	}
	if _, err := m.db.ExecContext(ctx, detach); err != nil {
		return fmt.Errorf("execute DETACH PARTITION: %w", err)
	}
	const tmplDrop = `SELECT format('DROP TABLE %%I', $1::text)`
	var drop string
	if err := m.db.QueryRowContext(ctx, tmplDrop, sanitisedPart).Scan(&drop); err != nil {
		return fmt.Errorf("compose DROP DDL: %w", err)
	}
	if _, err := m.db.ExecContext(ctx, drop); err != nil {
		return fmt.Errorf("execute DROP TABLE: %w", err)
	}
	return nil
}

// parsePartitionBound parses Postgres' canonical
// `FOR VALUES FROM ('lo') TO ('hi')` partition-bound expression.
// Returns lower, upper as time.Time in UTC. Bounds emitted by the
// 0017 migration always carry an explicit timezone, so RFC3339
// parsing succeeds. The MINVALUE shape produced by the legacy
// partition's ATTACH is normalised to `time.Time{}` (zero value);
// callers that consume Legacy partitions must treat this as a
// sentinel.
func parsePartitionBound(expr string) (lower, upper time.Time, err error) {
	// Strip the canonical wrapping. Anything else is a shape we
	// don't recognise (LIST / HASH / DEFAULT) — surface an error
	// rather than silently misinterpreting.
	const prefix = "FOR VALUES FROM ("
	const sep = ") TO ("
	const suffix = ")"
	if !hasPrefix(expr, prefix) || !hasSuffix(expr, suffix) {
		return time.Time{}, time.Time{}, fmt.Errorf("unrecognised partition bound shape: %q", expr)
	}
	inner := expr[len(prefix) : len(expr)-len(suffix)]
	idx := indexOf(inner, sep)
	if idx < 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("missing FROM/TO separator: %q", expr)
	}
	loRaw := unquoteSQLLiteral(inner[:idx])
	hiRaw := unquoteSQLLiteral(inner[idx+len(sep):])

	if loRaw == "MINVALUE" {
		lower = time.Time{}
	} else {
		lower, err = parsePartitionTimestamp(loRaw)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parse lower bound %q: %w", loRaw, err)
		}
	}
	if hiRaw == "MAXVALUE" {
		upper = time.Time{}
	} else {
		upper, err = parsePartitionTimestamp(hiRaw)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parse upper bound %q: %w", hiRaw, err)
		}
	}
	return lower, upper, nil
}

// parsePartitionTimestamp accepts the formats Postgres uses for
// timestamptz in `pg_get_expr` output. The 0017 migration emits
// RFC3339 with an explicit "+00" or "+0000" offset; we also accept
// the bare "YYYY-MM-DD HH:MM:SS" form a future change might
// introduce.
func parsePartitionTimestamp(s string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05-07",
		"2006-01-02 15:04:05.999999-07",
		"2006-01-02 15:04:05.999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("no matching timestamp layout for %q", s)
}

// unquoteSQLLiteral strips a surrounding pair of single quotes and
// unescapes any doubled-single-quote pairs. Postgres' `pg_get_expr`
// quotes literal values this way; everything inside the quotes is
// a verbatim timestamp string in our case.
func unquoteSQLLiteral(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		s = s[1 : len(s)-1]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' && i+1 < len(s) && s[i+1] == '\'' {
			out = append(out, '\'')
			i++
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// Small substring helpers — using stdlib `strings` would force
// another import line through this file; keep it self-contained.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// buildPartitionRunner wires the PartitionMaintenanceJob into the
// worker.Runner the application's spawn loop drives. Returns nil
// when the application has no Postgres handle (the partitioned
// tables only exist in PG-backed deployments) or when the operator
// has zeroed out cfg.Worker.PartitionInterval.
func buildPartitionRunner(cfg *config.Config, logger *slog.Logger, app *application, locks worker.LockFactory, metrics worker.MetricsRecorder) *worker.Runner {
	if app.pgDB == nil {
		logger.Info("sn360-es: partition worker skipped; no postgres handle")
		return nil
	}
	if cfg.Worker.PartitionInterval <= 0 {
		logger.Info("sn360-es: partition worker skipped; WORKER_PARTITION_INTERVAL is 0")
		return nil
	}
	parents := partitionedAppendOnlyTables()
	for i := range parents {
		parents[i].RetentionMonths = cfg.Worker.PartitionRetentionMonths
	}
	mgr := NewPgPartitionManager(app.pgDB, logger)
	job, err := worker.NewPartitionMaintenanceJob(worker.PartitionMaintenanceConfig{
		Interval:        cfg.Worker.PartitionInterval,
		LookaheadMonths: cfg.Worker.PartitionLookaheadMonths,
		Tables:          parents,
		Manager:         mgr,
		Logger:          logger,
	})
	if err != nil {
		logger.Warn("sn360-es: partition worker init failed",
			slog.Any("error", err))
		return nil
	}
	runner, rerr := worker.NewRunner(worker.RunnerConfig{
		Job:     job,
		Logger:  logger,
		Locks:   locks,
		Metrics: metrics,
	})
	if rerr != nil {
		logger.Warn("sn360-es: partition runner init failed",
			slog.Any("error", rerr))
		return nil
	}
	logger.Info("sn360-es: partition worker wired",
		slog.Duration("interval", cfg.Worker.PartitionInterval),
		slog.Int("lookahead_months", cfg.Worker.PartitionLookaheadMonths),
		slog.Int("retention_months", cfg.Worker.PartitionRetentionMonths),
		slog.Int("parents", len(parents)))
	return runner
}
