package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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

// SQL templates for the partition manager. Extracted to package
// scope so the regression tests in wire_partitions_test.go can
// assert their literal shape — specifically, that they use single
// %I / %L specifiers (not %%I / %%L). Postgres' format() treats
// `%%` as a literal `%`, so a double-percent typo would silently
// render invalid DDL and break partition CREATE/DROP at runtime.
// Devin Review caught one such typo on the first push of this
// file; the asserts are the structural guardrail that keeps it
// from coming back.
//
// Identifier (%I) and literal (%L) quoting still flows through
// Postgres' format() at execution time — we don't substitute in
// Go because Go's fmt has no SQL-aware quoting.
const (
	createPartitionTmpl = `
		SELECT format(
		    'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
		    $1::text, $2::text, $3::text, $4::text
		)
	`
	detachPartitionTmpl = `SELECT format('ALTER TABLE %I DETACH PARTITION %I', $1::text, $2::text)`
	dropPartitionTmpl   = `SELECT format('DROP TABLE %I', $1::text)`
)

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
	// Capture the sanitised name and use it for the query so the
	// catalog lookup uses the same identifier we'd issue DDL
	// against — keeps ListPartitions consistent with
	// CreatePartition / DropPartition, which both pass the
	// sanitised form. ::regclass is case-insensitive at lookup
	// time so the practical behaviour is unchanged; this just
	// closes the consistency gap Devin Review flagged.
	sanitisedParent, err := worker.SanitizePartitionName(parent)
	if err != nil {
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
	rows, err := m.db.QueryContext(ctx, q, sanitisedParent)
	if err != nil {
		return nil, fmt.Errorf("list partitions for %s: %w", sanitisedParent, err)
	}
	defer rows.Close()
	out := make([]worker.Partition, 0, 8)
	for rows.Next() {
		var name, expr string
		if err := rows.Scan(&name, &expr); err != nil {
			return nil, fmt.Errorf("scan partition row: %w", err)
		}
		bound, perr := parsePartitionBound(expr)
		if perr != nil {
			m.logger.Warn("worker.partition: cannot parse bound; treating as legacy (untouchable)",
				slog.String("parent", sanitisedParent),
				slog.String("partition", name),
				slog.String("expr", expr),
				slog.Any("error", perr))
			// Surface the partition with zero bounds + Legacy=true
			// so the worker treats it as untouchable. Forcing
			// Legacy=true is the authoritative signal — the
			// retention sweep checks it before any time math.
			out = append(out, worker.Partition{Name: name, Legacy: true})
			continue
		}
		// Three independent legacy signals — any one of them
		// makes the partition untouchable for the retention
		// sweep:
		//   1. `_legacy` name suffix — the historical partition
		//      attached by the 0017 migration.
		//   2. Lower bound = MINVALUE — the partition catches
		//      "everything before time T". Same shape as the
		//      legacy partition; future ATTACH operations might
		//      create one without the name convention.
		//   3. Upper bound = MAXVALUE — the partition catches
		//      "everything from time T onwards". Dropping this
		//      would discard the live tail. The current 0017
		//      migration never creates this shape, but a future
		//      manual partitioning operation could, and the
		//      reviewer flagged the gap explicitly.
		legacy := strings.HasSuffix(name, "_legacy") || bound.LowerUnbounded || bound.UpperUnbounded
		out = append(out, worker.Partition{
			Name:   name,
			Lower:  bound.Lower,
			Upper:  bound.Upper,
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
	// See package-level createPartitionTmpl for the format-spec
	// footgun the comment block above used to call out.
	var ddl string
	if err := m.db.QueryRowContext(ctx, createPartitionTmpl,
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
//
// DETACH + DROP run inside a single transaction so a failure on
// the second statement (or a context cancellation between them)
// cannot leave behind an orphan table — a standalone table with
// the partition's name but no `pg_inherits` link. Without the
// transaction, that orphan would cause the next reconcile cycle
// to see no partition for the dropped range (so it would try to
// CREATE), but the CREATE would silently no-op against the
// orphan (`CREATE TABLE IF NOT EXISTS` matches by name) and
// inserts targeting that month would route to a row-less
// orphan without partition routing — silent data loss. Wrapping
// both statements means either the partition is fully gone (we
// can CREATE a fresh one next cycle) or it is fully present (we
// retry the drop next cycle), never half-detached.
func (m *pgPartitionManager) DropPartition(ctx context.Context, parent, partition string) error {
	sanitisedParent, err := worker.SanitizePartitionName(parent)
	if err != nil {
		return fmt.Errorf("DropPartition: invalid parent %q: %w", parent, err)
	}
	sanitisedPart, err := worker.SanitizePartitionName(partition)
	if err != nil {
		return fmt.Errorf("DropPartition: invalid partition %q: %w", partition, err)
	}

	// Compose the two DDL statements through Postgres' format()
	// before opening the transaction. format() is a pure
	// expression, so we don't need a transaction to call it
	// safely, and pulling the composition out of the tx keeps
	// the tx-scope small (the transaction only spans the two
	// DDL executions that mutate the catalog). See package-level
	// detachPartitionTmpl / dropPartitionTmpl for the templates.
	var detachStmt string
	if err := m.db.QueryRowContext(ctx, detachPartitionTmpl, sanitisedParent, sanitisedPart).Scan(&detachStmt); err != nil {
		return fmt.Errorf("compose DETACH DDL: %w", err)
	}
	var dropStmt string
	if err := m.db.QueryRowContext(ctx, dropPartitionTmpl, sanitisedPart).Scan(&dropStmt); err != nil {
		return fmt.Errorf("compose DROP DDL: %w", err)
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("DropPartition: begin tx: %w", err)
	}
	// Rollback on any return path that hasn't committed. The
	// defer is a belt to the explicit rollbacks below — Tx.
	// Rollback() after a successful Commit() is a documented no-op.
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, detachStmt); err != nil {
		return fmt.Errorf("execute DETACH PARTITION: %w", err)
	}
	if _, err := tx.ExecContext(ctx, dropStmt); err != nil {
		return fmt.Errorf("execute DROP TABLE: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("DropPartition: commit: %w", err)
	}
	return nil
}

// partitionBound is the parsed result of pg_get_expr() on a
// RANGE partition's relpartbound. LowerUnbounded / UpperUnbounded
// distinguish MINVALUE / MAXVALUE from a real timestamp; the
// retention sweep treats either as a sentinel for "never auto-
// drop" because both shapes catch open-ended time ranges that
// can't be expressed in the cutoff comparison without risk.
type partitionBound struct {
	Lower          time.Time
	Upper          time.Time
	LowerUnbounded bool // MINVALUE
	UpperUnbounded bool // MAXVALUE — partition extends to +∞
}

// parsePartitionBound parses Postgres' canonical
// `FOR VALUES FROM ('lo') TO ('hi')` partition-bound expression.
// Returns a partitionBound where LowerUnbounded / UpperUnbounded
// are true for MINVALUE / MAXVALUE respectively (the timestamp
// fields are zero-valued in that case and MUST be ignored by
// callers). Bounds emitted by the 0017 migration always carry an
// explicit timezone so RFC3339 parsing succeeds.
func parsePartitionBound(expr string) (partitionBound, error) {
	// Strip the canonical wrapping. Anything else is a shape we
	// don't recognise (LIST / HASH / DEFAULT) — surface an error
	// rather than silently misinterpreting.
	const prefix = "FOR VALUES FROM ("
	const sep = ") TO ("
	const suffix = ")"
	if !strings.HasPrefix(expr, prefix) || !strings.HasSuffix(expr, suffix) {
		return partitionBound{}, fmt.Errorf("unrecognised partition bound shape: %q", expr)
	}
	inner := expr[len(prefix) : len(expr)-len(suffix)]
	idx := strings.Index(inner, sep)
	if idx < 0 {
		return partitionBound{}, fmt.Errorf("missing FROM/TO separator: %q", expr)
	}
	loRaw := unquoteSQLLiteral(inner[:idx])
	hiRaw := unquoteSQLLiteral(inner[idx+len(sep):])

	out := partitionBound{}
	if loRaw == "MINVALUE" {
		out.LowerUnbounded = true
	} else {
		t, err := parsePartitionTimestamp(loRaw)
		if err != nil {
			return partitionBound{}, fmt.Errorf("parse lower bound %q: %w", loRaw, err)
		}
		out.Lower = t
	}
	if hiRaw == "MAXVALUE" {
		out.UpperUnbounded = true
	} else {
		t, err := parsePartitionTimestamp(hiRaw)
		if err != nil {
			return partitionBound{}, fmt.Errorf("parse upper bound %q: %w", hiRaw, err)
		}
		out.Upper = t
	}
	return out, nil
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
