// Command sn360-es-migrate is a thin wrapper around the golang-migrate
// library that drives the SN360-ES Postgres schema. It exists so the
// repository does not require a separate `migrate` binary install.
//
// Usage:
//
//	sn360-es-migrate up                # apply all pending migrations
//	sn360-es-migrate down 1            # roll back N steps (default 1)
//	sn360-es-migrate status            # print the current version
//	sn360-es-migrate version           # alias of `status`
//	sn360-es-migrate force 3           # force-set version (recovery)
//	sn360-es-migrate check             # validate filenames + SQL syntax
//
// Configuration is read from the same `PG_*` environment variables as
// the main service (see `.env.example`). The directory containing the
// SQL files defaults to `migrations/` relative to the current working
// directory; override with `--path` or `SN360ES_MIGRATIONS_PATH`.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// advisoryLockID is a fixed 64-bit lock key derived from the ASCII
// bytes of "SN360" so two replicas racing on migration startup all
// hash to the same advisory lock and the loser blocks until the
// winner has finished. See cmd/sn360-es-migrate/main.go withAdvisoryLock.
const advisoryLockID int64 = 0x534E333630

// advisoryLockAcquireTimeout caps how long withAdvisoryLock will
// wait to ACQUIRE the lock. It does NOT bound how long the
// migration itself runs once the lock is held — once acquired,
// the migration closure runs to completion (or to its own
// internal timeout).
//
// 5 minutes is the worst-case wait we expect during a normal
// rolling restart: even if the second pod boots while the first
// is mid-migration, the first should release well under 5min. A
// wait longer than that indicates the holder is genuinely stuck
// and an operator should investigate rather than letting the
// loser block indefinitely.
const advisoryLockAcquireTimeout = 5 * time.Minute

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sn360-es-migrate: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("sn360-es-migrate", flag.ContinueOnError)
	pathFlag := fs.String("path", envOr("SN360ES_MIGRATIONS_PATH", "migrations"), "directory containing migration SQL files")
	dsnFlag := fs.String("dsn", os.Getenv("MIGRATIONS_DSN"), "postgres connection URL (defaults to PG_* env vars)")
	fs.Usage = usage
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	args := fs.Args()
	if len(args) == 0 {
		usage()
		return errors.New("missing command")
	}

	switch args[0] {
	case "check":
		return checkMigrations(*pathFlag)
	}

	dsn := *dsnFlag
	if dsn == "" {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		dsn = postgres.DSNFromConfig(cfg.Postgres)
	}

	sourceURL, err := absSourceURL(*pathFlag)
	if err != nil {
		return err
	}

	m, err := migrate.New(sourceURL, dsn)
	if err != nil {
		return fmt.Errorf("init migrate: %w", err)
	}
	defer func() {
		_, _ = m.Close()
	}()

	cmd := args[0]
	switch cmd {
	case "up":
		if err := withAdvisoryLock(dsn, func() error {
			if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("up: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
		return printVersion(m, "up")
	case "down":
		steps := 1
		if len(args) > 1 {
			n, err := strconv.Atoi(args[1])
			if err != nil || n <= 0 {
				return fmt.Errorf("down: expected positive integer step count, got %q", args[1])
			}
			steps = n
		}
		if err := withAdvisoryLock(dsn, func() error {
			if err := m.Steps(-steps); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("down: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
		return printVersion(m, "down")
	case "status", "version":
		return printVersion(m, "status")
	case "force":
		if len(args) < 2 {
			return errors.New("force: missing version argument")
		}
		v, err := strconv.Atoi(args[1])
		if err != nil || v < 0 {
			return fmt.Errorf("force: expected non-negative integer, got %q", args[1])
		}
		if err := m.Force(v); err != nil {
			return fmt.Errorf("force: %w", err)
		}
		fmt.Printf("forced schema version to %d\n", v)
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

// absSourceURL builds a file:// URL pointing at an absolute migrations path.
func absSourceURL(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve migrations path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("migrations path %q: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("migrations path %q is not a directory", abs)
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	return u.String(), nil
}

func printVersion(m *migrate.Migrate, op string) error {
	v, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		fmt.Printf("%s: no schema version (database is empty)\n", op)
		return nil
	}
	if err != nil {
		return fmt.Errorf("version: %w", err)
	}
	state := "clean"
	if dirty {
		state = "DIRTY"
	}
	fmt.Printf("%s: schema_version=%d state=%s\n", op, v, state)
	return nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// withAdvisoryLock serialises migration commands across replicas.
//
// Without it, two pods running `sn360-es-migrate up` at the same
// time (e.g. a Helm pre-install hook on a fresh cluster, or a
// rolling restart against an empty schema-migrations table) can
// both attempt to apply the same numbered migration. golang-migrate
// uses a `schema_migrations` advisory of its own per-session, but it
// is granted only for the lifetime of the single migration call and
// does NOT serialise across migrate.New invocations — i.e. two
// processes calling m.Up() concurrently both see version=0 dirty=false
// and race on inserting version=1.
//
// We layer a process-spanning advisory lock on top using a fixed
// 64-bit key derived from the literal bytes "SN360" (advisoryLockID).
// The winner runs the closure to completion, the loser blocks at
// pg_advisory_lock() until the winner unlocks, then re-runs the
// migration; by then the winner has already advanced the schema so
// the loser's m.Up() returns ErrNoChange.
//
// Timeout scope: advisoryLockAcquireTimeout caps the wait to
// ACQUIRE the lock; the migration closure fn() itself runs
// without a context deadline. This matches golang-migrate's API
// (m.Up()/m.Steps() do not accept a context), so the only
// timeout we can enforce here is on the lock handshake. A truly
// runaway migration must be killed by the operator.
//
// Note: we open a NEW *sql.DB rather than reusing the migrate-driver's
// connection because golang-migrate does not expose a stable hook to
// run arbitrary SQL alongside the migration steps, and we need the
// lock to outlive a single statement. The pgx stdlib driver
// (registered by the blank import above) handles the DSN we already
// pass to migrate.New.
func withAdvisoryLock(dsn string, fn func() error) (retErr error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("advisory lock: open: %w", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("advisory lock: close: %w", cerr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), advisoryLockAcquireTimeout)
	defer cancel()

	// Hold the lock on a single dedicated connection so the
	// unlock below runs on the same backend that acquired it —
	// advisory locks are scoped per-connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("advisory lock: checkout conn: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", advisoryLockID); err != nil {
		return fmt.Errorf("advisory lock: acquire: %w", err)
	}
	defer func() {
		// Best-effort release on a background context so a
		// cancelled / timed-out ctx above doesn't prevent the
		// unlock. The lock is also released implicitly when the
		// connection closes, so even a release failure does not
		// strand the lock beyond the process lifetime.
		unlockCtx, unlockCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer unlockCancel()
		if _, uerr := conn.ExecContext(unlockCtx, "SELECT pg_advisory_unlock($1)", advisoryLockID); uerr != nil && retErr == nil {
			retErr = fmt.Errorf("advisory lock: release: %w", uerr)
		}
	}()
	return fn()
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: sn360-es-migrate [--path DIR] [--dsn URL] COMMAND [ARGS]

Commands:
  up              Apply all pending migrations.
  down [N]        Roll back the most recent N migrations (default 1).
  status          Print the current schema version.
  version         Alias for "status".
  force VERSION   Force-set the schema version (recovery).
  check           Validate filenames + parse SQL without touching the DB.
`)
}
