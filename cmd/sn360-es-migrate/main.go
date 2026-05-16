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
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

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
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("up: %w", err)
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
		if err := m.Steps(-steps); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("down: %w", err)
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
