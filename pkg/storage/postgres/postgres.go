// Package postgres hosts the SN360-ES Postgres client wrapper.
//
// The wrapper exposes the small subset of `database/sql` we actually use
// (Open, Ping, BeginTx, helper for `ExecContext` + `QueryContext`) along
// with a uniform DSN builder so the rest of the codebase does not depend
// directly on a specific driver. The pgx stdlib driver
// (`github.com/jackc/pgx/v5/stdlib`) is wired in by default — callers that
// need a different driver can register their own and call `Open` with
// `driver=<name>`.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	// Register the pgx/v5 stdlib driver so callers can Open() with
	// driver=pgx without an extra import in every consumer.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kennguy3n/sn360-es/internal/config"
)

// Config configures a Postgres connection pool.
type Config struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	// Driver overrides the registered driver name (default "pgx").
	Driver string
}

// DSN returns a libpq-style connection string.
func (c Config) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, sslmodeOrDisable(c.SSLMode),
	)
}

// URL returns a postgres:// URL form of the DSN (useful for migration
// tools that prefer URLs over kv strings).
func (c Config) URL() string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.User, c.Password),
		Host:   fmt.Sprintf("%s:%d", c.Host, c.Port),
		Path:   "/" + c.Database,
	}
	q := u.Query()
	q.Set("sslmode", sslmodeOrDisable(c.SSLMode))
	u.RawQuery = q.Encode()
	return u.String()
}

func sslmodeOrDisable(s string) string {
	if s == "" {
		return "disable"
	}
	return s
}

// DSNFromConfig converts a config.Postgres into a postgres:// URL.
//
// Migration tools (golang-migrate, atlas, sqlc) all accept the URL form,
// so this is the canonical way to build a connection string from the
// main service config.
func DSNFromConfig(c config.Postgres) string {
	cfg := Config{
		Host:     c.Host,
		Port:     c.Port,
		User:     c.User,
		Password: c.Password,
		Database: c.Database,
		SSLMode:  c.SSLMode,
	}
	return cfg.URL()
}

// DB is the lightweight wrapper around *sql.DB.
//
// It carries an optional read-replica pool (sqlRead). When set,
// QueryContext / QueryRowContext route to the read pool unless a
// tenant-bound conn is already in context (see
// boundConnFromContext) — the bound conn always wins because RLS
// session GUCs are pinned to that specific conn on the write pool.
// ExecContext and BeginTx always route to the write pool, so
// mutations stay on the primary regardless of read-pool config.
// AttachReader is the public entry point that wires the read pool
// after Open succeeds (the wiring layer in cmd/sn360-es/app.go uses
// this so a misconfigured replica fails loudly during boot rather
// than silently degrading to single-pool mode).
type DB struct {
	sqlDB     *sql.DB
	sqlRead   *sql.DB
	readHost  string
	driver    string
	readOwned bool
}

// Open dials Postgres with the given configuration and returns a DB. The
// caller is responsible for calling Close.
func Open(ctx context.Context, cfg Config) (*DB, error) {
	if cfg.Host == "" {
		return nil, errors.New("postgres: Host is required")
	}
	if cfg.Database == "" {
		return nil, errors.New("postgres: Database is required")
	}
	driver := cfg.Driver
	if driver == "" {
		driver = "pgx"
	}
	sqlDB, err := openAndPing(ctx, driver, cfg)
	if err != nil {
		return nil, err
	}
	return &DB{sqlDB: sqlDB, driver: driver}, nil
}

// openAndPing is the shared dial-and-verify helper used by Open and
// AttachReader. Extracted so the read-pool wiring exercises the
// same dial timeout, pool-size, and connectivity checks the write
// pool does — a replica that can't be pinged at boot is a
// configuration bug, not a degraded-mode condition, and should
// surface during application startup rather than at first query.
func openAndPing(ctx context.Context, driver string, cfg Config) (*sql.DB, error) {
	sqlDB, err := sql.Open(driver, cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	if cfg.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}

	pingCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout(cfg))
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return sqlDB, nil
}

// AttachReader wires a read-replica pool to the DB. After this
// returns, QueryContext / QueryRowContext on a ctx with no
// bound-conn will route to the replica instead of the write pool.
// The DB takes ownership of the read pool — Close shuts both pools
// down. AttachReader is idempotent: calling it twice replaces the
// previously-attached reader (the old reader is closed). Passing
// an empty Host returns immediately with no error so callers can
// pass a partially-populated config without nil-checks.
//
// WS-2a (Read-Replica Routing): the read pool is wired separately
// from Open so a deployment without PG_READ_HOST set still gets a
// fully-functional single-pool DB — production environments enable
// the replica by setting PG_READ_HOST and the routing kicks in
// transparently for every Query* call site, no repo changes
// required.
func (d *DB) AttachReader(ctx context.Context, cfg Config) error {
	if d == nil || d.sqlDB == nil {
		return errors.New("postgres: AttachReader: DB is not initialised")
	}
	if cfg.Host == "" {
		return nil
	}
	if cfg.Database == "" {
		return errors.New("postgres: AttachReader: Database is required")
	}
	driver := cfg.Driver
	if driver == "" {
		driver = d.driver
	}
	if driver == "" {
		driver = "pgx"
	}
	sqlRead, err := openAndPing(ctx, driver, cfg)
	if err != nil {
		return fmt.Errorf("postgres: AttachReader: %w", err)
	}
	// Replace any previously-attached reader to keep AttachReader
	// idempotent. Closing the old pool here means the only path
	// that leaks a reader is a caller who never called Close on
	// the DB itself.
	if d.sqlRead != nil && d.readOwned {
		_ = d.sqlRead.Close()
	}
	d.sqlRead = sqlRead
	d.readHost = cfg.Host
	d.readOwned = true
	return nil
}

func defaultDialTimeout(cfg Config) time.Duration {
	if cfg.ConnMaxLifetime > 0 && cfg.ConnMaxLifetime < 5*time.Second {
		return cfg.ConnMaxLifetime
	}
	return 5 * time.Second
}

// SQL returns the underlying *sql.DB for callers that need primitives
// outside this wrapper. This always returns the write pool — callers
// that explicitly want the read pool (e.g. dashboard aggregation
// queries opting in to replica routing) should use SQLRead.
func (d *DB) SQL() *sql.DB { return d.sqlDB }

// SQLRead returns the read-pool *sql.DB if one was attached via
// AttachReader, otherwise nil. Call sites that want explicit
// read-replica routing (rather than the implicit routing in
// QueryContext / QueryRowContext) can fall back to SQL when this
// returns nil: `db := pg.SQLRead(); if db == nil { db = pg.SQL() }`.
func (d *DB) SQLRead() *sql.DB {
	if d == nil {
		return nil
	}
	return d.sqlRead
}

// HasReader reports whether a read replica is attached. Useful for
// readiness probes that want to log "single-pool" vs "primary +
// replica" boot mode without exposing the underlying *sql.DB.
func (d *DB) HasReader() bool {
	return d != nil && d.sqlRead != nil
}

// ReadHost returns the configured replica host (empty when no
// reader is attached). Used by structured boot logs so operators
// can confirm the WS-2a routing target without a separate probe.
func (d *DB) ReadHost() string {
	if d == nil {
		return ""
	}
	return d.readHost
}

// Driver reports the registered driver name in use (e.g. "pgx").
func (d *DB) Driver() string { return d.driver }

// Close shuts down all pooled connections (write pool and, if
// attached, the read pool). Errors from the read-pool close are
// not surfaced separately — in practice both pools share fate
// (process shutdown) and the write-pool error is the more
// actionable signal.
func (d *DB) Close() error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	if d.sqlRead != nil && d.readOwned {
		_ = d.sqlRead.Close()
	}
	return d.sqlDB.Close()
}

// PingContext exposes *sql.DB.PingContext for readiness probes.
// When a read pool is attached it is pinged too — a replica that
// has fallen off is a real availability concern even when the
// write pool is healthy (read-only endpoints would start failing).
func (d *DB) PingContext(ctx context.Context) error {
	if err := d.sqlDB.PingContext(ctx); err != nil {
		return err
	}
	if d.sqlRead != nil {
		if err := d.sqlRead.PingContext(ctx); err != nil {
			return fmt.Errorf("postgres: ping read replica: %w", err)
		}
	}
	return nil
}

// ExecContext forwards to a pinned tenant-bound *sql.Conn if one is
// attached to ctx (see tenant_context.go::WithBoundConn). Otherwise it
// forwards to the underlying *sql.DB pool. Routing through the pinned
// conn is what makes the Postgres RLS policy installed in
// `migrations/0018_row_level_security.up.sql` actually scope the
// query — the session GUC `sn360.tenant_id` was SET on that conn at
// bind time and would not be visible to a fresh pool conn.
func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if conn := boundConnFromContext(ctx); conn != nil {
		return conn.ExecContext(ctx, query, args...)
	}
	return d.sqlDB.ExecContext(ctx, query, args...)
}

// QueryContext forwards to a pinned tenant-bound *sql.Conn if one is
// attached to ctx, otherwise to the read-replica pool (when one is
// attached via AttachReader) or the write pool as a fallback. The
// returned *sql.Rows holds a reference to the pinned conn for the
// lifetime of iteration; the caller MUST close the rows before the
// bound-conn scope (e.g. the WithTenant cleanup) releases the
// connection.
//
// WS-2a routing matrix:
//
//	bound-conn present  -> bound conn (write pool, RLS-scoped)
//	no bound-conn + reader attached  -> read replica
//	no bound-conn + no reader        -> write pool
//
// Tenant-scoped reads (the common case for handler / consumer
// paths) always carry a bound conn from WithTenant, so they keep
// running against the primary even when a replica is wired — the
// session GUC `sn360.tenant_id` is pinned to that conn and is
// invisible to the replica's pool. Cross-tenant / unbound reads
// (audit log lookups, dashboard aggregations, vendor catalog
// browsing) automatically benefit from replica offload without
// any repo-side change.
func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if conn := boundConnFromContext(ctx); conn != nil {
		return conn.QueryContext(ctx, query, args...)
	}
	if d.sqlRead != nil {
		return d.sqlRead.QueryContext(ctx, query, args...)
	}
	return d.sqlDB.QueryContext(ctx, query, args...)
}

// QueryRowContext forwards to a pinned tenant-bound *sql.Conn if one
// is attached to ctx, otherwise to the read replica when one is
// attached, otherwise to the write pool. Same routing matrix as
// QueryContext — see that doc for the rationale.
func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if conn := boundConnFromContext(ctx); conn != nil {
		return conn.QueryRowContext(ctx, query, args...)
	}
	if d.sqlRead != nil {
		return d.sqlRead.QueryRowContext(ctx, query, args...)
	}
	return d.sqlDB.QueryRowContext(ctx, query, args...)
}

// BeginTx starts a transaction on the pinned tenant-bound *sql.Conn
// if one is attached to ctx, otherwise on the underlying pool. The
// transaction inherits the conn's session GUCs (sn360.tenant_id /
// sn360.cross_tenant) so RLS continues to scope the queries inside
// the txn.
func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	if conn := boundConnFromContext(ctx); conn != nil {
		return conn.BeginTx(ctx, opts)
	}
	return d.sqlDB.BeginTx(ctx, opts)
}

// QuotedIdent returns an identifier safe for inline use in a SQL
// statement. Postgres double-quotes identifiers and doubles any embedded
// double-quote.
func QuotedIdent(name string) string {
	q := []byte{'"'}
	for i := 0; i < len(name); i++ {
		if name[i] == '"' {
			q = append(q, '"', '"')
			continue
		}
		q = append(q, name[i])
	}
	q = append(q, '"')
	return string(q)
}

// ParseURL splits a postgres:// URL into a Config. Used by tooling and
// tests that receive a DSN from the environment.
func ParseURL(rawURL string) (Config, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Config{}, fmt.Errorf("postgres: parse url: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return Config{}, fmt.Errorf("postgres: unsupported scheme %q", u.Scheme)
	}
	port := 5432
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil {
			return Config{}, fmt.Errorf("postgres: parse port: %w", perr)
		}
		port = n
	}
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	cfg := Config{
		Host:     u.Hostname(),
		Port:     port,
		User:     user,
		Password: pass,
		Database: trimPathPrefix(u.Path),
		SSLMode:  u.Query().Get("sslmode"),
	}
	return cfg, nil
}

func trimPathPrefix(p string) string {
	if len(p) > 0 && p[0] == '/' {
		return p[1:]
	}
	return p
}
