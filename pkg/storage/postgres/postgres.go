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
type DB struct {
	sqlDB  *sql.DB
	driver string
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
	return &DB{sqlDB: sqlDB, driver: driver}, nil
}

func defaultDialTimeout(cfg Config) time.Duration {
	if cfg.ConnMaxLifetime > 0 && cfg.ConnMaxLifetime < 5*time.Second {
		return cfg.ConnMaxLifetime
	}
	return 5 * time.Second
}

// SQL returns the underlying *sql.DB for callers that need primitives
// outside this wrapper.
func (d *DB) SQL() *sql.DB { return d.sqlDB }

// Driver reports the registered driver name in use (e.g. "pgx").
func (d *DB) Driver() string { return d.driver }

// Close shuts down all pooled connections.
func (d *DB) Close() error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	return d.sqlDB.Close()
}

// PingContext exposes *sql.DB.PingContext for readiness probes.
func (d *DB) PingContext(ctx context.Context) error {
	return d.sqlDB.PingContext(ctx)
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
// attached to ctx, otherwise to the underlying pool. The returned
// *sql.Rows holds a reference to the pinned conn for the lifetime of
// iteration; the caller MUST close the rows before the bound-conn
// scope (e.g. the WithTenant cleanup) releases the connection.
func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if conn := boundConnFromContext(ctx); conn != nil {
		return conn.QueryContext(ctx, query, args...)
	}
	return d.sqlDB.QueryContext(ctx, query, args...)
}

// QueryRowContext forwards to a pinned tenant-bound *sql.Conn if one
// is attached to ctx, otherwise to the underlying pool.
func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if conn := boundConnFromContext(ctx); conn != nil {
		return conn.QueryRowContext(ctx, query, args...)
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
