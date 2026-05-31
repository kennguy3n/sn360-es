package config

import (
	"strings"
	"testing"
	"time"
)

// TestLoadPostgresRead_DisabledByDefault locks the WS-2a contract
// that omitting PG_READ_HOST runs the application single-pool.
// Operators upgrading from the pre-WS-2a default must not have
// the replica path silently enabled.
func TestLoadPostgresRead_DisabledByDefault(t *testing.T) {
	withEnv(t, map[string]string{
		"PG_HOST":      "primary.local",
		"PG_DATABASE":  "sn360es",
		"PG_USER":      "user",
		"PG_PASSWORD":  "pw",
		"PG_READ_HOST": "",
	})
	pg := loadPostgres()
	if pg.Read.Host != "" {
		t.Fatalf("Read.Host with PG_READ_HOST unset must be empty; got %q", pg.Read.Host)
	}
	if pg.Read.Database != "" || pg.Read.User != "" {
		t.Fatalf("unset PG_READ_HOST must leave Read fields zero; got %+v", pg.Read)
	}
}

// TestLoadPostgresRead_InheritsPrimaryDefaults asserts that
// setting only PG_READ_HOST is enough to wire a replica — every
// other field falls back to the primary's setting so an operator
// who wants the same credentials on the replica does not have to
// re-specify them. This is what makes PG_READ_HOST=<host> a
// one-line opt-in.
func TestLoadPostgresRead_InheritsPrimaryDefaults(t *testing.T) {
	withEnv(t, map[string]string{
		"PG_HOST":                "primary.local",
		"PG_PORT":                "5433",
		"PG_USER":                "primary_user",
		"PG_PASSWORD":            "primary_pw",
		"PG_DATABASE":            "sn360es",
		"PG_SSLMODE":             "verify-full",
		"PG_MAX_OPEN_CONNS":      "55",
		"PG_MAX_IDLE_CONNS":      "9",
		"PG_CONN_MAX_LIFETIME":   "45m",
		"PG_READ_HOST":           "replica.local",
		"PG_READ_PORT":           "",
		"PG_READ_USER":           "",
		"PG_READ_PASSWORD":       "",
		"PG_READ_DATABASE":       "",
		"PG_READ_SSLMODE":        "",
		"PG_READ_MAX_OPEN_CONNS": "",
		"PG_READ_MAX_IDLE_CONNS": "",
	})
	pg := loadPostgres()
	if pg.Read.Host != "replica.local" {
		t.Fatalf("Read.Host = %q, want replica.local", pg.Read.Host)
	}
	if pg.Read.Port != 5433 {
		t.Errorf("Read.Port = %d, want inherited 5433", pg.Read.Port)
	}
	if pg.Read.User != "primary_user" {
		t.Errorf("Read.User = %q, want inherited primary_user", pg.Read.User)
	}
	if pg.Read.Password != "primary_pw" {
		t.Errorf("Read.Password inheritance failed; got %q", pg.Read.Password)
	}
	if pg.Read.Database != "sn360es" {
		t.Errorf("Read.Database = %q, want inherited sn360es", pg.Read.Database)
	}
	if pg.Read.SSLMode != "verify-full" {
		t.Errorf("Read.SSLMode = %q, want inherited verify-full", pg.Read.SSLMode)
	}
	if pg.Read.MaxOpenConns != 55 {
		t.Errorf("Read.MaxOpenConns = %d, want inherited 55", pg.Read.MaxOpenConns)
	}
	if pg.Read.MaxIdleConns != 9 {
		t.Errorf("Read.MaxIdleConns = %d, want inherited 9", pg.Read.MaxIdleConns)
	}
	if pg.Read.ConnMaxLifetime != 45*time.Minute {
		t.Errorf("Read.ConnMaxLifetime = %v, want inherited 45m", pg.Read.ConnMaxLifetime)
	}
}

// TestLoadPostgresRead_AllOverridesHonored confirms that supplying
// every PG_READ_* explicitly produces independent settings — a
// replica that lives in a different VPC and has its own
// credentials must be fully configurable without inheriting from
// the primary.
func TestLoadPostgresRead_AllOverridesHonored(t *testing.T) {
	withEnv(t, map[string]string{
		"PG_HOST":                   "primary.local",
		"PG_PORT":                   "5432",
		"PG_USER":                   "primary_user",
		"PG_PASSWORD":               "primary_pw",
		"PG_DATABASE":               "sn360es",
		"PG_SSLMODE":                "require",
		"PG_READ_HOST":              "replica.other.local",
		"PG_READ_PORT":              "6543",
		"PG_READ_USER":              "replica_user",
		"PG_READ_PASSWORD":          "replica_pw",
		"PG_READ_DATABASE":          "sn360es_replica",
		"PG_READ_SSLMODE":           "verify-full",
		"PG_READ_MAX_OPEN_CONNS":    "80",
		"PG_READ_MAX_IDLE_CONNS":    "20",
		"PG_READ_CONN_MAX_LIFETIME": "2h",
	})
	pg := loadPostgres()
	if pg.Read.Host != "replica.other.local" || pg.Read.Port != 6543 {
		t.Errorf("Read host/port not honored; got %s:%d", pg.Read.Host, pg.Read.Port)
	}
	if pg.Read.User != "replica_user" || pg.Read.Password != "replica_pw" {
		t.Errorf("Read user/password not honored; got user=%q", pg.Read.User)
	}
	if pg.Read.Database != "sn360es_replica" {
		t.Errorf("Read.Database not honored; got %q", pg.Read.Database)
	}
	if pg.Read.SSLMode != "verify-full" {
		t.Errorf("Read.SSLMode not honored; got %q", pg.Read.SSLMode)
	}
	if pg.Read.MaxOpenConns != 80 || pg.Read.MaxIdleConns != 20 {
		t.Errorf("Read pool size not honored; open=%d idle=%d", pg.Read.MaxOpenConns, pg.Read.MaxIdleConns)
	}
	if pg.Read.ConnMaxLifetime != 2*time.Hour {
		t.Errorf("Read.ConnMaxLifetime not honored; got %v", pg.Read.ConnMaxLifetime)
	}
}

// TestValidate_PgReadSSLModeDisableBlockedInProd guards the
// production-environment fail-closed rule for the replica
// connection: a deployment that explicitly sets PG_READ_HOST and
// then disables TLS on the replica is just as broken as the
// primary-disable case validate() already catches, and must be
// rejected at boot.
func TestValidate_PgReadSSLModeDisableBlockedInProd(t *testing.T) {
	cfg := validProdConfig()
	cfg.Postgres.Read = PostgresRead{
		Host:     "replica.local",
		Port:     5432,
		User:     "u",
		Database: "d",
		SSLMode:  "disable",
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("validate must reject PG_READ_SSLMODE=disable in prod when PG_READ_HOST is set")
	}
	if !strings.Contains(err.Error(), "PG_READ_SSLMODE") {
		t.Errorf("error must mention PG_READ_SSLMODE; got %q", err.Error())
	}
}

// TestValidate_PgReadSSLModeIgnoredWhenHostUnset documents the
// other half of the guard: when no replica is wired, the SSL-mode
// value is irrelevant and validate() must not reject on it (it's
// effectively dead config from leftover env). Without this the
// guard would produce a confusing error message for any operator
// who left PG_READ_SSLMODE=disable in their env from a previous
// test run.
func TestValidate_PgReadSSLModeIgnoredWhenHostUnset(t *testing.T) {
	cfg := validProdConfig()
	cfg.Postgres.Read = PostgresRead{
		Host:    "",
		SSLMode: "disable",
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate must ignore PG_READ_SSLMODE when PG_READ_HOST is unset; got %v", err)
	}
}
