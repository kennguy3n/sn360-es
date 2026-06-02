package config

import (
	"fmt"
	"time"
)

// Postgres carries database connection config for the writer pool.
// Read traffic is optionally routed to a separate replica when
// ReadHost is set (see PostgresRead and docs/MULTI_REGION.md).
type Postgres struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration

	// Read holds optional read-replica connection settings.
	// When Read.Host is empty the application runs single-pool
	// (every Query* hits the primary). When set, the postgres
	// wrapper opens a second pool against the replica and routes
	// unbound reads (no tenant-context conn binding) to it.
	Read PostgresRead

	// HomeRegion names the region whose tenants are served by
	// the primary (PG_HOST) pool. Loaded from PG_HOME_REGION;
	// defaults to "ap-southeast-1" to match the `tenants.region`
	// column default in migrations/0001_init.up.sql:25. Has no
	// effect when RegionMap is empty (single-region deployment).
	HomeRegion string

	// RegionMap is the parsed PG_REGION_MAP env var: a mapping
	// of region name -> Postgres connection settings. Empty /
	// nil means single-region mode and the binary continues to
	// run against PG_HOST / PG_READ_HOST unchanged (the
	// default for every existing deployment). See
	// internal/config/postgres.go and
	// docs/MULTI_REGION.md for the contract.
	RegionMap map[string]Postgres
}

// PostgresRead carries connection settings for the optional read
// replica. Fields that fall back to the primary's settings are
// resolved in loadPostgres so callers see a fully-populated value.
//
// WS-2a (Read-Replica Routing): production deployments enable the
// replica by setting PG_READ_HOST (and optionally PG_READ_USER /
// PG_READ_PASSWORD if the replica has separate credentials).
// MaxOpenConns / MaxIdleConns default to the primary's values —
// most deployments size the replica pool the same as the primary;
// operators who want a different shape can override per-field via
// PG_READ_MAX_OPEN_CONNS / PG_READ_MAX_IDLE_CONNS.
type PostgresRead struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DSN returns a libpq connection string.
func (p Postgres) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		p.Host, p.Port, p.User, p.Password, p.Database, p.SSLMode,
	)
}

func loadPostgres() Postgres {
	primary := Postgres{
		Host:     getStr("PG_HOST", "127.0.0.1"),
		Port:     getInt("PG_PORT", 5432),
		User:     getStr("PG_USER", "sn360es"),
		Password: getStr("PG_PASSWORD", "sn360es"),
		Database: getStr("PG_DATABASE", "sn360es"),
		// Default to require so a forgotten PG_SSLMODE in a new
		// deployment fails secure. Production environments also
		// refuse the explicit value "disable" in validate().
		SSLMode:         getStr("PG_SSLMODE", "require"),
		MaxOpenConns:    getInt("PG_MAX_OPEN_CONNS", 40),
		MaxIdleConns:    getInt("PG_MAX_IDLE_CONNS", 10),
		ConnMaxLifetime: getDuration("PG_CONN_MAX_LIFETIME", time.Hour),
		// WS-7a multi-region routing: defaults match the
		// tenants.region column default in
		// migrations/0001_init.up.sql:25 so single-region
		// deployments (PG_REGION_MAP unset) and the home-region
		// branch of multi-region deployments agree on the same
		// region name without operator config.
		HomeRegion: getStr("PG_HOME_REGION", "ap-southeast-1"),
	}
	primary.Read = loadPostgresRead(primary)
	// RegionMap is populated by Load() after the strict numeric
	// re-parse — parsing PG_REGION_MAP can fail and Load is the
	// only call-site that propagates the error to callers.
	return primary
}

// loadPostgresRead builds the read-replica settings, inheriting
// any field the operator did not explicitly override from the
// primary settings. The Host field is the single trigger: when
// PG_READ_HOST is unset, the function returns a zero value and
// the wiring layer (cmd/sn360-es/app.go) skips AttachReader — the
// application runs single-pool. When set, the rest of the fields
// inherit sensible defaults so a deployment that only wants to
// supply the replica hostname does not also have to re-specify
// the user/password/database that already work for the primary.
func loadPostgresRead(primary Postgres) PostgresRead {
	host := getStr("PG_READ_HOST", "")
	if host == "" {
		return PostgresRead{}
	}
	return PostgresRead{
		Host:            host,
		Port:            getInt("PG_READ_PORT", primary.Port),
		User:            getStr("PG_READ_USER", primary.User),
		Password:        getStr("PG_READ_PASSWORD", primary.Password),
		Database:        getStr("PG_READ_DATABASE", primary.Database),
		SSLMode:         getStr("PG_READ_SSLMODE", primary.SSLMode),
		MaxOpenConns:    getInt("PG_READ_MAX_OPEN_CONNS", primary.MaxOpenConns),
		MaxIdleConns:    getInt("PG_READ_MAX_IDLE_CONNS", primary.MaxIdleConns),
		ConnMaxLifetime: getDuration("PG_READ_CONN_MAX_LIFETIME", primary.ConnMaxLifetime),
	}
}

// AWS holds AWS-related configuration (KMS, S3).
type AWS struct {
	Region              string
	KMSMasterKeyID      string
	S3CredentialsBucket string
	KMSUseMock          bool
	KMSMockKeyHex       string
}

func loadAWS() AWS {
	return AWS{
		Region:              getStr("AWS_REGION", "ap-southeast-1"),
		KMSMasterKeyID:      getStr("AWS_KMS_MASTER_KEY_ID", ""),
		S3CredentialsBucket: getStr("AWS_S3_BUCKET_CREDENTIALS", ""),
		KMSUseMock:          getBool("KMS_USE_MOCK", true),
		KMSMockKeyHex:       getStr("KMS_MOCK_KEY_HEX", ""),
	}
}
