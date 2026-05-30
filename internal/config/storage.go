package config

import (
	"fmt"
	"time"
)

// Postgres carries database connection config.
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
}

// DSN returns a libpq connection string.
func (p Postgres) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		p.Host, p.Port, p.User, p.Password, p.Database, p.SSLMode,
	)
}

func loadPostgres() Postgres {
	return Postgres{
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
