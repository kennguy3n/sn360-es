package action

import (
	"context"
	"fmt"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// PostgresReportStore persists user phishing reports to the
// user_reports table with de-duplication via a composite unique
// constraint on (tenant_id, message_id, reporter_hash).
type PostgresReportStore struct {
	db *postgres.DB
}

// NewPostgresReportStore wires the store against a Postgres connection.
func NewPostgresReportStore(db *postgres.DB) *PostgresReportStore {
	return &PostgresReportStore{db: db}
}

// EnsureSchema creates the user_reports table if it doesn't exist.
// Production should use Atlas migrations; this is a dev convenience.
func (s *PostgresReportStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS user_reports (
			id             BIGSERIAL PRIMARY KEY,
			tenant_id      TEXT NOT NULL,
			message_id     TEXT NOT NULL,
			reporter_hash  TEXT NOT NULL,
			created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(tenant_id, message_id, reporter_hash)
		);
		CREATE INDEX IF NOT EXISTS idx_user_reports_tenant_msg
			ON user_reports (tenant_id, message_id);
	`)
	return err
}

// Add implements ReportStore. It inserts a new report row and returns
// the total count of unique reporters for this message. Duplicate
// (tenant, message, reporter) combinations are silently ignored.
func (s *PostgresReportStore) Add(ctx context.Context, tenantID, pseudoMessageID, reporterHash string) (int, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_reports (tenant_id, message_id, reporter_hash)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, message_id, reporter_hash) DO NOTHING
	`, tenantID, pseudoMessageID, reporterHash)
	if err != nil {
		return 0, fmt.Errorf("report: add: %w", err)
	}
	return s.Get(ctx, tenantID, pseudoMessageID)
}

// Get implements ReportStore. Returns the count of unique reporters
// for the given message.
func (s *PostgresReportStore) Get(ctx context.Context, tenantID, pseudoMessageID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM user_reports
		WHERE tenant_id = $1 AND message_id = $2
	`, tenantID, pseudoMessageID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("report: get: %w", err)
	}
	return count, nil
}

// compile-time assertion
var _ ReportStore = (*PostgresReportStore)(nil)
