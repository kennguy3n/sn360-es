package education

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// PostgresCampaignStore persists simulation campaigns to the
// education_campaigns table. The full Campaign DTO is round-tripped
// through a JSONB column so we don't lose fields on schema evolution.
type PostgresCampaignStore struct {
	db *postgres.DB
}

// NewPostgresCampaignStore wires the store against a Postgres
// connection. The caller is responsible for ensuring the
// education_campaigns migration has been applied.
func NewPostgresCampaignStore(db *postgres.DB) *PostgresCampaignStore {
	return &PostgresCampaignStore{db: db}
}

// EnsureSchema creates the education_campaigns table if it doesn't
// exist. This is a convenience for development; production should use
// Atlas migrations.
func (s *PostgresCampaignStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS education_campaigns (
			campaign_id  TEXT PRIMARY KEY,
			tenant_id    TEXT NOT NULL,
			name         TEXT NOT NULL DEFAULT '',
			template_id  TEXT NOT NULL DEFAULT '',
			difficulty   TEXT NOT NULL DEFAULT 'beginner',
			status       TEXT NOT NULL DEFAULT 'draft',
			target_count INT  NOT NULL DEFAULT 0,
			sent_count   INT  NOT NULL DEFAULT 0,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			scheduled_at TIMESTAMPTZ,
			started_at   TIMESTAMPTZ,
			completed_at TIMESTAMPTZ,
			context      JSONB NOT NULL DEFAULT '{}'
		);
		CREATE INDEX IF NOT EXISTS idx_education_campaigns_tenant
			ON education_campaigns (tenant_id);
	`)
	return err
}

// campaignRow is the JSONB payload stored alongside the discrete columns.
type campaignRow struct {
	Campaign dto.Campaign `json:"campaign"`
}

// SaveCampaign implements CampaignStore.
func (s *PostgresCampaignStore) SaveCampaign(ctx context.Context, c dto.Campaign) error {
	payload, err := json.Marshal(campaignRow{Campaign: c})
	if err != nil {
		return fmt.Errorf("education: marshal campaign: %w", err)
	}

	var (
		scheduledAt any
		startedAt   any
		completedAt any
	)
	if !c.ScheduledAt.IsZero() {
		scheduledAt = c.ScheduledAt.UTC()
	}
	if c.StartedAt != nil {
		startedAt = c.StartedAt.UTC()
	}
	if c.CompletedAt != nil {
		completedAt = c.CompletedAt.UTC()
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO education_campaigns
			(campaign_id, tenant_id, name, template_id, difficulty, status,
			 target_count, sent_count, created_at, scheduled_at, started_at,
			 completed_at, context)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (campaign_id) DO UPDATE SET
			name         = EXCLUDED.name,
			template_id  = EXCLUDED.template_id,
			difficulty   = EXCLUDED.difficulty,
			status       = EXCLUDED.status,
			target_count = EXCLUDED.target_count,
			sent_count   = EXCLUDED.sent_count,
			scheduled_at = EXCLUDED.scheduled_at,
			started_at   = EXCLUDED.started_at,
			completed_at = EXCLUDED.completed_at,
			context      = EXCLUDED.context
	`,
		c.CampaignID, c.TenantID, c.Name, c.TemplateID,
		string(c.Difficulty), string(c.Status),
		c.TargetCount, c.SentCount,
		c.CreatedAt.UTC(), scheduledAt, startedAt, completedAt,
		payload,
	)
	if err != nil {
		return fmt.Errorf("education: save campaign: %w", err)
	}
	return nil
}

// LoadCampaign implements CampaignStore.
func (s *PostgresCampaignStore) LoadCampaign(ctx context.Context, id string) (dto.Campaign, bool, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT context FROM education_campaigns WHERE campaign_id = $1`, id,
	).Scan(&blob)
	if err != nil {
		if err == sql.ErrNoRows {
			return dto.Campaign{}, false, nil
		}
		return dto.Campaign{}, false, fmt.Errorf("education: load campaign: %w", err)
	}
	var row campaignRow
	if err := json.Unmarshal(blob, &row); err != nil {
		return dto.Campaign{}, false, fmt.Errorf("education: unmarshal campaign: %w", err)
	}
	return row.Campaign, true, nil
}

// ListCampaigns implements CampaignStore.
func (s *PostgresCampaignStore) ListCampaigns(ctx context.Context, tenantID string) ([]dto.Campaign, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT context FROM education_campaigns WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT context FROM education_campaigns ORDER BY created_at DESC`)
	}
	if err != nil {
		return nil, fmt.Errorf("education: list campaigns: %w", err)
	}
	defer rows.Close()

	var out []dto.Campaign
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, fmt.Errorf("education: scan campaign: %w", err)
		}
		var row campaignRow
		if err := json.Unmarshal(blob, &row); err != nil {
			continue
		}
		out = append(out, row.Campaign)
	}
	return out, rows.Err()
}

// CountByStatus returns the number of campaigns per status for a tenant.
// Useful for dashboard aggregation.
func (s *PostgresCampaignStore) CountByStatus(ctx context.Context, tenantID string) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM education_campaigns WHERE tenant_id = $1 GROUP BY status`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("education: count by status: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		counts[status] = count
	}
	return counts, rows.Err()
}

// compile-time assertion
var _ CampaignStore = (*PostgresCampaignStore)(nil)

// suppress unused import
var _ = time.Now
