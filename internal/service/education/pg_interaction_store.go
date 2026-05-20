package education

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// PostgresInteractionStore persists per-campaign user interactions in
// the education_interactions table. One row per (campaign_id,
// user_hash) tuple records which actions a target took during a
// phishing-simulation campaign.
//
// Schema rationale: the migration's `simulation_results` table is
// foreign-keyed to `campaigns(UUID)`, but the education
// SimulationEngine generates campaign IDs as opaque hex strings
// ("camp-<hex>") rather than UUIDs. To keep the persistence layer
// aligned with the existing education_campaigns table (TEXT
// campaign_id) created by PostgresCampaignStore, we provision a
// parallel education_interactions table here instead of reusing
// simulation_results. Both tables share the same boolean-flag column
// layout so the data model is intuitive for SQL ad-hoc analysis.
type PostgresInteractionStore struct {
	db *postgres.DB
}

// NewPostgresInteractionStore wires the store against a Postgres
// connection. The caller is responsible for invoking EnsureSchema (or
// running a migration) before reads or writes.
func NewPostgresInteractionStore(db *postgres.DB) *PostgresInteractionStore {
	return &PostgresInteractionStore{db: db}
}

// EnsureSchema creates the education_interactions table if it does
// not exist. Mirrors PostgresCampaignStore.EnsureSchema so production
// boots cleanly even when run before the operator has applied a
// numbered Atlas migration that codifies the same DDL.
func (s *PostgresInteractionStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS education_interactions (
			campaign_id     TEXT        NOT NULL,
			user_hash       TEXT        NOT NULL,
			delivered       BOOLEAN     NOT NULL DEFAULT FALSE,
			opened          BOOLEAN     NOT NULL DEFAULT FALSE,
			clicked         BOOLEAN     NOT NULL DEFAULT FALSE,
			submitted_creds BOOLEAN     NOT NULL DEFAULT FALSE,
			reported        BOOLEAN     NOT NULL DEFAULT FALSE,
			ignored         BOOLEAN     NOT NULL DEFAULT FALSE,
			first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (campaign_id, user_hash)
		);
		CREATE INDEX IF NOT EXISTS idx_education_interactions_campaign
			ON education_interactions (campaign_id);
	`)
	return err
}

// actionColumn returns the column toggled for a given interaction
// type. Returns "" when the action does not map onto a discrete
// column (e.g. an unknown action — should never happen if the DTO
// validator was used).
func actionColumn(a dto.UserInteractionType) string {
	switch a {
	case dto.InteractionDelivered:
		return "delivered"
	case dto.InteractionOpened:
		return "opened"
	case dto.InteractionClickedLink:
		return "clicked"
	case dto.InteractionSubmittedCredentials:
		return "submitted_creds"
	case dto.InteractionReportedPhishing:
		return "reported"
	case dto.InteractionIgnored:
		return "ignored"
	}
	return ""
}

// Append implements InteractionStore. Each invocation is an UPSERT —
// the row is created if it does not exist, otherwise the matching
// action column is flipped to TRUE and updated_at is bumped. This
// matches the semantics expected by callers like SimulationTracker:
// recording "opened" twice for the same user should not produce two
// distinct rows.
func (s *PostgresInteractionStore) Append(ctx context.Context, i dto.UserInteraction) error {
	col := actionColumn(i.Action)
	if col == "" {
		return fmt.Errorf("education: unknown interaction %q", i.Action)
	}
	occurredAt := i.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	// fmt.Sprintf is safe here because col is sourced from a closed
	// set returned by actionColumn — none of the values can include
	// SQL metacharacters.
	query := fmt.Sprintf(`
		INSERT INTO education_interactions
			(campaign_id, user_hash, %[1]s, first_seen_at, updated_at)
		VALUES ($1, $2, TRUE, $3, $3)
		ON CONFLICT (campaign_id, user_hash) DO UPDATE SET
			%[1]s     = TRUE,
			updated_at = EXCLUDED.updated_at
	`, col)
	if _, err := s.db.ExecContext(ctx, query, i.CampaignID, i.UserHash, occurredAt.UTC()); err != nil {
		return fmt.Errorf("education: append interaction: %w", err)
	}
	return nil
}

// ListByCampaign implements InteractionStore. The boolean columns are
// reconstructed into one UserInteraction per (true) action so callers
// like SimulationTracker.Aggregate can sum the counts without knowing
// the wire format.
func (s *PostgresInteractionStore) ListByCampaign(ctx context.Context, campaignID string) ([]dto.UserInteraction, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_hash, delivered, opened, clicked, submitted_creds,
		       reported, ignored, updated_at
		FROM education_interactions
		WHERE campaign_id = $1
		ORDER BY first_seen_at ASC
	`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("education: list interactions: %w", err)
	}
	defer rows.Close()

	var out []dto.UserInteraction
	for rows.Next() {
		var (
			userHash                                         string
			delivered, opened, clicked, submitted, reported, ignored bool
			updatedAt                                        sql.NullTime
		)
		if err := rows.Scan(&userHash, &delivered, &opened, &clicked,
			&submitted, &reported, &ignored, &updatedAt); err != nil {
			return nil, fmt.Errorf("education: scan interaction: %w", err)
		}
		ts := time.Time{}
		if updatedAt.Valid {
			ts = updatedAt.Time.UTC()
		}
		// Emit one UserInteraction per recorded action so the row's
		// fan-out into Aggregate's per-action counters works without
		// any callsite changes. Order mirrors the dto.UserInteraction
		// constant declaration so traces stay stable across runs.
		for _, ent := range []struct {
			flag bool
			act  dto.UserInteractionType
		}{
			{delivered, dto.InteractionDelivered},
			{opened, dto.InteractionOpened},
			{clicked, dto.InteractionClickedLink},
			{submitted, dto.InteractionSubmittedCredentials},
			{reported, dto.InteractionReportedPhishing},
			{ignored, dto.InteractionIgnored},
		} {
			if !ent.flag {
				continue
			}
			out = append(out, dto.UserInteraction{
				CampaignID: campaignID,
				UserHash:   userHash,
				Action:     ent.act,
				OccurredAt: ts,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("education: iterate interactions: %w", err)
	}
	return out, nil
}

// compile-time assertion
var _ InteractionStore = (*PostgresInteractionStore)(nil)
