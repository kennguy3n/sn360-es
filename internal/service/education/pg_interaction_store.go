package education

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

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
// not exist and brings legacy installs up to the per-action timestamp
// schema via additive ALTERs. Mirrors PostgresCampaignStore.EnsureSchema
// so production boots cleanly even when run before the operator has
// applied a numbered Atlas migration that codifies the same DDL.
//
// Per-action timestamp columns (delivered_at, opened_at, ...) record
// when each action was first observed, mirroring the per-event
// semantics of MemoryInteractionStore. updated_at is retained as the
// row's last-touch for ORDER BY and for backfill compatibility with
// installs that pre-date the per-action columns.
func (s *PostgresInteractionStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS education_interactions (
			campaign_id        TEXT        NOT NULL,
			user_hash          TEXT        NOT NULL,
			delivered          BOOLEAN     NOT NULL DEFAULT FALSE,
			opened             BOOLEAN     NOT NULL DEFAULT FALSE,
			clicked            BOOLEAN     NOT NULL DEFAULT FALSE,
			submitted_creds    BOOLEAN     NOT NULL DEFAULT FALSE,
			reported           BOOLEAN     NOT NULL DEFAULT FALSE,
			ignored            BOOLEAN     NOT NULL DEFAULT FALSE,
			delivered_at       TIMESTAMPTZ,
			opened_at          TIMESTAMPTZ,
			clicked_at         TIMESTAMPTZ,
			submitted_creds_at TIMESTAMPTZ,
			reported_at        TIMESTAMPTZ,
			ignored_at         TIMESTAMPTZ,
			first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (campaign_id, user_hash)
		);
		CREATE INDEX IF NOT EXISTS idx_education_interactions_campaign
			ON education_interactions (campaign_id);
		-- Idempotent forward-migration for legacy installs that pre-date
		-- the per-action timestamp columns. ADD COLUMN IF NOT EXISTS
		-- keeps EnsureSchema safe to re-run on every boot.
		ALTER TABLE education_interactions
			ADD COLUMN IF NOT EXISTS delivered_at       TIMESTAMPTZ,
			ADD COLUMN IF NOT EXISTS opened_at          TIMESTAMPTZ,
			ADD COLUMN IF NOT EXISTS clicked_at         TIMESTAMPTZ,
			ADD COLUMN IF NOT EXISTS submitted_creds_at TIMESTAMPTZ,
			ADD COLUMN IF NOT EXISTS reported_at        TIMESTAMPTZ,
			ADD COLUMN IF NOT EXISTS ignored_at         TIMESTAMPTZ;
	`)
	return err
}

// actionColumns returns the boolean flag column and the per-action
// timestamp column toggled for a given interaction type. Returns two
// empty strings when the action does not map onto a discrete column
// (e.g. an unknown action — should never happen if the DTO validator
// was used).
func actionColumns(a dto.UserInteractionType) (flag, ts string) {
	switch a {
	case dto.InteractionDelivered:
		return "delivered", "delivered_at"
	case dto.InteractionOpened:
		return "opened", "opened_at"
	case dto.InteractionClickedLink:
		return "clicked", "clicked_at"
	case dto.InteractionSubmittedCredentials:
		return "submitted_creds", "submitted_creds_at"
	case dto.InteractionReportedPhishing:
		return "reported", "reported_at"
	case dto.InteractionIgnored:
		return "ignored", "ignored_at"
	}
	return "", ""
}

// Append implements InteractionStore. Each invocation is an UPSERT —
// the row is created if it does not exist, otherwise the matching
// action's flag column is flipped to TRUE and its per-action timestamp
// is set to the first observation of that action (subsequent observations
// are no-ops on the timestamp via COALESCE). updated_at is always bumped
// to the latest occurredAt. This matches the semantics expected by
// callers like SimulationTracker: recording "opened" twice for the same
// user does not produce two distinct rows, but the per-action timestamp
// preserves the moment the action first happened — which is what makes
// per-action timeline analysis possible against this schema.
func (s *PostgresInteractionStore) Append(ctx context.Context, i dto.UserInteraction) error {
	flagCol, tsCol := actionColumns(i.Action)
	if flagCol == "" {
		return fmt.Errorf("education: unknown interaction %q", i.Action)
	}
	occurredAt := i.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	// fmt.Sprintf is safe here because flagCol / tsCol are sourced from
	// a closed set returned by actionColumns — none of the values can
	// include SQL metacharacters.
	query := fmt.Sprintf(`
		INSERT INTO education_interactions
			(campaign_id, user_hash, %[1]s, %[2]s, first_seen_at, updated_at)
		VALUES ($1, $2, TRUE, $3, $3, $3)
		ON CONFLICT (campaign_id, user_hash) DO UPDATE SET
			%[1]s      = TRUE,
			%[2]s      = COALESCE(education_interactions.%[2]s, EXCLUDED.%[2]s),
			updated_at = EXCLUDED.updated_at
	`, flagCol, tsCol)
	if _, err := s.db.ExecContext(ctx, query, i.CampaignID, i.UserHash, occurredAt.UTC()); err != nil {
		return fmt.Errorf("education: append interaction: %w", err)
	}
	return nil
}

// ListByCampaign implements InteractionStore. The boolean columns are
// reconstructed into one UserInteraction per (true) action so callers
// like SimulationTracker.Aggregate can sum the counts without knowing
// the wire format. Each emitted UserInteraction carries its own
// per-action timestamp; legacy rows that pre-date the timestamp
// columns fall back to the row's updated_at so downstream code
// always gets a usable time.
func (s *PostgresInteractionStore) ListByCampaign(ctx context.Context, campaignID string) ([]dto.UserInteraction, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_hash,
		       delivered, opened, clicked, submitted_creds, reported, ignored,
		       delivered_at, opened_at, clicked_at, submitted_creds_at,
		       reported_at, ignored_at,
		       updated_at
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
			userHash                                                 string
			delivered, opened, clicked, submitted, reported, ignored bool
			deliveredAt, openedAt, clickedAt                         sql.NullTime
			submittedAt, reportedAt, ignoredAt                       sql.NullTime
			updatedAt                                                sql.NullTime
		)
		if err := rows.Scan(
			&userHash,
			&delivered, &opened, &clicked, &submitted, &reported, &ignored,
			&deliveredAt, &openedAt, &clickedAt, &submittedAt, &reportedAt, &ignoredAt,
			&updatedAt,
		); err != nil {
			return nil, fmt.Errorf("education: scan interaction: %w", err)
		}
		// Legacy fallback: rows written before the per-action
		// timestamp columns existed have NULL in every <action>_at.
		// updated_at is NOT NULL by schema, so it always provides a
		// usable time even on those legacy rows.
		fallback := time.Time{}
		if updatedAt.Valid {
			fallback = updatedAt.Time.UTC()
		}
		pick := func(col sql.NullTime) time.Time {
			if col.Valid {
				return col.Time.UTC()
			}
			return fallback
		}
		// Emit one UserInteraction per recorded action so the row's
		// fan-out into Aggregate's per-action counters works without
		// any callsite changes. Order mirrors the dto.UserInteraction
		// constant declaration so traces stay stable across runs.
		for _, ent := range []struct {
			flag bool
			act  dto.UserInteractionType
			ts   sql.NullTime
		}{
			{delivered, dto.InteractionDelivered, deliveredAt},
			{opened, dto.InteractionOpened, openedAt},
			{clicked, dto.InteractionClickedLink, clickedAt},
			{submitted, dto.InteractionSubmittedCredentials, submittedAt},
			{reported, dto.InteractionReportedPhishing, reportedAt},
			{ignored, dto.InteractionIgnored, ignoredAt},
		} {
			if !ent.flag {
				continue
			}
			out = append(out, dto.UserInteraction{
				CampaignID: campaignID,
				UserHash:   userHash,
				Action:     ent.act,
				OccurredAt: pick(ent.ts),
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("education: iterate interactions: %w", err)
	}
	return out, nil
}

// ListByCampaigns returns the fanned-out interactions for every supplied
// campaign in a single query. It is the batch fast path used by the
// analytics aggregator to avoid an N+1 over ListByCampaign. The result
// preserves the same one-row-per-action semantics as ListByCampaign;
// callers must not assume any cross-campaign ordering beyond the
// per-campaign first_seen_at ordering.
func (s *PostgresInteractionStore) ListByCampaigns(ctx context.Context, campaignIDs []string) ([]dto.UserInteraction, error) {
	if len(campaignIDs) == 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT campaign_id, user_hash,
		       delivered, opened, clicked, submitted_creds, reported, ignored,
		       delivered_at, opened_at, clicked_at, submitted_creds_at,
		       reported_at, ignored_at,
		       updated_at
		FROM education_interactions
		WHERE campaign_id = ANY($1)
		ORDER BY campaign_id ASC, first_seen_at ASC
	`, pq.Array(campaignIDs))
	if err != nil {
		return nil, fmt.Errorf("education: list interactions (batch): %w", err)
	}
	defer rows.Close()

	var out []dto.UserInteraction
	for rows.Next() {
		var (
			campaignID, userHash                                     string
			delivered, opened, clicked, submitted, reported, ignored bool
			deliveredAt, openedAt, clickedAt                         sql.NullTime
			submittedAt, reportedAt, ignoredAt                       sql.NullTime
			updatedAt                                                sql.NullTime
		)
		if err := rows.Scan(
			&campaignID, &userHash,
			&delivered, &opened, &clicked, &submitted, &reported, &ignored,
			&deliveredAt, &openedAt, &clickedAt, &submittedAt, &reportedAt, &ignoredAt,
			&updatedAt,
		); err != nil {
			return nil, fmt.Errorf("education: scan interaction (batch): %w", err)
		}
		fallback := time.Time{}
		if updatedAt.Valid {
			fallback = updatedAt.Time.UTC()
		}
		pick := func(col sql.NullTime) time.Time {
			if col.Valid {
				return col.Time.UTC()
			}
			return fallback
		}
		for _, ent := range []struct {
			flag bool
			act  dto.UserInteractionType
			ts   sql.NullTime
		}{
			{delivered, dto.InteractionDelivered, deliveredAt},
			{opened, dto.InteractionOpened, openedAt},
			{clicked, dto.InteractionClickedLink, clickedAt},
			{submitted, dto.InteractionSubmittedCredentials, submittedAt},
			{reported, dto.InteractionReportedPhishing, reportedAt},
			{ignored, dto.InteractionIgnored, ignoredAt},
		} {
			if !ent.flag {
				continue
			}
			out = append(out, dto.UserInteraction{
				CampaignID: campaignID,
				UserHash:   userHash,
				Action:     ent.act,
				OccurredAt: pick(ent.ts),
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("education: iterate interactions (batch): %w", err)
	}
	return out, nil
}

// compile-time assertion
var _ InteractionStore = (*PostgresInteractionStore)(nil)
