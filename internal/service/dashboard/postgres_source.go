package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// pgQuerier is the subset of pkg/storage/postgres.DB this package
// needs. Defined locally so tests can pass a *sql.DB / *sql.Tx
// directly without pulling in the wrapper.
type pgQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// PostgresSource is a MetricsSource backed by the management
// Postgres schema (migrations/0001_init.up.sql). It runs SQL
// aggregates against the evaluation_results, simulation_results, and
// escalation_tickets tables — the dashboard endpoint reads through
// here so the same aggregations are available regardless of
// caller (HTTP handler, batch job, internal admin tool).
//
// Feedback / quarantine / false-rate counters do not yet have a
// dedicated table in the v1 schema, so PostgresSource derives them
// from evaluation_results and escalation_tickets where possible and
// returns deterministic zero values for the unmapped fields. The
// dto.DashboardSummary fields are still populated so the JSON shape
// is stable.
type PostgresSource struct {
	db pgQuerier
}

// NewPostgresSource constructs a MetricsSource backed by the given
// querier (typically a *postgres.DB).
func NewPostgresSource(db pgQuerier) (*PostgresSource, error) {
	if db == nil {
		return nil, errors.New("dashboard: postgres source requires a non-nil querier")
	}
	return &PostgresSource{db: db}, nil
}

// EmailsProcessed counts evaluation_results rows in the window.
func (s *PostgresSource) EmailsProcessed(ctx context.Context, tenantID string, r dto.TimeRange) (int, error) {
	const q = `
        SELECT COUNT(*) FROM evaluation_results
        WHERE tenant_id = $1 AND evaluated_at >= $2 AND evaluated_at < $3
    `
	var n int
	if err := s.db.QueryRowContext(ctx, q, tenantID, r.Start.UTC(), r.End.UTC()).Scan(&n); err != nil {
		return 0, fmt.Errorf("dashboard: emails_processed: %w", err)
	}
	return n, nil
}

// ThreatsByTier groups evaluation_results by tier in the window.
// Rows with empty tier strings are excluded so the dashboard does
// not surface "uncategorised" buckets.
func (s *PostgresSource) ThreatsByTier(ctx context.Context, tenantID string, r dto.TimeRange) ([]dto.TierCount, error) {
	const q = `
        SELECT tier, COUNT(*)
        FROM evaluation_results
        WHERE tenant_id = $1 AND evaluated_at >= $2 AND evaluated_at < $3
              AND tier <> ''
        GROUP BY tier
    `
	rows, err := s.db.QueryContext(ctx, q, tenantID, r.Start.UTC(), r.End.UTC())
	if err != nil {
		return nil, fmt.Errorf("dashboard: threats_by_tier: %w", err)
	}
	defer rows.Close()

	out := make([]dto.TierCount, 0, 6)
	for rows.Next() {
		var tier string
		var count int
		if err := rows.Scan(&tier, &count); err != nil {
			return nil, fmt.Errorf("dashboard: threats_by_tier scan: %w", err)
		}
		out = append(out, dto.TierCount{Tier: tier, Count: count})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dashboard: threats_by_tier rows: %w", err)
	}
	return out, nil
}

// ThreatsByCategory groups evaluation_results by primary_category in
// the window, excluding the empty (no-threat) bucket.
func (s *PostgresSource) ThreatsByCategory(ctx context.Context, tenantID string, r dto.TimeRange) ([]dto.CategoryCount, error) {
	const q = `
        SELECT primary_category, COUNT(*)
        FROM evaluation_results
        WHERE tenant_id = $1 AND evaluated_at >= $2 AND evaluated_at < $3
              AND primary_category IS NOT NULL
              AND primary_category <> ''
        GROUP BY primary_category
    `
	rows, err := s.db.QueryContext(ctx, q, tenantID, r.Start.UTC(), r.End.UTC())
	if err != nil {
		return nil, fmt.Errorf("dashboard: threats_by_category: %w", err)
	}
	defer rows.Close()

	out := make([]dto.CategoryCount, 0, 16)
	for rows.Next() {
		var cat sql.NullString
		var count int
		if err := rows.Scan(&cat, &count); err != nil {
			return nil, fmt.Errorf("dashboard: threats_by_category scan: %w", err)
		}
		if !cat.Valid || strings.TrimSpace(cat.String) == "" {
			continue
		}
		out = append(out, dto.CategoryCount{Category: cat.String, Count: count})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dashboard: threats_by_category rows: %w", err)
	}
	return out, nil
}

// Feedback returns zero-valued FeedbackStats — the v1 schema has no
// dedicated feedback table, so reported / false_positive / false_negative
// counts are not yet aggregable from Postgres. The fields remain in
// the response shape so add-in clients can rely on a stable JSON
// contract.
func (s *PostgresSource) Feedback(ctx context.Context, tenantID string, r dto.TimeRange) (dto.FeedbackStats, error) {
	if ctx.Err() != nil {
		return dto.FeedbackStats{}, ctx.Err()
	}
	return dto.FeedbackStats{}, nil
}

// Quarantine counts evaluation_results rows in the Quarantine tier
// (canonical constant.TierBlocked equivalent at the storage layer
// uses the raw string written by evaluateResultRow). Released /
// false-quarantine counts are zero — they require a dedicated
// quarantine_actions table the schema does not yet have.
func (s *PostgresSource) Quarantine(ctx context.Context, tenantID string, r dto.TimeRange) (dto.QuarantineStats, error) {
	const q = `
        SELECT COUNT(*)
        FROM evaluation_results
        WHERE tenant_id = $1 AND evaluated_at >= $2 AND evaluated_at < $3
              AND tier IN ('Blocked', 'Quarantine', 'HighRisk')
    `
	var n int
	if err := s.db.QueryRowContext(ctx, q, tenantID, r.Start.UTC(), r.End.UTC()).Scan(&n); err != nil {
		return dto.QuarantineStats{}, fmt.Errorf("dashboard: quarantine: %w", err)
	}
	return dto.QuarantineStats{Quarantined: n}, nil
}

// Simulation aggregates simulation_results for the tenant. "Sent"
// counts rows with a non-null delivered_at (the canonical "this user
// received the simulation" signal); the other fields map straight to
// the per-target booleans tracked by the simulation tracker. The
// "opened" column on the table is not surfaced because the
// dto.SimulationStats shape does not carry it.
func (s *PostgresSource) Simulation(ctx context.Context, tenantID string, r dto.TimeRange) (dto.SimulationStats, error) {
	const q = `
        SELECT
            COUNT(*) FILTER (WHERE delivered_at IS NOT NULL)             AS sent,
            COUNT(*) FILTER (WHERE clicked)                              AS clicked,
            COUNT(*) FILTER (WHERE submitted_creds)                      AS submitted,
            COUNT(*) FILTER (WHERE reported)                             AS reported,
            COUNT(*) FILTER (WHERE ignored)                              AS ignored
        FROM simulation_results
        WHERE tenant_id = $1 AND updated_at >= $2 AND updated_at < $3
    `
	var (
		sent, clicked, submitted, reported, ignored int
	)
	if err := s.db.QueryRowContext(ctx, q, tenantID, r.Start.UTC(), r.End.UTC()).
		Scan(&sent, &clicked, &submitted, &reported, &ignored); err != nil {
		return dto.SimulationStats{}, fmt.Errorf("dashboard: simulation: %w", err)
	}
	return dto.SimulationStats{
		Sent:                 sent,
		Clicked:              clicked,
		SubmittedCredentials: submitted,
		Reported:             reported,
		Ignored:              ignored,
	}, nil
}

// FalseRates aggregates escalation_tickets resolutions to estimate
// fp / fn rates within the window. Tickets resolved with a
// resolution of "false_positive" or "false_negative" feed the
// counters; everything else is ignored. When the v1 schema does not
// carry a structured resolution code yet, this returns 0 / 0 for
// both rates.
func (s *PostgresSource) FalseRates(ctx context.Context, tenantID string, r dto.TimeRange) (int, int, error) {
	const q = `
        SELECT
            COUNT(*) FILTER (WHERE resolution ILIKE '%false_positive%') AS fp,
            COUNT(*) FILTER (WHERE resolution ILIKE '%false_negative%') AS fn
        FROM escalation_tickets
        WHERE tenant_id = $1 AND resolved_at IS NOT NULL
              AND resolved_at >= $2 AND resolved_at < $3
    `
	var fp, fn int
	if err := s.db.QueryRowContext(ctx, q, tenantID, r.Start.UTC(), r.End.UTC()).Scan(&fp, &fn); err != nil {
		return 0, 0, fmt.Errorf("dashboard: false_rates: %w", err)
	}
	return fp, fn, nil
}
