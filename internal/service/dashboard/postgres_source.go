package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// FeedbackCountsReader returns aggregate per-action feedback counts
// from whatever store the repository layer is wired against. The
// dashboard package depends on this minimal contract (not on the full
// repository.FeedbackEventRepository) so unit tests can supply a fake.
type FeedbackCountsReader interface {
	Counts(ctx context.Context, tenantID string, start, end time.Time) (FeedbackCounts, error)
}

// FeedbackCounts mirrors repository.FeedbackCounts. Defined locally so
// the dashboard package does not import the repository package.
type FeedbackCounts struct {
	ReportedPhishing int
	MarkedSafe       int
	TrustedSender    int
}

// pgQuerier is the subset of pkg/storage/postgres.DB this package
// needs. Defined locally so tests can pass a *sql.DB / *sql.Tx
// directly without pulling in the wrapper.
type pgQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// PostgresSource is a MetricsSource backed by the management
// Postgres schema (migrations/*.up.sql). It runs SQL aggregates
// against the evaluation_results, simulation_results,
// escalation_tickets, and feedback_events tables — the dashboard
// endpoint reads through here so the same aggregations are available
// regardless of caller (HTTP handler, batch job, internal admin
// tool).
//
// Feedback counters are sourced from the feedback_events table
// (migration 0002); false-rate counters use the structured
// resolution_code column on escalation_tickets (migration 0003)
// rather than ILIKE pattern matching against free-form text.
type PostgresSource struct {
	db       pgQuerier
	feedback FeedbackCountsReader
}

// PostgresSourceConfig wires the optional dependencies. When
// Feedback is nil, PostgresSource.Feedback() falls back to a direct
// query against feedback_events using the supplied pgQuerier.
type PostgresSourceConfig struct {
	Feedback FeedbackCountsReader
}

// NewPostgresSource constructs a MetricsSource backed by the given
// querier (typically a *postgres.DB).
func NewPostgresSource(db pgQuerier) (*PostgresSource, error) {
	return NewPostgresSourceWithConfig(db, PostgresSourceConfig{})
}

// NewPostgresSourceWithConfig is the explicit constructor used when
// a custom feedback reader (e.g. an in-memory fake in tests or a
// repository-backed adapter in main.go) should override the default
// direct-query path.
func NewPostgresSourceWithConfig(db pgQuerier, cfg PostgresSourceConfig) (*PostgresSource, error) {
	if db == nil {
		return nil, errors.New("dashboard: postgres source requires a non-nil querier")
	}
	return &PostgresSource{db: db, feedback: cfg.Feedback}, nil
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

// Feedback aggregates rows from the feedback_events table (migration
// 0002) keyed by tenant and time window. Each verified banner click
// (`report_phishing`, `mark_safe`, `trust_sender`) becomes a row in
// feedback_events; the dashboard surfaces the per-action totals.
//
// When a FeedbackCountsReader is configured (the production path
// when main.go wires the repository) the call is delegated to it;
// otherwise PostgresSource issues the aggregate query directly.
func (s *PostgresSource) Feedback(ctx context.Context, tenantID string, r dto.TimeRange) (dto.FeedbackStats, error) {
	start, end := r.Start.UTC(), r.End.UTC()
	if s.feedback != nil {
		counts, err := s.feedback.Counts(ctx, tenantID, start, end)
		if err != nil {
			return dto.FeedbackStats{}, fmt.Errorf("dashboard: feedback: %w", err)
		}
		return dto.FeedbackStats{
			ReportedPhishing: counts.ReportedPhishing,
			MarkedSafe:       counts.MarkedSafe,
			TrustedSender:    counts.TrustedSender,
		}, nil
	}
	const q = `
        SELECT
            COUNT(*) FILTER (WHERE action = 'report_phishing') AS reported,
            COUNT(*) FILTER (WHERE action = 'mark_safe')       AS marked,
            COUNT(*) FILTER (WHERE action = 'trust_sender')    AS trusted
          FROM feedback_events
         WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3
    `
	var (
		reported, marked, trusted int
	)
	if err := s.db.QueryRowContext(ctx, q, tenantID, start, end).
		Scan(&reported, &marked, &trusted); err != nil {
		return dto.FeedbackStats{}, fmt.Errorf("dashboard: feedback: %w", err)
	}
	return dto.FeedbackStats{
		ReportedPhishing: reported,
		MarkedSafe:       marked,
		TrustedSender:    trusted,
	}, nil
}

// Quarantine counts evaluation_results rows that match the canonical
// quarantine tier. The architecture (PROPOSAL.md §3) only
// auto-quarantines at Blocked — HighRisk surfaces a warning banner
// but does NOT pull the message — so this filter is intentionally
// "Blocked" only. Released / false-quarantine counts are zero;
// they require a dedicated quarantine_actions table the v1 schema
// does not yet have.
func (s *PostgresSource) Quarantine(ctx context.Context, tenantID string, r dto.TimeRange) (dto.QuarantineStats, error) {
	const q = `
        SELECT COUNT(*)
        FROM evaluation_results
        WHERE tenant_id = $1 AND evaluated_at >= $2 AND evaluated_at < $3
              AND tier = 'Blocked'
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
// fp / fn rates within the window. SecOps mark a ticket with the
// structured resolution_code column (migration 0003):
//
//   - false_positive    → counted as a false positive
//   - confirmed_phishing→ counted as a false negative (the original
//     verdict missed a real phish)
//   - requires_hunting,
//     closed_no_action  → ignored
//
// We deliberately scope the filter to the structured enum so a
// resolution_notes string containing "false_positive" no longer
// inflates the counters.
func (s *PostgresSource) FalseRates(ctx context.Context, tenantID string, r dto.TimeRange) (int, int, error) {
	const q = `
        SELECT
            COUNT(*) FILTER (WHERE resolution_code = 'false_positive')     AS fp,
            COUNT(*) FILTER (WHERE resolution_code = 'confirmed_phishing') AS fn
        FROM escalation_tickets
        WHERE tenant_id = $1 AND resolved_at IS NOT NULL
              AND resolved_at >= $2 AND resolved_at < $3
              AND resolution_code IS NOT NULL
    `
	var fp, fn int
	if err := s.db.QueryRowContext(ctx, q, tenantID, r.Start.UTC(), r.End.UTC()).Scan(&fp, &fn); err != nil {
		return 0, 0, fmt.Errorf("dashboard: false_rates: %w", err)
	}
	return fp, fn, nil
}
