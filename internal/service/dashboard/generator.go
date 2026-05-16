// Package dashboard generates the per-tenant security dashboard
// (PROPOSAL.md §8). It produces both structured aggregates and an
// AI-written narrative so admins can read a one-paragraph summary of
// the past 7 days without scrolling through charts.
package dashboard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// MetricsSource is the read-side dependency of the generator. It is
// expected to be backed by the management service's Postgres + Redis;
// tests use a fake that returns fixed slices.
type MetricsSource interface {
	EmailsProcessed(ctx context.Context, tenantID string, r dto.TimeRange) (int, error)
	ThreatsByTier(ctx context.Context, tenantID string, r dto.TimeRange) ([]dto.TierCount, error)
	ThreatsByCategory(ctx context.Context, tenantID string, r dto.TimeRange) ([]dto.CategoryCount, error)
	Feedback(ctx context.Context, tenantID string, r dto.TimeRange) (dto.FeedbackStats, error)
	Quarantine(ctx context.Context, tenantID string, r dto.TimeRange) (dto.QuarantineStats, error)
	Simulation(ctx context.Context, tenantID string, r dto.TimeRange) (dto.SimulationStats, error)
	FalseRates(ctx context.Context, tenantID string, r dto.TimeRange) (fp int, fn int, err error)
}

// NarrativeGenerator produces a human-readable summary from the
// aggregated metrics. In production this is wired to the AI Support
// agent's narrative function; tests use a deterministic fake.
type NarrativeGenerator interface {
	Generate(ctx context.Context, summary dto.DashboardSummary) (string, error)
}

// DashboardGeneratorConfig wires the generator.
type DashboardGeneratorConfig struct {
	Source    MetricsSource
	Narrative NarrativeGenerator
	Logger    *slog.Logger
	Clock     func() time.Time
}

// DashboardGenerator orchestrates the aggregation calls and folds them
// into a DashboardSummary.
type DashboardGenerator struct {
	src       MetricsSource
	narrative NarrativeGenerator
	log       *slog.Logger
	now       func() time.Time
}

// NewDashboardGenerator constructs the generator.
func NewDashboardGenerator(cfg DashboardGeneratorConfig) (*DashboardGenerator, error) {
	if cfg.Source == nil {
		return nil, errors.New("dashboard: source is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &DashboardGenerator{
		src:       cfg.Source,
		narrative: cfg.Narrative,
		log:       cfg.Logger,
		now:       cfg.Clock,
	}, nil
}

// GenerateSummary runs all read-side queries in series and returns the
// aggregated summary. The Narrative field is populated when a generator
// is wired and non-error.
func (g *DashboardGenerator) GenerateSummary(ctx context.Context, tenantID string, r dto.TimeRange) (dto.DashboardSummary, error) {
	if tenantID == "" {
		return dto.DashboardSummary{}, errors.New("dashboard: tenant_id is required")
	}
	if r.End.IsZero() {
		r.End = g.now()
	}
	if r.Start.IsZero() {
		r.Start = r.End.Add(-7 * 24 * time.Hour)
	}
	if !r.End.After(r.Start) {
		return dto.DashboardSummary{}, errors.New("dashboard: range end must be after start")
	}

	emails, err := g.src.EmailsProcessed(ctx, tenantID, r)
	if err != nil {
		return dto.DashboardSummary{}, fmt.Errorf("dashboard: emails_processed: %w", err)
	}
	tiers, err := g.src.ThreatsByTier(ctx, tenantID, r)
	if err != nil {
		return dto.DashboardSummary{}, fmt.Errorf("dashboard: threats_by_tier: %w", err)
	}
	cats, err := g.src.ThreatsByCategory(ctx, tenantID, r)
	if err != nil {
		return dto.DashboardSummary{}, fmt.Errorf("dashboard: threats_by_category: %w", err)
	}
	feedback, err := g.src.Feedback(ctx, tenantID, r)
	if err != nil {
		return dto.DashboardSummary{}, fmt.Errorf("dashboard: feedback: %w", err)
	}
	quar, err := g.src.Quarantine(ctx, tenantID, r)
	if err != nil {
		return dto.DashboardSummary{}, fmt.Errorf("dashboard: quarantine: %w", err)
	}
	sim, err := g.src.Simulation(ctx, tenantID, r)
	if err != nil {
		return dto.DashboardSummary{}, fmt.Errorf("dashboard: simulation: %w", err)
	}
	fp, fn, err := g.src.FalseRates(ctx, tenantID, r)
	if err != nil {
		return dto.DashboardSummary{}, fmt.Errorf("dashboard: false_rates: %w", err)
	}

	sort.Slice(tiers, func(i, j int) bool { return tiers[i].Count > tiers[j].Count })
	sort.Slice(cats, func(i, j int) bool { return cats[i].Count > cats[j].Count })

	out := dto.DashboardSummary{
		TenantID:        tenantID,
		Range:           r,
		EmailsProcessed: emails,
		ThreatsByTier:   tiers,
		ThreatsByCat:    cats,
		FalsePositive:   fp,
		FalseNegative:   fn,
		Feedback:        feedback,
		Quarantine:      quar,
		Simulation:      sim,
		GeneratedAt:     g.now(),
	}
	if g.narrative != nil {
		text, err := g.narrative.Generate(ctx, out)
		if err != nil {
			g.log.WarnContext(ctx, "dashboard: narrative failed", slog.Any("error", err))
		} else {
			out.Narrative = strings.TrimSpace(text)
		}
	} else {
		out.Narrative = DeterministicNarrative(out)
	}
	return out, nil
}

// GenerateNarrative is a convenience that re-runs only the narrative
// step against an existing summary.
func (g *DashboardGenerator) GenerateNarrative(ctx context.Context, s dto.DashboardSummary) (string, error) {
	if g.narrative == nil {
		return DeterministicNarrative(s), nil
	}
	return g.narrative.Generate(ctx, s)
}

// DeterministicNarrative is the fallback narrative used when no AI
// generator is wired. It produces a deterministic, audit-friendly
// summary of the supplied metrics — useful for tests and for tenants
// who don't want LLM-generated copy.
func DeterministicNarrative(s dto.DashboardSummary) string {
	if s.EmailsProcessed == 0 {
		return "SN360 processed no email traffic in this window. No threats observed."
	}
	// "Threats" = anything at Warning severity or worse. The threshold
	// is expressed in terms of constant.Tier.Severity() so that adding
	// a new tier between Warning and HighRisk later automatically
	// rolls into this count without touching this code. canonicalTier
	// folds the lowercase / snake_case variants that tests and add-in
	// payloads sometimes emit back to the canonical PascalCase form.
	threshold := constant.TierWarning.Severity()
	threats := 0
	for _, t := range s.ThreatsByTier {
		tier := canonicalTier(t.Tier)
		if tier == "" {
			continue
		}
		if tier.Severity() >= threshold {
			threats += t.Count
		}
	}
	topCat := "n/a"
	if len(s.ThreatsByCat) > 0 {
		topCat = s.ThreatsByCat[0].Category
	}
	return fmt.Sprintf(
		"In the last %d hours SN360 processed %d messages, flagged %d as Warning+, and quarantined %d. Top threat category: %s. Users reported %d phishing attempts; %d false positives and %d false negatives were corrected.",
		int(s.Range.End.Sub(s.Range.Start).Hours()),
		s.EmailsProcessed,
		threats,
		s.Quarantine.Quarantined,
		topCat,
		s.Feedback.ReportedPhishing,
		s.FalsePositive,
		s.FalseNegative,
	)
}

// canonicalTier maps a free-form tier string back to its constant.Tier
// equivalent. It accepts the canonical PascalCase form ("HighRisk")
// emitted by the production MetricsSource as well as the lowercase /
// snake_case variants ("high_risk", "highrisk") used in tests and
// add-in payloads. Returns "" if the input doesn't match any known
// tier so callers can decide how to handle unknown tiers (the
// dashboard treats them as "not a threat" rather than guessing).
func canonicalTier(raw string) constant.Tier {
	norm := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "_", "")
	if norm == "" {
		return ""
	}
	for _, t := range constant.AllTiers {
		if strings.ToLower(string(t)) == norm {
			return t
		}
	}
	return ""
}
