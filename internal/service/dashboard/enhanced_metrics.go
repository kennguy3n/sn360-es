package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// UserThreatCount pairs a pseudonymized user hash with the number of
// threats received in a time range.
type UserThreatCount struct {
	UserHash string `json:"user_hash"`
	Count    int    `json:"count"`
}

// LatencyPercentiles holds p50/p95/p99 latency measurements in milliseconds.
type LatencyPercentiles struct {
	P50 int64 `json:"p50_ms"`
	P95 int64 `json:"p95_ms"`
	P99 int64 `json:"p99_ms"`
}

// EnhancedMetrics extends the base MetricsSource with additional
// aggregations for the improved dashboard.
type EnhancedMetrics interface {
	MetricsSource
	// ThreatsPerUser returns the top-N users by threat count.
	ThreatsPerUser(ctx context.Context, tenantID string, r dto.TimeRange, limit int) ([]UserThreatCount, error)
	// TimeToDetection returns detection latency percentiles.
	TimeToDetection(ctx context.Context, tenantID string, r dto.TimeRange) (LatencyPercentiles, error)
	// TimeToRemediation returns remediation latency percentiles.
	TimeToRemediation(ctx context.Context, tenantID string, r dto.TimeRange) (LatencyPercentiles, error)
}

// EnhancedDashboardSummary extends DashboardSummary with the new metrics.
type EnhancedDashboardSummary struct {
	dto.DashboardSummary
	TopTargetedUsers    []UserThreatCount  `json:"top_targeted_users,omitempty"`
	TimeToDetection     LatencyPercentiles `json:"time_to_detection"`
	TimeToRemediation   LatencyPercentiles `json:"time_to_remediation"`
}

// EnhancedGeneratorConfig wires the enhanced dashboard generator.
type EnhancedGeneratorConfig struct {
	Source    EnhancedMetrics
	Narrative NarrativeGenerator
	Logger    *slog.Logger
	Clock     func() time.Time
	// TopUsersLimit caps the ThreatsPerUser result set. Defaults to 10.
	TopUsersLimit int
}

// EnhancedGenerator extends DashboardGenerator with the new metrics.
type EnhancedGenerator struct {
	base      *DashboardGenerator
	esrc      EnhancedMetrics
	topLimit  int
}

// NewEnhancedGenerator constructs the enhanced generator.
func NewEnhancedGenerator(cfg EnhancedGeneratorConfig) (*EnhancedGenerator, error) {
	base, err := NewDashboardGenerator(DashboardGeneratorConfig{
		Source:    cfg.Source,
		Narrative: cfg.Narrative,
		Logger:    cfg.Logger,
		Clock:     cfg.Clock,
	})
	if err != nil {
		return nil, err
	}
	if cfg.TopUsersLimit <= 0 {
		cfg.TopUsersLimit = 10
	}
	return &EnhancedGenerator{
		base:     base,
		esrc:     cfg.Source,
		topLimit: cfg.TopUsersLimit,
	}, nil
}

// Generate produces the enhanced dashboard summary.
func (g *EnhancedGenerator) Generate(ctx context.Context, tenantID string, r dto.TimeRange) (EnhancedDashboardSummary, error) {
	baseSummary, err := g.base.GenerateSummary(ctx, tenantID, r)
	if err != nil {
		return EnhancedDashboardSummary{}, err
	}

	out := EnhancedDashboardSummary{DashboardSummary: baseSummary}

	topUsers, err := g.esrc.ThreatsPerUser(ctx, tenantID, r, g.topLimit)
	if err == nil {
		sort.Slice(topUsers, func(i, j int) bool { return topUsers[i].Count > topUsers[j].Count })
		out.TopTargetedUsers = topUsers
	}

	ttd, err := g.esrc.TimeToDetection(ctx, tenantID, r)
	if err == nil {
		out.TimeToDetection = ttd
	}

	ttr, err := g.esrc.TimeToRemediation(ctx, tenantID, r)
	if err == nil {
		out.TimeToRemediation = ttr
	}

	return out, nil
}

// ReportSchedulerConfig wires the periodic dashboard report worker.
type ReportSchedulerConfig struct {
	Generator *EnhancedGenerator
	Publisher events.EventService
	Logger    *slog.Logger
	Clock     func() time.Time
	// Interval between report generation runs. Defaults to 7 days.
	Interval time.Duration
}

// ReportScheduler generates periodic dashboard reports and publishes
// them as events.
type ReportScheduler struct {
	gen      *EnhancedGenerator
	pub      events.EventService
	log      *slog.Logger
	now      func() time.Time
	interval time.Duration
}

// NewReportScheduler constructs the scheduler.
func NewReportScheduler(cfg ReportSchedulerConfig) (*ReportScheduler, error) {
	if cfg.Generator == nil {
		return nil, fmt.Errorf("dashboard: generator is required")
	}
	if cfg.Publisher == nil {
		return nil, fmt.Errorf("dashboard: publisher is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 7 * 24 * time.Hour
	}
	return &ReportScheduler{
		gen:      cfg.Generator,
		pub:      cfg.Publisher,
		log:      cfg.Logger,
		now:      cfg.Clock,
		interval: cfg.Interval,
	}, nil
}

// GenerateAndPublish runs a single report cycle for the given tenant.
func (s *ReportScheduler) GenerateAndPublish(ctx context.Context, tenantID string) error {
	now := s.now()
	r := dto.TimeRange{
		Start: now.Add(-s.interval),
		End:   now,
	}

	summary, err := s.gen.Generate(ctx, tenantID, r)
	if err != nil {
		return fmt.Errorf("dashboard: generate: %w", err)
	}

	payload, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("dashboard: marshal: %w", err)
	}

	if err := s.pub.Publish(ctx, "es.dashboard.report.generated", payload,
		events.WithTenantID(tenantID),
		events.WithEventType("dashboard.report.generated"),
	); err != nil {
		return fmt.Errorf("dashboard: publish: %w", err)
	}

	s.log.InfoContext(ctx, "dashboard: report published",
		slog.String("tenant", tenantID),
		slog.Int("emails", summary.EmailsProcessed))

	return nil
}

// Run starts the periodic report loop. It blocks until ctx is cancelled.
func (s *ReportScheduler) Run(ctx context.Context, tenantIDs []string) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run once immediately.
	s.runAll(ctx, tenantIDs)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.runAll(ctx, tenantIDs)
		}
	}
}

func (s *ReportScheduler) runAll(ctx context.Context, tenantIDs []string) {
	for _, tid := range tenantIDs {
		if err := s.GenerateAndPublish(ctx, tid); err != nil {
			s.log.WarnContext(ctx, "dashboard: report failed",
				slog.String("tenant", tid),
				slog.Any("error", err))
		}
	}
}
