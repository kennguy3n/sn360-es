package education

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// AnalyticsService computes the per-tenant training-programme analytics
// that back GET /v1/education/analytics. It is a read-only aggregator:
// it owns no state, fans out to the campaign + interaction stores for a
// single tenant, and folds the results into a dto.EducationAnalytics.
//
// Tenant isolation: the service only ever reads interactions for
// campaign IDs it first obtained from CampaignStore.ListCampaigns(tenant)
// — it never queries the interaction store by an arbitrary, caller-
// supplied campaign ID. Combined with Postgres RLS on
// education_campaigns (which scopes ListCampaigns to the bound tenant),
// a tenant can never observe another tenant's interactions even though
// education_interactions itself is keyed only by campaign_id.
type AnalyticsService struct {
	campaigns    CampaignStore
	interactions InteractionStore
	scorer       *ResilienceScorer
	templates    *TemplateLibrary
	now          func() time.Time
	log          *slog.Logger
}

// AnalyticsConfig wires the AnalyticsService. Campaigns, Interactions
// and Templates are required; Scorer is optional (when nil the
// resilience_trend series is returned empty rather than failing the
// whole request).
type AnalyticsConfig struct {
	Campaigns    CampaignStore
	Interactions InteractionStore
	Templates    *TemplateLibrary
	Scorer       *ResilienceScorer
	Logger       *slog.Logger
	Clock        func() time.Time
}

// batchInteractionLister is an OPTIONAL fast path on an InteractionStore
// that can return interactions for many campaigns in a single round
// trip. PostgresInteractionStore implements it with one
// `WHERE campaign_id = ANY($1)` query, eliminating the N+1 that a naive
// per-campaign loop would incur for a tenant with many campaigns. Stores
// that don't implement it fall back to ListByCampaign per campaign.
type batchInteractionLister interface {
	ListByCampaigns(ctx context.Context, campaignIDs []string) ([]dto.UserInteraction, error)
}

// topClickedLimit caps how many template rows the top_clicked_templates
// series returns. The full distribution is rarely useful to a dashboard;
// the long tail is dropped after sorting.
const topClickedLimit = 10

// maxTrendBuckets bounds the resilience_trend series length so a very
// long range can't produce an unbounded payload. 90d at weekly
// granularity is ~13 points; the cap only bites on pathological ranges.
const maxTrendBuckets = 26

// NewAnalyticsService constructs the service. It returns an error when a
// required dependency is missing so a misconfigured wiring fails loudly
// at boot rather than serving empty analytics.
func NewAnalyticsService(cfg AnalyticsConfig) (*AnalyticsService, error) {
	if cfg.Campaigns == nil {
		return nil, errors.New("education: analytics requires Campaigns store")
	}
	if cfg.Interactions == nil {
		return nil, errors.New("education: analytics requires Interactions store")
	}
	if cfg.Templates == nil {
		return nil, errors.New("education: analytics requires Templates library")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &AnalyticsService{
		campaigns:    cfg.Campaigns,
		interactions: cfg.Interactions,
		scorer:       cfg.Scorer,
		templates:    cfg.Templates,
		now:          cfg.Clock,
		log:          cfg.Logger,
	}, nil
}

// campaignAgg holds the distinct-user sets derived from a single
// campaign's interactions. Each set is keyed by user_hash so a user is
// counted at most once per outcome regardless of replayed events.
type campaignAgg struct {
	campaign dto.Campaign
	attack   dto.AttackType
	reg      dto.RegulatoryCategory

	reached   map[string]struct{} // any interaction observed
	delivered map[string]struct{} // delivered
	clicked   map[string]struct{} // clicked_link OR submitted_credentials
	decided   map[string]struct{} // clicked / submitted / reported / ignored
}

// userAgg accumulates, per user, the earliest time each resilience-
// relevant outcome was observed for each campaign. The trend folds
// these into time-bucketed ResilienceSignals.
type userAgg struct {
	sent     map[string]time.Time // campaign_id -> first interaction
	detected map[string]time.Time // campaign_id -> first report/ignore
	incident map[string]time.Time // campaign_id -> first click/submit
}

func newUserAgg() *userAgg {
	return &userAgg{
		sent:     map[string]time.Time{},
		detected: map[string]time.Time{},
		incident: map[string]time.Time{},
	}
}

// ComputeAnalytics aggregates every analytics dimension for a tenant
// over the supplied range. The range is normalised: a zero End defaults
// to now, a zero Start defaults to End-90d, and End must be after Start.
func (s *AnalyticsService) ComputeAnalytics(ctx context.Context, tenantID string, r dto.TimeRange) (dto.EducationAnalytics, error) {
	if tenantID == "" {
		return dto.EducationAnalytics{}, errors.New("education: tenant_id is required")
	}
	if r.End.IsZero() {
		r.End = s.now()
	}
	if r.Start.IsZero() {
		r.Start = r.End.Add(-90 * 24 * time.Hour)
	}
	r.Start = r.Start.UTC()
	r.End = r.End.UTC()
	if !r.End.After(r.Start) {
		return dto.EducationAnalytics{}, errors.New("education: range end must be after start")
	}

	campaigns, err := s.campaigns.ListCampaigns(ctx, tenantID)
	if err != nil {
		return dto.EducationAnalytics{}, fmt.Errorf("education: list campaigns: %w", err)
	}

	// Keep only campaigns whose reference time falls inside the window.
	inWindow := make([]dto.Campaign, 0, len(campaigns))
	for _, c := range campaigns {
		ts := campaignRefTime(c)
		if !ts.Before(r.Start) && ts.Before(r.End) {
			inWindow = append(inWindow, c)
		}
	}

	out := dto.EducationAnalytics{
		TenantID:                tenantID,
		Range:                   r,
		CampaignCompletionRates: []dto.DatedRate{},
		ClickRatesByAttackType:  []dto.AttackTypeClickRate{},
		ClickRatesByDifficulty:  []dto.DifficultyClickRate{},
		ResilienceTrend:         []dto.DatedScore{},
		TopClickedTemplates:     []dto.TemplateClickCount{},
		RegulatoryCompletion:    map[string]float64{},
		GeneratedAt:             s.now(),
	}
	// Always report a row per known regulatory regime, even at 0, so the
	// dashboard layout is stable across tenants.
	for _, cat := range dto.AllRegulatoryCategories {
		out.RegulatoryCompletion[string(cat)] = 0
	}
	if len(inWindow) == 0 {
		return out, nil
	}

	ids := make([]string, len(inWindow))
	for i, c := range inWindow {
		ids[i] = c.CampaignID
	}
	byCampaign, err := s.loadInteractions(ctx, ids)
	if err != nil {
		return dto.EducationAnalytics{}, err
	}

	aggs := make([]campaignAgg, 0, len(inWindow))
	users := map[string]*userAgg{}
	for _, c := range inWindow {
		agg := s.aggregateCampaign(c, byCampaign[c.CampaignID], users)
		aggs = append(aggs, agg)
	}

	out.CampaignCompletionRates = completionRatesByDate(aggs)
	out.ClickRatesByAttackType = clickRatesByAttackType(aggs)
	out.ClickRatesByDifficulty = clickRatesByDifficulty(aggs)
	out.TopClickedTemplates = topClickedTemplates(aggs)
	out.RegulatoryCompletion = regulatoryCompletion(aggs)
	out.ResilienceTrend = s.resilienceTrend(ctx, tenantID, users, r)

	return out, nil
}

// loadInteractions returns interactions grouped by campaign id, using
// the batch fast path when the store supports it.
func (s *AnalyticsService) loadInteractions(ctx context.Context, ids []string) (map[string][]dto.UserInteraction, error) {
	out := make(map[string][]dto.UserInteraction, len(ids))
	if batch, ok := s.interactions.(batchInteractionLister); ok {
		all, err := batch.ListByCampaigns(ctx, ids)
		if err != nil {
			return nil, fmt.Errorf("education: list interactions (batch): %w", err)
		}
		for _, i := range all {
			out[i.CampaignID] = append(out[i.CampaignID], i)
		}
		return out, nil
	}
	for _, id := range ids {
		items, err := s.interactions.ListByCampaign(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("education: list interactions for %s: %w", id, err)
		}
		out[id] = items
	}
	return out, nil
}

// aggregateCampaign folds one campaign's interactions into a campaignAgg
// and updates the cross-campaign per-user accumulator used by the trend.
func (s *AnalyticsService) aggregateCampaign(c dto.Campaign, items []dto.UserInteraction, users map[string]*userAgg) campaignAgg {
	agg := campaignAgg{
		campaign:  c,
		attack:    s.attackTypeOf(c.TemplateID),
		reg:       s.regulatoryOf(c.TemplateID),
		reached:   map[string]struct{}{},
		delivered: map[string]struct{}{},
		clicked:   map[string]struct{}{},
		decided:   map[string]struct{}{},
	}
	for _, i := range items {
		agg.reached[i.UserHash] = struct{}{}
		ua := users[i.UserHash]
		if ua == nil {
			ua = newUserAgg()
			users[i.UserHash] = ua
		}
		setEarliest(ua.sent, c.CampaignID, i.OccurredAt)

		switch i.Action {
		case dto.InteractionDelivered:
			agg.delivered[i.UserHash] = struct{}{}
		case dto.InteractionClickedLink, dto.InteractionSubmittedCredentials:
			agg.clicked[i.UserHash] = struct{}{}
			agg.decided[i.UserHash] = struct{}{}
			setEarliest(ua.incident, c.CampaignID, i.OccurredAt)
		case dto.InteractionReportedPhishing, dto.InteractionIgnored:
			agg.decided[i.UserHash] = struct{}{}
			setEarliest(ua.detected, c.CampaignID, i.OccurredAt)
		case dto.InteractionOpened:
			// Opening alone is neither a decision nor an incident.
		}
	}
	return agg
}

// reachedDenominator returns the population a rate is taken over:
// delivered users when the campaign recorded deliveries, otherwise the
// set of users who interacted at all. This keeps rates well-defined when
// a backend only persists engagement events.
func (a campaignAgg) reachedDenominator() int {
	if len(a.delivered) > 0 {
		return len(a.delivered)
	}
	return len(a.reached)
}

// completionRatesByDate groups campaigns by their reference calendar
// date and averages each day's per-campaign completion rate. A
// campaign's completion rate is the fraction of its target population
// that reached a decision (reported, ignored, clicked, or submitted)
// rather than leaving the simulation untouched.
func completionRatesByDate(aggs []campaignAgg) []dto.DatedRate {
	type acc struct {
		sum float64
		n   int
	}
	byDate := map[string]*acc{}
	for _, a := range aggs {
		denom := a.campaign.TargetCount
		if denom <= 0 {
			denom = a.reachedDenominator()
		}
		var rate float64
		if denom > 0 {
			rate = float64(len(a.decided)) / float64(denom)
		}
		rate = clampUnit(rate)
		key := campaignRefTime(a.campaign).Format("2006-01-02")
		e := byDate[key]
		if e == nil {
			e = &acc{}
			byDate[key] = e
		}
		e.sum += rate
		e.n++
	}
	out := make([]dto.DatedRate, 0, len(byDate))
	for date, e := range byDate {
		out = append(out, dto.DatedRate{Date: date, Rate: round4(e.sum / float64(e.n))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date < out[j].Date })
	return out
}

// clickRatesByAttackType aggregates clicks / reached across all
// campaigns sharing an attack type.
func clickRatesByAttackType(aggs []campaignAgg) []dto.AttackTypeClickRate {
	type acc struct{ clicked, reached int }
	byType := map[dto.AttackType]*acc{}
	for _, a := range aggs {
		if a.attack == "" {
			continue
		}
		e := byType[a.attack]
		if e == nil {
			e = &acc{}
			byType[a.attack] = e
		}
		e.clicked += len(a.clicked)
		e.reached += a.reachedDenominator()
	}
	out := make([]dto.AttackTypeClickRate, 0, len(byType))
	for at, e := range byType {
		var rate float64
		if e.reached > 0 {
			rate = float64(e.clicked) / float64(e.reached)
		}
		out = append(out, dto.AttackTypeClickRate{AttackType: at, ClickRate: round4(clampUnit(rate))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AttackType < out[j].AttackType })
	return out
}

// clickRatesByDifficulty aggregates clicks / reached across all
// campaigns sharing a difficulty band.
func clickRatesByDifficulty(aggs []campaignAgg) []dto.DifficultyClickRate {
	type acc struct{ clicked, reached int }
	byDiff := map[dto.DifficultyLevel]*acc{}
	for _, a := range aggs {
		diff := a.campaign.Difficulty
		if diff == "" {
			continue
		}
		e := byDiff[diff]
		if e == nil {
			e = &acc{}
			byDiff[diff] = e
		}
		e.clicked += len(a.clicked)
		e.reached += a.reachedDenominator()
	}
	out := make([]dto.DifficultyClickRate, 0, len(byDiff))
	for d, e := range byDiff {
		var rate float64
		if e.reached > 0 {
			rate = float64(e.clicked) / float64(e.reached)
		}
		out = append(out, dto.DifficultyClickRate{Difficulty: d, ClickRate: round4(clampUnit(rate))})
	}
	// Sort by the canonical difficulty order (easy < medium < hard).
	order := map[dto.DifficultyLevel]int{dto.DifficultyEasy: 0, dto.DifficultyMedium: 1, dto.DifficultyHard: 2}
	sort.Slice(out, func(i, j int) bool { return order[out[i].Difficulty] < order[out[j].Difficulty] })
	return out
}

// topClickedTemplates ranks templates by distinct clicking users,
// summed across every campaign that used the template.
func topClickedTemplates(aggs []campaignAgg) []dto.TemplateClickCount {
	byTemplate := map[string]int{}
	for _, a := range aggs {
		if a.campaign.TemplateID == "" {
			continue
		}
		byTemplate[a.campaign.TemplateID] += len(a.clicked)
	}
	out := make([]dto.TemplateClickCount, 0, len(byTemplate))
	for id, n := range byTemplate {
		if n == 0 {
			continue
		}
		out = append(out, dto.TemplateClickCount{TemplateID: id, ClickCount: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClickCount != out[j].ClickCount {
			return out[i].ClickCount > out[j].ClickCount
		}
		return out[i].TemplateID < out[j].TemplateID
	})
	if len(out) > topClickedLimit {
		out = out[:topClickedLimit]
	}
	return out
}

// regulatoryCompletion reports, per regime, the fraction of distinct
// targeted users who completed (reached a decision on) at least one
// simulation in that regime.
func regulatoryCompletion(aggs []campaignAgg) map[string]float64 {
	targeted := map[dto.RegulatoryCategory]map[string]struct{}{}
	completed := map[dto.RegulatoryCategory]map[string]struct{}{}
	for _, cat := range dto.AllRegulatoryCategories {
		targeted[cat] = map[string]struct{}{}
		completed[cat] = map[string]struct{}{}
	}
	for _, a := range aggs {
		if a.reg == "" {
			continue
		}
		tset, ok := targeted[a.reg]
		if !ok {
			// Unknown category on a template — skip defensively.
			continue
		}
		cset := completed[a.reg]
		// Targeted = delivered users, falling back to anyone who
		// interacted when deliveries weren't recorded.
		src := a.delivered
		if len(src) == 0 {
			src = a.reached
		}
		for u := range src {
			tset[u] = struct{}{}
		}
		for u := range a.decided {
			cset[u] = struct{}{}
		}
	}
	out := map[string]float64{}
	for _, cat := range dto.AllRegulatoryCategories {
		t := len(targeted[cat])
		var ratio float64
		if t > 0 {
			ratio = float64(len(completed[cat])) / float64(t)
		}
		out[string(cat)] = round4(clampUnit(ratio))
	}
	return out
}

// resilienceTrend computes a group resilience score at each time bucket
// in the range. Each bucket folds every user's interactions observed up
// to the bucket's end into ResilienceSignals and averages them via the
// scorer's group formula. Returns an empty series when no scorer is
// wired.
func (s *AnalyticsService) resilienceTrend(ctx context.Context, tenantID string, users map[string]*userAgg, r dto.TimeRange) []dto.DatedScore {
	if s.scorer == nil || len(users) == 0 {
		return []dto.DatedScore{}
	}
	bucketEnds := trendBuckets(r)
	out := make([]dto.DatedScore, 0, len(bucketEnds))
	for _, te := range bucketEnds {
		members := make([]ResilienceSignals, 0, len(users))
		for _, ua := range users {
			sig := ResilienceSignals{
				SimulationsSent:     countAtOrBefore(ua.sent, te),
				SimulationsDetected: countAtOrBefore(ua.detected, te),
				IncidentCount:       countAtOrBefore(ua.incident, te),
			}
			if sig.SimulationsSent == 0 {
				// User hadn't been sent a sim yet by this bucket.
				continue
			}
			members = append(members, sig)
		}
		if len(members) == 0 {
			continue
		}
		score, err := s.scorer.ComputeGroupScore(ctx, tenantID, "education-trend", members)
		if err != nil {
			s.log.WarnContext(ctx, "education: resilience trend bucket failed",
				slog.String("tenant_id", tenantID),
				slog.Time("bucket_end", te),
				slog.Any("error", err),
			)
			continue
		}
		out = append(out, dto.DatedScore{Date: te.Format("2006-01-02"), Score: float64(score.Score)})
	}
	return out
}

// trendBuckets returns the inclusive bucket-end timestamps for the
// range. Granularity is daily for windows up to 14 days and weekly
// beyond that, capped at maxTrendBuckets points.
func trendBuckets(r dto.TimeRange) []time.Time {
	span := r.End.Sub(r.Start)
	step := 24 * time.Hour
	if span > 14*24*time.Hour {
		step = 7 * 24 * time.Hour
	}
	var ends []time.Time
	for t := r.Start.Add(step); t.Before(r.End); t = t.Add(step) {
		ends = append(ends, t)
	}
	ends = append(ends, r.End)
	if len(ends) > maxTrendBuckets {
		// Keep the most recent maxTrendBuckets points.
		ends = ends[len(ends)-maxTrendBuckets:]
	}
	return ends
}

func (s *AnalyticsService) attackTypeOf(templateID string) dto.AttackType {
	if templateID == "" {
		return ""
	}
	if t, ok := s.templates.Get(templateID); ok {
		return t.AttackType
	}
	return ""
}

func (s *AnalyticsService) regulatoryOf(templateID string) dto.RegulatoryCategory {
	if templateID == "" {
		return ""
	}
	if cat, ok := s.templates.RegulatoryCategoryOf(templateID); ok {
		return cat
	}
	return ""
}

// campaignRefTime picks the most meaningful timestamp for ordering a
// campaign: completion, else start, else creation.
func campaignRefTime(c dto.Campaign) time.Time {
	if c.CompletedAt != nil && !c.CompletedAt.IsZero() {
		return c.CompletedAt.UTC()
	}
	if c.StartedAt != nil && !c.StartedAt.IsZero() {
		return c.StartedAt.UTC()
	}
	return c.CreatedAt.UTC()
}

// setEarliest records t for key only if it's the first observation or
// earlier than the existing one.
func setEarliest(m map[string]time.Time, key string, t time.Time) {
	if existing, ok := m[key]; !ok || t.Before(existing) {
		m[key] = t
	}
}

// countAtOrBefore counts how many timestamps in m are at or before te.
func countAtOrBefore(m map[string]time.Time, te time.Time) int {
	n := 0
	for _, t := range m {
		if !t.After(te) {
			n++
		}
	}
	return n
}

func clampUnit(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func round4(v float64) float64 {
	return float64(int64(v*1e4+0.5)) / 1e4
}
