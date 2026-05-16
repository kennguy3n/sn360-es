package education

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/numutil"
)

// ResilienceSignals is the bundle of per-user / per-group metrics the
// scorer pulls from the various data sources. Callers are expected to
// populate the fields they have; missing fields contribute neutral
// (50/100) weight rather than penalising the subject.
type ResilienceSignals struct {
	// SimulationsSent is the total simulations the subject received in
	// the scoring window.
	SimulationsSent int
	// SimulationsDetected is the count where the subject reported the
	// simulation OR ignored it without engaging.
	SimulationsDetected int
	// RealPhishingReceived counts production messages classified as
	// Warning+ tier delivered to the subject.
	RealPhishingReceived int
	// RealPhishingReported counts how many of those the subject
	// reported via the banner action.
	RealPhishingReported int
	// LessonsServed counts how many micro-lessons the subject viewed
	// (or were served to a group's members).
	LessonsServed int
	// LessonsExpected approximates how many should have been served
	// given the subject's risk profile (used to compute engagement %).
	LessonsExpected int
	// IncidentCount counts confirmed incidents (clicked / submitted
	// credentials / fell for a real attack) in the scoring window.
	IncidentCount int
}

// ResilienceCache is an opaque per-tenant cache. The contract matches
// Redis with a TTL: callers may persist scores keyed by the canonical
// key returned by ResilienceKey.
type ResilienceCache interface {
	Get(ctx context.Context, key string) (dto.ResilienceScore, bool, error)
	Set(ctx context.Context, key string, value dto.ResilienceScore, ttl time.Duration) error
}

// ResilienceScorerConfig wires the ResilienceScorer.
type ResilienceScorerConfig struct {
	Cache  ResilienceCache
	TTL    time.Duration
	Logger *slog.Logger
	Clock  func() time.Time
}

// ResilienceScorer implements the resilience formula from PROPOSAL.md
// §5c:
//
//	score = 0.40 * simulation_performance
//	      + 0.25 * report_rate
//	      + 0.20 * lesson_engagement
//	      + 0.15 * incident_history
type ResilienceScorer struct {
	cache ResilienceCache
	ttl   time.Duration
	log   *slog.Logger
	now   func() time.Time
}

// NewResilienceScorer constructs a scorer.
func NewResilienceScorer(cfg ResilienceScorerConfig) *ResilienceScorer {
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &ResilienceScorer{
		cache: cfg.Cache,
		ttl:   cfg.TTL,
		log:   cfg.Logger,
		now:   cfg.Clock,
	}
}

// ComputeScore evaluates the formula for an individual user. The
// subject is the canonical user-hash (NOT email).
func (s *ResilienceScorer) ComputeScore(ctx context.Context, tenantID, userHash string, sig ResilienceSignals) (dto.ResilienceScore, error) {
	if tenantID == "" {
		return dto.ResilienceScore{}, errors.New("education: tenant_id is required")
	}
	if userHash == "" {
		return dto.ResilienceScore{}, errors.New("education: user_hash is required")
	}
	score := computeFromSignals(userHash, sig, s.now())
	if s.cache != nil {
		_ = s.cache.Set(ctx, ResilienceKey(tenantID, userHash), score, s.ttl)
	}
	return score, nil
}

// ComputeGroupScore aggregates per-user signals into a group score by
// averaging the sub-components. This preserves the meaning of each
// breakdown rather than collapsing to a single integer.
func (s *ResilienceScorer) ComputeGroupScore(ctx context.Context, tenantID, groupID string, members []ResilienceSignals) (dto.ResilienceScore, error) {
	if tenantID == "" {
		return dto.ResilienceScore{}, errors.New("education: tenant_id is required")
	}
	if groupID == "" {
		return dto.ResilienceScore{}, errors.New("education: group_id is required")
	}
	if len(members) == 0 {
		neutral := neutralScore(groupID, s.now())
		neutral.Subject = groupID
		return neutral, nil
	}
	var sumSim, sumReport, sumEng, sumInc, sumTotal float64
	for _, m := range members {
		sub := computeFromSignals("agg", m, s.now())
		sumSim += float64(sub.SimulationScore)
		sumReport += float64(sub.ReportRateScore)
		sumEng += float64(sub.EngagementScore)
		sumInc += float64(sub.IncidentScore)
		sumTotal += float64(sub.Score)
	}
	n := float64(len(members))
	score := dto.ResilienceScore{
		Subject:         groupID,
		Score:           numutil.IntClamp(sumTotal / n),
		SimulationScore: numutil.IntClamp(sumSim / n),
		ReportRateScore: numutil.IntClamp(sumReport / n),
		EngagementScore: numutil.IntClamp(sumEng / n),
		IncidentScore:   numutil.IntClamp(sumInc / n),
		ComputedAt:      s.now(),
	}
	score.Tier = dto.BucketTier(score.Score)
	if s.cache != nil {
		_ = s.cache.Set(ctx, ResilienceKey(tenantID, "group:"+groupID), score, s.ttl)
	}
	return score, nil
}

// Lookup returns the most recent cached score for a subject (user or
// group). Returns ok=false if not cached.
func (s *ResilienceScorer) Lookup(ctx context.Context, tenantID, subject string) (dto.ResilienceScore, bool, error) {
	if s.cache == nil {
		return dto.ResilienceScore{}, false, nil
	}
	return s.cache.Get(ctx, ResilienceKey(tenantID, subject))
}

// ResilienceKey returns the canonical Redis key for a resilience score.
func ResilienceKey(tenantID, subject string) string {
	return fmt.Sprintf("tenant:%s:resilience:%s", tenantID, subject)
}

func computeFromSignals(subject string, sig ResilienceSignals, now time.Time) dto.ResilienceScore {
	sim := simulationPerformance(sig)
	report := reportRate(sig)
	engagement := lessonEngagement(sig)
	incidents := incidentHistory(sig)
	total := 0.40*sim + 0.25*report + 0.20*engagement + 0.15*incidents
	score := dto.ResilienceScore{
		Subject:         subject,
		Score:           numutil.IntClamp(total),
		SimulationScore: numutil.IntClamp(sim),
		ReportRateScore: numutil.IntClamp(report),
		EngagementScore: numutil.IntClamp(engagement),
		IncidentScore:   numutil.IntClamp(incidents),
		ComputedAt:      now,
	}
	score.Tier = dto.BucketTier(score.Score)
	return score
}

// All sub-scorers return a 0..100 float. Neutral is 50.

func simulationPerformance(sig ResilienceSignals) float64 {
	if sig.SimulationsSent <= 0 {
		return 50
	}
	return numutil.ClampPct(float64(sig.SimulationsDetected) / float64(sig.SimulationsSent) * 100)
}

func reportRate(sig ResilienceSignals) float64 {
	if sig.RealPhishingReceived <= 0 {
		return 50
	}
	return numutil.ClampPct(float64(sig.RealPhishingReported) / float64(sig.RealPhishingReceived) * 100)
}

func lessonEngagement(sig ResilienceSignals) float64 {
	if sig.LessonsExpected <= 0 {
		return 50
	}
	ratio := float64(sig.LessonsServed) / float64(sig.LessonsExpected)
	if ratio > 1 {
		ratio = 1
	}
	return numutil.ClampPct(ratio * 100)
}

func incidentHistory(sig ResilienceSignals) float64 {
	// Each incident knocks 25 points off a starting 100. Floor at 0.
	score := 100 - float64(sig.IncidentCount)*25
	return numutil.ClampPct(score)
}

func neutralScore(subject string, now time.Time) dto.ResilienceScore {
	return dto.ResilienceScore{
		Subject:         subject,
		Score:           50,
		Tier:            dto.ResilienceMedium,
		SimulationScore: 50, ReportRateScore: 50, EngagementScore: 50, IncidentScore: 100,
		ComputedAt: now,
	}
}

// --- In-memory cache --------------------------------------------------------

// MemoryResilienceCache is a goroutine-safe in-memory cache used for
// tests and small deployments.
type MemoryResilienceCache struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
}

type cacheEntry struct {
	value     dto.ResilienceScore
	expiresAt time.Time
}

// NewMemoryResilienceCache returns an empty cache.
func NewMemoryResilienceCache() *MemoryResilienceCache {
	return &MemoryResilienceCache{items: map[string]cacheEntry{}}
}

// Get implements ResilienceCache.
func (c *MemoryResilienceCache) Get(_ context.Context, key string) (dto.ResilienceScore, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.items[key]
	if !ok {
		return dto.ResilienceScore{}, false, nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		return dto.ResilienceScore{}, false, nil
	}
	return e.value, true, nil
}

// Set implements ResilienceCache.
func (c *MemoryResilienceCache) Set(_ context.Context, key string, value dto.ResilienceScore, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := time.Time{}
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	c.items[key] = cacheEntry{value: value, expiresAt: exp}
	return nil
}

// MarshalSignals is a small convenience for callers that want to log
// the signals JSON-encoded without exposing this package's internal
// formatting choices.
func MarshalSignals(s ResilienceSignals) ([]byte, error) { return json.Marshal(s) }
