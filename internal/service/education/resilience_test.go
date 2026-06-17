package education

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestResilience_NoDataIsNeutral(t *testing.T) {
	r := NewResilienceScorer(ResilienceScorerConfig{Cache: NewMemoryResilienceCache()})
	got, err := r.ComputeScore(context.Background(), "acme", "u-1", ResilienceSignals{})
	if err != nil {
		t.Fatalf("ComputeScore: %v", err)
	}
	// No data -> neutral 50s + incident-history starts at 100 -> total is mid.
	if got.Score < 40 || got.Score > 80 {
		t.Fatalf("expected mid-range neutral score, got %d", got.Score)
	}
	if got.Tier == "" {
		t.Fatal("tier not set")
	}
}

func TestResilience_PerfectSignalsScoresHigh(t *testing.T) {
	r := NewResilienceScorer(ResilienceScorerConfig{})
	got, _ := r.ComputeScore(context.Background(), "acme", "u-1", ResilienceSignals{
		SimulationsSent:      10,
		SimulationsDetected:  10,
		RealPhishingReceived: 5,
		RealPhishingReported: 5,
		LessonsServed:        8,
		LessonsExpected:      8,
		IncidentCount:        0,
	})
	if got.Score < 95 {
		t.Fatalf("expected high score, got %d", got.Score)
	}
	if got.Tier != dto.ResilienceHigh {
		t.Fatalf("tier: %q", got.Tier)
	}
}

func TestResilience_AllIncidentsScoresLow(t *testing.T) {
	r := NewResilienceScorer(ResilienceScorerConfig{})
	got, _ := r.ComputeScore(context.Background(), "acme", "u-1", ResilienceSignals{
		SimulationsSent:      5,
		SimulationsDetected:  0,
		RealPhishingReceived: 5,
		RealPhishingReported: 0,
		IncidentCount:        6, // > 4 → floors at 0
	})
	if got.Score > 30 {
		t.Fatalf("expected low score, got %d", got.Score)
	}
	if got.Tier != dto.ResilienceLow {
		t.Fatalf("tier: %q", got.Tier)
	}
}

func TestResilience_CachePersists(t *testing.T) {
	cache := NewMemoryResilienceCache()
	r := NewResilienceScorer(ResilienceScorerConfig{Cache: cache, TTL: time.Minute})
	score, _ := r.ComputeScore(context.Background(), "acme", "u-1", ResilienceSignals{
		SimulationsSent:     2,
		SimulationsDetected: 2,
	})
	cached, ok, err := r.Lookup(context.Background(), "acme", "u-1")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("expected cached score")
	}
	if cached.Score != score.Score {
		t.Fatalf("cached score: %d; expected %d", cached.Score, score.Score)
	}
}

func TestResilience_GroupAggregatesMembers(t *testing.T) {
	r := NewResilienceScorer(ResilienceScorerConfig{})
	members := []ResilienceSignals{
		{SimulationsSent: 10, SimulationsDetected: 10, RealPhishingReceived: 1, RealPhishingReported: 1, LessonsServed: 5, LessonsExpected: 5},
		{SimulationsSent: 10, SimulationsDetected: 0, RealPhishingReceived: 1, RealPhishingReported: 0, IncidentCount: 1, LessonsServed: 0, LessonsExpected: 5},
	}
	got, err := r.ComputeGroupScore(context.Background(), "acme", "marketing", members)
	if err != nil {
		t.Fatalf("ComputeGroupScore: %v", err)
	}
	if got.Subject != "marketing" {
		t.Fatalf("subject: %q", got.Subject)
	}
	// Mean of a perfect and a poor user should be somewhere in the middle.
	if got.Score < 30 || got.Score > 80 {
		t.Fatalf("group score out of expected band: %d", got.Score)
	}
}

func TestResilience_GroupEmpty(t *testing.T) {
	r := NewResilienceScorer(ResilienceScorerConfig{})
	got, err := r.ComputeGroupScore(context.Background(), "acme", "empty", nil)
	if err != nil {
		t.Fatalf("ComputeGroupScore: %v", err)
	}
	if got.Score != 50 {
		t.Fatalf("expected neutral 50 for empty group, got %d", got.Score)
	}
}

func TestResilience_BucketTier(t *testing.T) {
	cases := []struct {
		score int
		want  dto.ResilienceTier
	}{
		{0, dto.ResilienceLow},
		{39, dto.ResilienceLow},
		{40, dto.ResilienceMedium},
		{69, dto.ResilienceMedium},
		{70, dto.ResilienceHigh},
		{100, dto.ResilienceHigh},
	}
	for _, c := range cases {
		if got := dto.BucketTier(c.score); got != c.want {
			t.Fatalf("BucketTier(%d) = %q; want %q", c.score, got, c.want)
		}
	}
}

func TestResilience_RejectsEmptyTenant(t *testing.T) {
	r := NewResilienceScorer(ResilienceScorerConfig{})
	if _, err := r.ComputeScore(context.Background(), "", "u", ResilienceSignals{}); err == nil {
		t.Fatal("expected error for empty tenant")
	}
	if _, err := r.ComputeScore(context.Background(), "acme", "", ResilienceSignals{}); err == nil {
		t.Fatal("expected error for empty user")
	}
	if _, err := r.ComputeGroupScore(context.Background(), "", "g", []ResilienceSignals{}); err == nil {
		t.Fatal("expected error for empty tenant")
	}
	if _, err := r.ComputeGroupScore(context.Background(), "acme", "", []ResilienceSignals{}); err == nil {
		t.Fatal("expected error for empty group")
	}
}

func TestMemoryResilienceCache_SweepsExpiredOnSet(t *testing.T) {
	base := time.Now()
	cur := base
	c := NewMemoryResilienceCache()
	c.now = func() time.Time { return cur }
	c.sweepInterval = time.Minute
	c.lastSweep = cur

	ctx := context.Background()
	// A short-TTL entry, and a no-TTL (permanent) entry.
	_ = c.Set(ctx, "tenant:a:resilience:u1", dto.ResilienceScore{Score: 70}, 30*time.Second)
	_ = c.Set(ctx, "tenant:a:resilience:u2", dto.ResilienceScore{Score: 40}, 0)
	if len(c.items) != 2 {
		t.Fatalf("expected 2 entries before sweep, got %d", len(c.items))
	}

	// Advance past u1's expiry and past the sweep interval, then write a
	// third key — the opportunistic sweep on Set should reclaim u1 while
	// keeping the permanent u2 and the fresh u3.
	cur = base.Add(2 * time.Minute)
	_ = c.Set(ctx, "tenant:a:resilience:u3", dto.ResilienceScore{Score: 55}, 30*time.Second)

	if _, ok := c.items["tenant:a:resilience:u1"]; ok {
		t.Fatal("expired u1 should have been swept")
	}
	if _, ok := c.items["tenant:a:resilience:u2"]; !ok {
		t.Fatal("permanent u2 (no TTL) should be retained")
	}
	if _, ok := c.items["tenant:a:resilience:u3"]; !ok {
		t.Fatal("fresh u3 should be retained")
	}

	// The expired entry is also invisible via Get before the sweep runs.
	if _, ok, _ := c.Get(ctx, "tenant:a:resilience:u3"); !ok {
		t.Fatal("u3 should be readable while unexpired")
	}
	cur = base.Add(3 * time.Minute)
	if _, ok, _ := c.Get(ctx, "tenant:a:resilience:u3"); ok {
		t.Fatal("u3 should read as expired after its TTL elapses")
	}
}
