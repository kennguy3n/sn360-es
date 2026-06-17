package events

import (
	"testing"
	"time"
)

// newTestRateLimiter builds a RateLimitedEventService with a frozen,
// caller-controlled clock. inner is nil because these tests exercise
// only the bucket bookkeeping (allow / sweepIdle), which never touches
// the wrapped service.
func newTestRateLimiter(cfg RateLimitConfig) *RateLimitedEventService {
	return NewRateLimitedEventService(nil, cfg)
}

func TestRateLimitedEventService_BurstThenDeny(t *testing.T) {
	now := time.Now()
	s := newTestRateLimiter(RateLimitConfig{
		MaxPerTenantPerSecond: 10,
		BurstSize:             3,
		Clock:                 func() time.Time { return now },
	})
	for i := 0; i < 3; i++ {
		if !s.allow("t1") {
			t.Fatalf("request %d: expected allow within burst", i)
		}
	}
	if s.allow("t1") {
		t.Fatal("expected deny once the burst is exhausted with no refill")
	}
}

func TestRateLimitedEventService_RefillsOverTime(t *testing.T) {
	now := time.Now()
	s := newTestRateLimiter(RateLimitConfig{
		MaxPerTenantPerSecond: 10,
		BurstSize:             1,
		Clock:                 func() time.Time { return now },
	})
	if !s.allow("t1") {
		t.Fatal("first request should be allowed")
	}
	if s.allow("t1") {
		t.Fatal("second immediate request should be denied")
	}
	// 10 tokens/sec → one token after 100ms.
	now = now.Add(150 * time.Millisecond)
	if !s.allow("t1") {
		t.Fatal("request after refill window should be allowed")
	}
}

func TestRateLimitedEventService_EvictsIdleKeepsActive(t *testing.T) {
	now := time.Now()
	s := newTestRateLimiter(RateLimitConfig{
		MaxPerTenantPerSecond: 10,
		BurstSize:             3,
		IdleTTL:               10 * time.Minute,
		SweepInterval:         time.Minute,
		Clock:                 func() time.Time { return now },
	})
	s.allow("t1")
	s.allow("t2")
	if len(s.buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(s.buckets))
	}
	t1Bucket := s.buckets["t1"]

	// Keep t1 warm at +6m: the sweep runs but t2 is only idle 6m < 10m
	// TTL, so nothing is evicted yet.
	now = now.Add(6 * time.Minute)
	s.allow("t1")
	if len(s.buckets) != 2 {
		t.Fatalf("nothing should be evicted yet, got %d buckets", len(s.buckets))
	}

	// Touch t1 again at +12m: t1 is idle only 6m (kept), t2 is now idle
	// 12m ≥ TTL and fully refilled (evicted).
	now = now.Add(6 * time.Minute)
	s.allow("t1")
	if _, ok := s.buckets["t2"]; ok {
		t.Fatal("idle t2 bucket should have been evicted")
	}
	if s.buckets["t1"] != t1Bucket {
		t.Fatal("active t1 bucket should be the same retained instance")
	}
}

func TestRateLimitedEventService_EvictionIsLossless(t *testing.T) {
	now := time.Now()
	s := newTestRateLimiter(RateLimitConfig{
		MaxPerTenantPerSecond: 10,
		BurstSize:             3,
		IdleTTL:               time.Minute,
		SweepInterval:         time.Second,
		Clock:                 func() time.Time { return now },
	})
	// Drain t1 completely.
	for i := 0; i < 3; i++ {
		s.allow("t1")
	}
	if s.allow("t1") {
		t.Fatal("t1 should be drained")
	}

	// Let t1 sit idle past the TTL, then drive an unrelated tenant so the
	// sweep runs and evicts t1.
	now = now.Add(2 * time.Minute)
	s.allow("t2")
	if _, ok := s.buckets["t1"]; ok {
		t.Fatal("idle t1 should have been evicted")
	}

	// A returning t1 gets a fresh full bucket — identical to the state a
	// retained-and-refilled bucket would have presented, so no tenant can
	// exceed its limit by churning through eviction.
	if !s.allow("t1") {
		t.Fatal("returning t1 should get a fresh full bucket")
	}
}

func TestRateLimitedEventService_NoEvictionWhileDraining(t *testing.T) {
	now := time.Now()
	s := newTestRateLimiter(RateLimitConfig{
		MaxPerTenantPerSecond: 10,
		BurstSize:             3,
		IdleTTL:               time.Minute,
		SweepInterval:         time.Second,
		Clock:                 func() time.Time { return now },
	})
	// Hit t1 continuously so it never sits idle for a full TTL; its
	// partially-drained bucket must never be evicted (eviction would
	// reset it to full and defeat the limiter).
	for i := 0; i < 50; i++ {
		s.allow("t1")
		now = now.Add(2 * time.Second) // < IdleTTL each step
	}
	if _, ok := s.buckets["t1"]; !ok {
		t.Fatal("continuously-active t1 bucket must not be evicted")
	}
}
