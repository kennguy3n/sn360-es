package redis

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// newRateBucketStore wires a RateBucketStore against miniredis with
// an injectable clock so tests can advance time deterministically.
// The returned setNow lets the caller jump the clock forward to
// observe refill behaviour without sleeping.
func newRateBucketStore(t *testing.T, ttl time.Duration) (*RateBucketStore, func(time.Time)) {
	t.Helper()
	client, _ := newMiniredisClient(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	var mu sync.Mutex
	nowFn := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	setNow := func(t time.Time) {
		mu.Lock()
		defer mu.Unlock()
		now = t
	}
	s, err := NewRateBucketStore(context.Background(), client, RateBucketConfig{
		KeyPrefix: "rl:test",
		TTL:       ttl,
		Now:       nowFn,
	})
	if err != nil {
		t.Fatalf("NewRateBucketStore: %v", err)
	}
	return s, setNow
}

// TestRateBucketStore_BurstThenDeny exercises the canonical token-
// bucket invariant: a fresh bucket allows `burst` consecutive Takes,
// then denies the (burst+1)th — and the denial's retry-after is the
// time to refill one token at the configured rate.
func TestRateBucketStore_BurstThenDeny(t *testing.T) {
	s, _ := newRateBucketStore(t, time.Minute)
	ctx := context.Background()

	// rate=2 tokens/sec, burst=3 → first 3 takes succeed, 4th
	// denied; retry-after = 1/2s = 500 ms.
	for i := 0; i < 3; i++ {
		allowed, retry, err := s.Take(ctx, "client-A", 2, 3)
		if err != nil {
			t.Fatalf("Take #%d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("Take #%d: expected allowed", i)
		}
		if retry != 0 {
			t.Fatalf("Take #%d: retry-after on allowed should be 0, got %v", i, retry)
		}
	}
	allowed, retry, err := s.Take(ctx, "client-A", 2, 3)
	if err != nil {
		t.Fatalf("Take #4: %v", err)
	}
	if allowed {
		t.Fatal("Take #4: expected denial after burst")
	}
	if retry < 400*time.Millisecond || retry > 600*time.Millisecond {
		t.Fatalf("Take #4: retry-after = %v, want ~500ms", retry)
	}
}

// TestRateBucketStore_Refill verifies that advancing the clock by
// `t = burst/rate` seconds refills the bucket back to `burst`. This
// is the property that lets a well-behaved client serve sustained
// traffic at `rate` r/s without ever getting 429'd.
func TestRateBucketStore_Refill(t *testing.T) {
	s, setNow := newRateBucketStore(t, time.Minute)
	ctx := context.Background()
	rate := 10.0
	burst := 5

	// Drain.
	for i := 0; i < burst; i++ {
		if allowed, _, err := s.Take(ctx, "refill", rate, burst); err != nil || !allowed {
			t.Fatalf("drain Take #%d: allowed=%v err=%v", i, allowed, err)
		}
	}
	if allowed, _, _ := s.Take(ctx, "refill", rate, burst); allowed {
		t.Fatal("post-drain Take must be denied")
	}

	// Jump forward 1 second → at 10 r/s the bucket has 10 tokens
	// of refill credit, capped at burst=5. Take 5 must all succeed.
	setNow(time.Unix(1_700_000_001, 0).UTC())
	for i := 0; i < burst; i++ {
		allowed, _, err := s.Take(ctx, "refill", rate, burst)
		if err != nil || !allowed {
			t.Fatalf("post-refill Take #%d: allowed=%v err=%v", i, allowed, err)
		}
	}
	if allowed, _, _ := s.Take(ctx, "refill", rate, burst); allowed {
		t.Fatal("(burst+1)th post-refill Take must be denied")
	}
}

// TestRateBucketStore_IsolationBetweenClients locks in the
// fundamental requirement: client A draining its bucket must not
// affect client B's bucket. Without this, a single noisy IP would
// starve every other IP.
func TestRateBucketStore_IsolationBetweenClients(t *testing.T) {
	s, _ := newRateBucketStore(t, time.Minute)
	ctx := context.Background()
	rate := 1.0
	burst := 2

	// Drain client A.
	for i := 0; i < burst; i++ {
		if allowed, _, err := s.Take(ctx, "client-A", rate, burst); err != nil || !allowed {
			t.Fatalf("A drain #%d: allowed=%v err=%v", i, allowed, err)
		}
	}
	if allowed, _, _ := s.Take(ctx, "client-A", rate, burst); allowed {
		t.Fatal("A post-drain Take must be denied")
	}

	// Client B is unaffected.
	for i := 0; i < burst; i++ {
		allowed, _, err := s.Take(ctx, "client-B", rate, burst)
		if err != nil || !allowed {
			t.Fatalf("B Take #%d: allowed=%v err=%v", i, allowed, err)
		}
	}
}

// TestRateBucketStore_ClusterShared mimics the "two replicas at
// the same rate" scenario the cluster limiter exists to fix. Two
// distinct RateBucketStore values pointing at the same Redis must
// see the same bucket — i.e. replica A's drain blocks replica B,
// not the other way around (which is exactly what the in-memory
// limiter fails to do across replicas).
func TestRateBucketStore_ClusterShared(t *testing.T) {
	client, _ := newMiniredisClient(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	nowFn := func() time.Time { return now }
	a, err := NewRateBucketStore(context.Background(), client, RateBucketConfig{KeyPrefix: "shared", TTL: time.Minute, Now: nowFn})
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := NewRateBucketStore(context.Background(), client, RateBucketConfig{KeyPrefix: "shared", TTL: time.Minute, Now: nowFn})
	if err != nil {
		t.Fatalf("b: %v", err)
	}

	ctx := context.Background()
	// Drain via replica A.
	for i := 0; i < 5; i++ {
		if allowed, _, err := a.Take(ctx, "ip-1", 1, 5); err != nil || !allowed {
			t.Fatalf("A Take #%d: allowed=%v err=%v", i, allowed, err)
		}
	}
	// Replica B sees the same drained bucket.
	allowed, retry, err := b.Take(ctx, "ip-1", 1, 5)
	if err != nil {
		t.Fatalf("B Take after A drain: %v", err)
	}
	if allowed {
		t.Fatal("B Take after A drained the bucket must be denied (cluster-wide sharing)")
	}
	if retry < 500*time.Millisecond || retry > 1500*time.Millisecond {
		t.Fatalf("B retry-after = %v, want ~1s", retry)
	}
}

// TestRateBucketStore_RejectsInvalid covers Take's input validation.
// Negative or zero rate / burst is a configuration bug we want to
// surface loudly, not silently allow.
func TestRateBucketStore_RejectsInvalid(t *testing.T) {
	s, _ := newRateBucketStore(t, time.Minute)
	ctx := context.Background()
	cases := []struct {
		name  string
		rate  float64
		burst int
		key   string
	}{
		{"zero rate", 0, 1, "x"},
		{"negative rate", -1, 1, "x"},
		{"zero burst", 1, 0, "x"},
		{"negative burst", 1, -1, "x"},
		{"empty key", 1, 1, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := s.Take(ctx, c.key, c.rate, c.burst)
			if err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
			// Empty-key uses a different sentinel than
			// invalid-rate/burst; either is fine, we just
			// assert the call failed loudly.
			if c.key != "" && !errors.Is(err, ErrInvalidRateLimit) {
				t.Fatalf("expected ErrInvalidRateLimit for %s, got %v", c.name, err)
			}
		})
	}
}

// TestRateBucketStore_Reset deletes the bucket so the next Take
// starts from a fresh `burst`. Required for the operational
// override flow (SRE clearing a stuck bucket).
func TestRateBucketStore_Reset(t *testing.T) {
	s, _ := newRateBucketStore(t, time.Minute)
	ctx := context.Background()
	if allowed, _, err := s.Take(ctx, "drain-me", 1, 1); err != nil || !allowed {
		t.Fatalf("initial Take: %v %v", allowed, err)
	}
	if allowed, _, _ := s.Take(ctx, "drain-me", 1, 1); allowed {
		t.Fatal("after burst, second Take must be denied")
	}
	if err := s.Reset(ctx, "drain-me"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if allowed, _, err := s.Take(ctx, "drain-me", 1, 1); err != nil || !allowed {
		t.Fatalf("post-Reset Take: %v %v", allowed, err)
	}
}

// TestNewRateBucketStore_RejectsBadConfig surfaces every constructor
// guardrail. The store is meant to fail boot, not first-request, on
// misconfiguration.
func TestNewRateBucketStore_RejectsBadConfig(t *testing.T) {
	client, _ := newMiniredisClient(t)
	t.Run("nil client", func(t *testing.T) {
		_, err := NewRateBucketStore(context.Background(), nil, RateBucketConfig{KeyPrefix: "x"})
		if err == nil || !strings.Contains(err.Error(), "non-nil client") {
			t.Fatalf("nil client: got %v", err)
		}
	})
	t.Run("empty key prefix", func(t *testing.T) {
		_, err := NewRateBucketStore(context.Background(), client, RateBucketConfig{KeyPrefix: ""})
		if err == nil || !strings.Contains(err.Error(), "key prefix") {
			t.Fatalf("empty prefix: got %v", err)
		}
	})
	t.Run("default ttl and clock", func(t *testing.T) {
		s, err := NewRateBucketStore(context.Background(), client, RateBucketConfig{KeyPrefix: "x"})
		if err != nil {
			t.Fatalf("default config: %v", err)
		}
		if s.ttl <= 0 {
			t.Fatalf("default ttl must be positive, got %v", s.ttl)
		}
		if s.now == nil {
			t.Fatal("default clock must be set")
		}
	})
}

// TestRateBucketStore_TTLBoundFloorsAtRefill verifies the TTL floor:
// configured TTL too short to cover a full refill is silently raised
// so the bucket cannot be evicted mid-drain and reset to `burst`.
func TestRateBucketStore_TTLBoundFloorsAtRefill(t *testing.T) {
	// rate=1, burst=60 → refill-from-empty time = 60s. A
	// configured TTL of 1s would evict the drained bucket within
	// 1s and the next Take would start from burst=60 — handing
	// the abuser a fresh 60 tokens. The floor protects against
	// that.
	client, mr := newMiniredisClient(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	nowFn := func() time.Time { return now }
	s, err := NewRateBucketStore(context.Background(), client, RateBucketConfig{KeyPrefix: "floor", TTL: time.Second, Now: nowFn})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if _, _, err := s.Take(context.Background(), "ab", 1, 60); err != nil {
		t.Fatalf("Take: %v", err)
	}
	got := mr.TTL("floor:ab")
	// At rate=1 b/s, burst=60 → floor is 60 s of TTL.
	// miniredis reports the remaining TTL.
	if got < 30*time.Second {
		t.Fatalf("TTL floor not applied: got %v, want >= 30s", got)
	}
}
