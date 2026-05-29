package middleware

import (
	"context"
	"errors"
	"sync"
	"time"
)

// memoryBucketStore is the default in-process [BucketStore]: one
// bucket per clientKey in a sync.Map, served by per-bucket mutex so
// concurrent Take calls against the same key serialise. It is the
// original behaviour of the rate-limit middleware before the
// pluggable BucketStore abstraction landed — preserved for callers
// that have not migrated to Redis-backed counting yet, and used as
// the FailureModeFallback when the Redis path falters.
//
// Eviction is driven externally by [RateLimiter.sweepIdle] (which
// the limiter's janitor invokes on a ticker). The store does not
// run its own goroutine — the limiter owns lifecycle so it can be
// cleanly Stopped.
type memoryBucketStore struct {
	now     func() time.Time
	buckets sync.Map // string -> *memoryBucket
}

// memoryBucket is the per-key state. Locking by value inside the
// struct keeps the sync.Map entry to a single pointer.
type memoryBucket struct {
	mu       sync.Mutex
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
}

// newMemoryBucketStore returns a fresh in-process store. The clock
// is injectable so tests can drive refill / eviction
// deterministically.
func newMemoryBucketStore(now func() time.Time) *memoryBucketStore {
	if now == nil {
		now = time.Now
	}
	return &memoryBucketStore{now: now}
}

// Take implements [BucketStore].
//
// rate / burst are validated on every call — both because the
// interface contract requires it (per-call config drift is allowed)
// and because the limiter's defaults are applied at config time, so
// the store cannot rely on them having been pre-checked here.
func (s *memoryBucketStore) Take(_ context.Context, clientKey string, rate float64, burst int) (bool, time.Duration, error) {
	if rate <= 0 || burst <= 0 {
		return false, 0, errors.New("rate-limit: rate and burst must be positive")
	}
	if clientKey == "" {
		return false, 0, errors.New("rate-limit: clientKey is required")
	}
	now := s.now()
	b := s.bucketFor(clientKey, now, burst)
	if !b.take(now, rate, burst) {
		return false, b.retryAfter(rate), nil
	}
	return true, 0, nil
}

// bucketFor returns the bucket for clientKey, creating it on first
// use. The lastSeen timestamp is bumped on every lookup so the
// janitor doesn't evict an actively-used bucket.
func (s *memoryBucketStore) bucketFor(clientKey string, now time.Time, burst int) *memoryBucket {
	if v, ok := s.buckets.Load(clientKey); ok {
		b := v.(*memoryBucket)
		b.mu.Lock()
		b.lastSeen = now
		b.mu.Unlock()
		return b
	}
	fresh := &memoryBucket{
		tokens:   float64(burst),
		lastFill: now,
		lastSeen: now,
	}
	actual, _ := s.buckets.LoadOrStore(clientKey, fresh)
	b := actual.(*memoryBucket)
	if actual != fresh {
		b.mu.Lock()
		b.lastSeen = now
		b.mu.Unlock()
	}
	return b
}

// sweepIdle evicts buckets that have not been touched within
// idleTTL. The conditional CompareAndDelete keeps the sweep safe
// against the racing-update case where a request lands between the
// idle check and the delete.
func (s *memoryBucketStore) sweepIdle(now time.Time, idleTTL time.Duration) int {
	removed := 0
	s.buckets.Range(func(key, value any) bool {
		b := value.(*memoryBucket)
		b.mu.Lock()
		idle := now.Sub(b.lastSeen) > idleTTL
		b.mu.Unlock()
		if idle {
			if s.buckets.CompareAndDelete(key, value) {
				removed++
			}
		}
		return true
	})
	return removed
}

// take attempts to consume one token from the bucket. Returns true
// if the request is allowed. Refill is computed lazily on every
// Take so we don't need a refill goroutine.
func (b *memoryBucket) take(now time.Time, rate float64, burst int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	elapsed := now.Sub(b.lastFill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rate
		if ceiling := float64(burst); b.tokens > ceiling {
			b.tokens = ceiling
		}
		b.lastFill = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	b.lastSeen = now
	return true
}

// retryAfter returns the duration until the bucket regains one full
// token. Rate must be positive (the store's Take validates this).
func (b *memoryBucket) retryAfter(rate float64) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tokens >= 1 {
		return 0
	}
	deficit := 1 - b.tokens
	secs := deficit / rate
	if secs < 0 {
		secs = 0
	}
	return time.Duration(secs * float64(time.Second))
}

// NewMemoryBucketStore returns a fresh in-process [BucketStore].
// Exported so callers wiring the rate limiter manually (e.g. tests,
// custom keyed limiters) can build an explicit memory store
// independent of the RateLimiter's owned-store lifecycle.
func NewMemoryBucketStore() BucketStore {
	return newMemoryBucketStore(time.Now)
}
