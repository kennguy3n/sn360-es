package middleware_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/middleware"
)

// stubBucketStore lets tests drive the BucketStore contract directly:
// every Take call records the (key, rate, burst) tuple and returns
// the pre-seeded response. It is the canonical way to assert that
// the limiter wires its BucketStore correctly without standing up
// Redis or relying on the in-memory implementation.
type stubBucketStore struct {
	calls atomic.Int64
	// allowed / retry / err are the canned reply. Allowed=true is
	// the default (request passes).
	allowed bool
	retry   time.Duration
	err     error
	// lastKey / lastRate / lastBurst capture the most recent call
	// so assertions can verify the limiter passes through the
	// configured rate / burst unchanged.
	lastKey   string
	lastRate  float64
	lastBurst int
}

func (s *stubBucketStore) Take(_ context.Context, key string, rate float64, burst int) (bool, time.Duration, error) {
	s.calls.Add(1)
	s.lastKey = key
	s.lastRate = rate
	s.lastBurst = burst
	return s.allowed, s.retry, s.err
}

func TestRateLimiter_PluggableStore_DelegatesToConfiguredBackend(t *testing.T) {
	t.Parallel()
	store := &stubBucketStore{allowed: true}
	backend := &countedHandler{}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:  100,
		Burst: 50,
		Store: store,
	})
	defer rl.Stop()

	req := newRequest(t, "10.0.0.1", "/v1/things")
	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := store.calls.Load(); got != 1 {
		t.Fatalf("store.calls=%d want=1", got)
	}
	if store.lastKey != "10.0.0.1" {
		t.Fatalf("store.lastKey=%q want=10.0.0.1", store.lastKey)
	}
	if store.lastRate != 100 || store.lastBurst != 50 {
		t.Fatalf("store.last={rate=%v burst=%d} want={100, 50}",
			store.lastRate, store.lastBurst)
	}
	if backend.calls.Load() != 1 {
		t.Fatalf("backend.calls=%d want=1", backend.calls.Load())
	}
}

func TestRateLimiter_PluggableStore_HonoursDeny(t *testing.T) {
	t.Parallel()
	store := &stubBucketStore{
		allowed: false,
		retry:   1500 * time.Millisecond,
	}
	backend := &countedHandler{}
	var limitedCalls atomic.Int64
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:  10,
		Burst: 5,
		Store: store,
		OnLimited: func(_, _ string) {
			limitedCalls.Add(1)
		},
	})
	defer rl.Stop()

	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.1", "/v1/things"))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want=429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		// 1.5s rounds up to 2 in the HTTP retry-after seconds
		// representation.
		t.Fatalf("Retry-After=%q want=2", got)
	}
	if backend.calls.Load() != 0 {
		t.Fatalf("backend should not be reached; calls=%d", backend.calls.Load())
	}
	if limitedCalls.Load() != 1 {
		t.Fatalf("OnLimited not called; got=%d", limitedCalls.Load())
	}
}

func TestRateLimiter_StoreError_FailureModeOpen_LetsRequestThrough(t *testing.T) {
	t.Parallel()
	store := &stubBucketStore{
		err: errors.New("kaboom"),
	}
	backend := &countedHandler{}
	var observedErr atomic.Pointer[error]
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:        10,
		Burst:       5,
		Store:       store,
		FailureMode: middleware.FailureModeOpen,
		OnStoreError: func(err error, _ string) {
			observedErr.Store(&err)
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer rl.Stop()

	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.1", "/v1/things"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=200 (fail-open)", rec.Code)
	}
	if backend.calls.Load() != 1 {
		t.Fatalf("backend.calls=%d want=1", backend.calls.Load())
	}
	if p := observedErr.Load(); p == nil || (*p).Error() != "kaboom" {
		t.Fatalf("OnStoreError not called or wrong err: %v", observedErr.Load())
	}
}

func TestRateLimiter_StoreError_FailureModeClosed_Returns503(t *testing.T) {
	t.Parallel()
	store := &stubBucketStore{
		err: errors.New("kaboom"),
	}
	backend := &countedHandler{}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:        10,
		Burst:       5,
		Store:       store,
		FailureMode: middleware.FailureModeClosed,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer rl.Stop()

	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.1", "/v1/things"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=503 (fail-closed)", rec.Code)
	}
	if backend.calls.Load() != 0 {
		t.Fatalf("backend.calls=%d want=0", backend.calls.Load())
	}
}

func TestRateLimiter_PrimaryUnavailable_FallsBackToSecondaryStore(t *testing.T) {
	t.Parallel()
	primary := &stubBucketStore{
		err: fmt.Errorf("%w: redis dial: connection refused", middleware.ErrBucketStoreUnavailable),
	}
	// The fallback is a real in-process store so we exercise the
	// full code path: primary fails -> fallback admits the
	// request -> request reaches the backend.
	fallback := middleware.NewMemoryBucketStore()
	backend := &countedHandler{}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:                10,
		Burst:               5,
		Store:               primary,
		FailureModeFallback: fallback,
		FailureMode:         middleware.FailureModeClosed,
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer rl.Stop()

	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.1", "/v1/things"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=200 (fallback path)", rec.Code)
	}
	if backend.calls.Load() != 1 {
		t.Fatalf("backend.calls=%d want=1", backend.calls.Load())
	}
	if primary.calls.Load() != 1 {
		t.Fatalf("primary.calls=%d want=1", primary.calls.Load())
	}
}

// TestRateLimiter_FallbackError_FiresOnStoreError verifies that
// when BOTH primary and fallback stores fail, OnStoreError fires
// for each — operators monitoring
// `RateLimitStoreErrorsTotal{role="fallback"}` need a separate
// signal from `role="primary"` to distinguish "primary down,
// fallback healthy" (degraded but available) from "both down,
// requests failing open" (real outage).
func TestRateLimiter_FallbackError_FiresOnStoreError(t *testing.T) {
	t.Parallel()
	primary := &stubBucketStore{
		err: fmt.Errorf("%w: redis dial: connection refused", middleware.ErrBucketStoreUnavailable),
	}
	fallback := &stubBucketStore{
		err: errors.New("memory store: pool exhausted"),
	}
	backend := &countedHandler{}
	var (
		mu        sync.Mutex
		callbacks []error
	)
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:                10,
		Burst:               5,
		Store:               primary,
		FailureModeFallback: fallback,
		FailureMode:         middleware.FailureModeClosed,
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnStoreError: func(err error, _ string) {
			mu.Lock()
			callbacks = append(callbacks, err)
			mu.Unlock()
		},
	})
	defer rl.Stop()

	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.1", "/v1/things"))

	mu.Lock()
	defer mu.Unlock()
	if len(callbacks) != 2 {
		t.Fatalf("OnStoreError fired %d time(s), want 2 (primary + fallback)", len(callbacks))
	}
	// First call should be the primary error.
	if !errors.Is(callbacks[0], middleware.ErrBucketStoreUnavailable) {
		t.Errorf("callback[0] = %v, want wrap of ErrBucketStoreUnavailable", callbacks[0])
	}
	// Second call should carry the ErrFallbackStore sentinel so
	// metric labellers can split primary from fallback.
	if !errors.Is(callbacks[1], middleware.ErrFallbackStore) {
		t.Errorf("callback[1] = %v, want wrap of ErrFallbackStore", callbacks[1])
	}
}

func TestRateLimiter_PrimaryNonAvailabilityError_DoesNotFallBack(t *testing.T) {
	t.Parallel()
	// A non-availability error (e.g. a Lua script bug) MUST NOT
	// fall back — that would mask programmer errors as transient.
	// The limiter applies the configured FailureMode instead.
	primary := &stubBucketStore{
		err: errors.New("redis: lua script returned unexpected type"),
	}
	fallback := middleware.NewMemoryBucketStore()
	backend := &countedHandler{}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:                10,
		Burst:               5,
		Store:               primary,
		FailureModeFallback: fallback,
		FailureMode:         middleware.FailureModeClosed,
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer rl.Stop()

	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.1", "/v1/things"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=503 (programmer-error path)", rec.Code)
	}
	if backend.calls.Load() != 0 {
		t.Fatalf("backend.calls=%d want=0 (fallback should not run)",
			backend.calls.Load())
	}
}

func TestMemoryBucketStore_RejectsInvalid(t *testing.T) {
	t.Parallel()
	store := middleware.NewMemoryBucketStore()
	cases := []struct {
		name  string
		key   string
		rate  float64
		burst int
	}{
		{"zero rate", "k", 0, 5},
		{"negative rate", "k", -1, 5},
		{"zero burst", "k", 10, 0},
		{"negative burst", "k", 10, -1},
		{"empty key", "", 10, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := store.Take(context.Background(), tc.key, tc.rate, tc.burst)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestMemoryBucketStore_BurstThenRefill(t *testing.T) {
	t.Parallel()
	store := middleware.NewMemoryBucketStore()
	ctx := context.Background()
	// Drain the burst.
	for i := 0; i < 5; i++ {
		allowed, _, err := store.Take(ctx, "client-a", 10, 5)
		if err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("take %d: expected allowed", i)
		}
	}
	// 6th must be rejected with a positive retry-after.
	allowed, retry, err := store.Take(ctx, "client-a", 10, 5)
	if err != nil {
		t.Fatalf("6th take: %v", err)
	}
	if allowed {
		t.Fatalf("6th take should be denied")
	}
	if retry <= 0 || retry > time.Second {
		t.Fatalf("retry-after=%v outside (0, 1s]", retry)
	}
}
