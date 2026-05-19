package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/middleware"
)

// stubClock returns a controllable time source. The middleware uses it
// to refill buckets — tests advance time explicitly so we can observe
// the bucket recovery deterministically.
type stubClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stubClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stubClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newRequest(t *testing.T, ip, path string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = ip + ":54321"
	return r
}

// counted backend records every call. We assert on it rather than the
// recorder status to catch the case where the limiter passes through
// AND writes a 429 (which would be a bug).
type countedHandler struct{ calls atomic.Int64 }

func (c *countedHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	c.calls.Add(1)
	w.WriteHeader(http.StatusOK)
}

func TestRateLimiter_NormalTrafficPasses(t *testing.T) {
	t.Parallel()
	clk := &stubClock{now: time.Unix(1_700_000_000, 0)}
	backend := &countedHandler{}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:    10,
		Burst:   5,
		Now:     clk.Now,
		IdleTTL: time.Minute,
	})
	t.Cleanup(rl.Stop)

	// Send 5 requests — below the burst, all should pass.
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		rl.ServeHTTP(rec, newRequest(t, "10.0.0.1", "/v1/predict/open"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i, rec.Code)
		}
	}
	if got := backend.calls.Load(); got != 5 {
		t.Fatalf("backend invoked %d times, want 5", got)
	}
}

func TestRateLimiter_BurstReturns429WithRetryAfter(t *testing.T) {
	t.Parallel()
	clk := &stubClock{now: time.Unix(1_700_000_000, 0)}
	backend := &countedHandler{}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:    2,
		Burst:   3,
		Now:     clk.Now,
		IdleTTL: time.Minute,
	})
	t.Cleanup(rl.Stop)

	// Drain the burst.
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		rl.ServeHTTP(rec, newRequest(t, "10.0.0.2", "/"))
		if rec.Code != http.StatusOK {
			t.Fatalf("burst request %d: want 200, got %d", i, rec.Code)
		}
	}
	// 4th request: should be limited.
	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.2", "/"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rec.Code)
	}
	retry := rec.Header().Get("Retry-After")
	if retry == "" {
		t.Fatal("Retry-After header missing")
	}
	secs, err := strconv.Atoi(retry)
	if err != nil || secs < 1 {
		t.Fatalf("Retry-After=%q parse=%v secs=%d", retry, err, secs)
	}
	if got := backend.calls.Load(); got != 3 {
		t.Fatalf("backend should only have seen 3 calls (burst), got %d", got)
	}

	// After the bucket refills, the next request should succeed.
	clk.advance(time.Second) // adds 2 tokens
	rec = httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.2", "/"))
	if rec.Code != http.StatusOK {
		t.Fatalf("after refill: want 200, got %d", rec.Code)
	}
}

func TestRateLimiter_IndependentBucketsPerIP(t *testing.T) {
	t.Parallel()
	clk := &stubClock{now: time.Unix(1_700_000_000, 0)}
	backend := &countedHandler{}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:    1,
		Burst:   2,
		Now:     clk.Now,
		IdleTTL: time.Minute,
	})
	t.Cleanup(rl.Stop)

	// Drain IP A.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		rl.ServeHTTP(rec, newRequest(t, "10.0.0.10", "/"))
		if rec.Code != http.StatusOK {
			t.Fatalf("A burst %d: %d", i, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.10", "/"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("A exhaustion: want 429, got %d", rec.Code)
	}

	// IP B still has a full bucket.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		rl.ServeHTTP(rec, newRequest(t, "10.0.0.11", "/"))
		if rec.Code != http.StatusOK {
			t.Fatalf("B burst %d: %d (A's exhaustion leaked into B)", i, rec.Code)
		}
	}
}

func TestRateLimiter_SkipPathsBypass(t *testing.T) {
	t.Parallel()
	clk := &stubClock{now: time.Unix(1_700_000_000, 0)}
	backend := &countedHandler{}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:      1,
		Burst:     1,
		Now:       clk.Now,
		IdleTTL:   time.Minute,
		SkipPaths: []string{"/healthz", "/docs/"},
	})
	t.Cleanup(rl.Stop)

	// 100 calls to a skipped path must all succeed regardless of the
	// tiny burst because the limiter never even touches the bucket.
	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		rl.ServeHTTP(rec, newRequest(t, "10.0.0.99", "/healthz"))
		if rec.Code != http.StatusOK {
			t.Fatalf("/healthz %d: want 200, got %d", i, rec.Code)
		}
	}
	// Prefix-style skip path also bypasses.
	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		rl.ServeHTTP(rec, newRequest(t, "10.0.0.99", "/docs/swagger.css"))
		if rec.Code != http.StatusOK {
			t.Fatalf("/docs/swagger.css %d: want 200, got %d", i, rec.Code)
		}
	}
}

func TestRateLimiter_IdleSweepEvictsBuckets(t *testing.T) {
	t.Parallel()
	clk := &stubClock{now: time.Unix(1_700_000_000, 0)}
	backend := &countedHandler{}
	// Disable the auto-janitor; we drive sweepIdle directly via the
	// exported behaviour (an idle window passing then a fresh request
	// landing in a new bucket). This keeps the test deterministic
	// without sleeping.
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:            5,
		Burst:           5,
		Now:             clk.Now,
		CleanupInterval: time.Hour, // effectively no auto-janitor during this test
		IdleTTL:         time.Second,
	})
	t.Cleanup(rl.Stop)

	// Populate a bucket for IP A.
	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.42", "/"))
	if rec.Code != http.StatusOK {
		t.Fatalf("seed request: want 200, got %d", rec.Code)
	}

	// Advance past the idle TTL and trigger a manual sweep via the
	// exported behaviour: a follow-up request for a different IP
	// after time has advanced lets us observe that the old bucket
	// was evicted (it would otherwise show the previously-decremented
	// token count). We confirm via the public sweep API.
	clk.advance(2 * time.Second)
	if removed := middleware.RateLimiterSweepIdle(rl, clk.Now()); removed != 1 {
		t.Fatalf("sweep removed %d, want 1", removed)
	}
}

func TestRateLimiter_OnLimitedCallback(t *testing.T) {
	t.Parallel()
	clk := &stubClock{now: time.Unix(1_700_000_000, 0)}
	backend := &countedHandler{}
	var captured struct {
		mu     sync.Mutex
		ips    []string
		paths  []string
		called int
	}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:    1,
		Burst:   1,
		Now:     clk.Now,
		IdleTTL: time.Minute,
		OnLimited: func(ip, path string) {
			captured.mu.Lock()
			defer captured.mu.Unlock()
			captured.called++
			captured.ips = append(captured.ips, ip)
			captured.paths = append(captured.paths, path)
		},
	})
	t.Cleanup(rl.Stop)

	// Drain.
	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.7", "/v1/escalation/resolve"))
	if rec.Code != http.StatusOK {
		t.Fatalf("seed: %d", rec.Code)
	}
	// 429.
	rec = httptest.NewRecorder()
	rl.ServeHTTP(rec, newRequest(t, "10.0.0.7", "/v1/escalation/resolve"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rec.Code)
	}
	captured.mu.Lock()
	defer captured.mu.Unlock()
	if captured.called != 1 || captured.ips[0] != "10.0.0.7" || captured.paths[0] != "/v1/escalation/resolve" {
		t.Fatalf("OnLimited not invoked as expected: called=%d ips=%v paths=%v",
			captured.called, captured.ips, captured.paths)
	}
}

func TestRateLimiter_XForwardedForRespected(t *testing.T) {
	t.Parallel()
	clk := &stubClock{now: time.Unix(1_700_000_000, 0)}
	backend := &countedHandler{}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:    1,
		Burst:   1,
		Now:     clk.Now,
		IdleTTL: time.Minute,
	})
	t.Cleanup(rl.Stop)

	// Two requests from the same ALB-source RemoteAddr but DIFFERENT
	// XFF client IPs must NOT share a bucket.
	r1 := newRequest(t, "10.0.0.1", "/")
	r1.Header.Set("X-Forwarded-For", "203.0.113.5")
	r2 := newRequest(t, "10.0.0.1", "/")
	r2.Header.Set("X-Forwarded-For", "203.0.113.6")

	rec1, rec2 := httptest.NewRecorder(), httptest.NewRecorder()
	rl.ServeHTTP(rec1, r1)
	rl.ServeHTTP(rec2, r2)
	if rec1.Code != http.StatusOK || rec2.Code != http.StatusOK {
		t.Fatalf("XFF bucket isolation broken: %d %d", rec1.Code, rec2.Code)
	}

	// A second request from 203.0.113.5 should be limited because
	// burst=1 and the first one already drained it.
	rec3 := httptest.NewRecorder()
	rl.ServeHTTP(rec3, r1)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("XFF=203.0.113.5 second call: want 429, got %d", rec3.Code)
	}
}
