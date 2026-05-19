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

// TestRateLimiter_XForwardedForIgnoredByDefault confirms the secure
// default: when no trusted-proxy CIDRs are configured, the middleware
// refuses to use X-Forwarded-For — preventing a direct attacker from
// either evading their own bucket (rotating XFF on each request) or
// exhausting an arbitrary IP's bucket (planting a victim's IP in
// XFF). Two requests from the same RemoteAddr with different XFF
// values share a single bucket keyed on RemoteAddr.
func TestRateLimiter_XForwardedForIgnoredByDefault(t *testing.T) {
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

	r1 := newRequest(t, "203.0.113.10", "/")
	r1.Header.Set("X-Forwarded-For", "10.20.30.40")
	r2 := newRequest(t, "203.0.113.10", "/")
	r2.Header.Set("X-Forwarded-For", "10.20.30.41")

	rec1 := httptest.NewRecorder()
	rl.ServeHTTP(rec1, r1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	rl.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request from same RemoteAddr with rotated XFF: want 429, got %d (attacker can evade bucket by rotating XFF)", rec2.Code)
	}
}

// TestRateLimiter_TrustedProxyXFFFromRight verifies the proxy-aware
// extractor walks XFF from the right past trusted-proxy IPs and
// returns the first untrusted IP it finds. This is the exact failure
// mode the leftmost-XFF parser had: when an AWS-style ALB appends the
// real client IP to whatever the client supplied, the leftmost entry
// is attacker-controlled and must NEVER be returned as the bucket key.
func TestRateLimiter_TrustedProxyXFFFromRight(t *testing.T) {
	t.Parallel()
	clk := &stubClock{now: time.Unix(1_700_000_000, 0)}
	backend := &countedHandler{}
	trusted, err := middleware.ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:           1,
		Burst:          1,
		Now:            clk.Now,
		IdleTTL:        time.Minute,
		TrustedProxies: trusted,
	})
	t.Cleanup(rl.Stop)

	// Peer is a trusted proxy (10.0.0.5). Both requests come from
	// the SAME real client 203.0.113.5 (whose IP the ALB appends),
	// but the attacker has rotated the leftmost XFF entry hoping to
	// evade their bucket. The rightmost-untrusted walk must collapse
	// both into the same bucket keyed on 203.0.113.5.
	r1 := newRequest(t, "10.0.0.5", "/")
	r1.Header.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.5")
	r2 := newRequest(t, "10.0.0.5", "/")
	r2.Header.Set("X-Forwarded-For", "198.51.100.42, 203.0.113.5")

	rec1 := httptest.NewRecorder()
	rl.ServeHTTP(rec1, r1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", rec1.Code)
	}
	rec2 := httptest.NewRecorder()
	rl.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request from same real client with rotated leftmost XFF: want 429, got %d (attacker can evade rate limit by spinning the leftmost XFF entry)", rec2.Code)
	}

	// A third request from a DIFFERENT real client (different
	// rightmost-untrusted IP) must still pass through — confirming
	// the rightmost-walk produces stable, per-real-client buckets
	// even though the proxy chain is identical.
	r3 := newRequest(t, "10.0.0.5", "/")
	r3.Header.Set("X-Forwarded-For", "198.51.100.42, 203.0.113.6")
	rec3 := httptest.NewRecorder()
	rl.ServeHTTP(rec3, r3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("request from different real client 203.0.113.6: want 200, got %d (rightmost-walk collapsed unrelated clients into one bucket)", rec3.Code)
	}
}

// TestRateLimiter_UntrustedPeerIgnoresXFF guards the half of the
// trust model that catches a direct attacker spoofing XFF when the
// service is exposed to the public internet without (or alongside) a
// proxy. If the peer itself is not in the trusted-proxy set, XFF must
// be ignored regardless of what the trusted-proxy config says.
func TestRateLimiter_UntrustedPeerIgnoresXFF(t *testing.T) {
	t.Parallel()
	clk := &stubClock{now: time.Unix(1_700_000_000, 0)}
	backend := &countedHandler{}
	trusted, err := middleware.ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	rl := middleware.NewRateLimiter(backend, middleware.RateLimitConfig{
		Rate:           1,
		Burst:          1,
		Now:            clk.Now,
		IdleTTL:        time.Minute,
		TrustedProxies: trusted,
	})
	t.Cleanup(rl.Stop)

	// Peer 203.0.113.10 is NOT trusted. XFF is attacker-controlled.
	// Two requests with rotated XFF must share the same bucket.
	r1 := newRequest(t, "203.0.113.10", "/")
	r1.Header.Set("X-Forwarded-For", "198.51.100.1")
	r2 := newRequest(t, "203.0.113.10", "/")
	r2.Header.Set("X-Forwarded-For", "198.51.100.2")

	rec1 := httptest.NewRecorder()
	rl.ServeHTTP(rec1, r1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first: %d", rec1.Code)
	}
	rec2 := httptest.NewRecorder()
	rl.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("untrusted-peer XFF spoof bypassed bucket: want 429, got %d", rec2.Code)
	}
}

// TestParseTrustedProxies covers the configuration parser: bare
// addresses expand to host prefixes, CIDR prefixes pass through,
// empty / whitespace entries are skipped, and malformed entries fail
// fast.
func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		wantLen int
		wantErr bool
	}{
		{"", 0, false},
		{"   ", 0, false},
		{"10.0.0.0/8", 1, false},
		{"10.0.0.0/8,192.168.0.0/16", 2, false},
		{"10.0.0.1", 1, false},
		{"10.0.0.1, 10.0.0.2,", 2, false},
		{"::1", 1, false},
		{"fd00::/8", 1, false},
		{"not-an-ip", 0, true},
		{"10.0.0.0/99", 0, true},
	}
	for _, tc := range cases {
		got, err := middleware.ParseTrustedProxies(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseTrustedProxies(%q): err=%v wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && len(got) != tc.wantLen {
			t.Errorf("ParseTrustedProxies(%q): len=%d want=%d", tc.in, len(got), tc.wantLen)
		}
	}
}
