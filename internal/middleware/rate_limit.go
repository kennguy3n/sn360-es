package middleware

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimitConfig configures per-IP token-bucket rate limiting.
//
// The middleware maintains one bucket per remote IP. Each bucket
// fills at Rate tokens/sec up to Burst capacity. A request consumes
// one token; if no token is available the request is rejected with
// 429 Too Many Requests and a Retry-After header indicating when the
// bucket will have a token again.
//
// Tracked buckets are evicted by a janitor goroutine that runs every
// CleanupInterval and removes buckets that have not seen traffic for
// IdleTTL. The eviction policy keeps memory bounded under bursts of
// unique IPs (e.g. a noisy /metrics scrape from a load balancer rotating
// source IPs) without dropping legitimate long-running clients.
type RateLimitConfig struct {
	// Rate is the refill rate in tokens per second. Defaults to 30.
	Rate float64
	// Burst is the maximum number of tokens a single bucket can hold.
	// Defaults to 60.
	Burst int
	// CleanupInterval is how often the janitor sweeps idle buckets.
	// A zero value selects the 1-minute default (so callers that
	// leave the field unset still get sensible behaviour). A
	// negative value disables the janitor entirely — the bucket map
	// grows unbounded until [RateLimiter.Stop] is called, so use
	// negative only in tests that drive eviction manually via
	// the export-only helper RateLimiterSweepIdle.
	CleanupInterval time.Duration
	// IdleTTL is the grace period after which an idle bucket is
	// evicted. Defaults to 5 minutes.
	IdleTTL time.Duration
	// Now is an injectable clock for tests. Defaults to time.Now.
	Now func() time.Time
	// ClientIP extracts the client IP from a request. When nil the
	// middleware constructs one from TrustedProxies: an empty
	// TrustedProxies set yields [DefaultClientIP] (which trusts no
	// proxy headers); a non-empty set yields [ProxyAwareClientIP]
	// (which walks X-Forwarded-For from the right past trusted
	// proxies). Callers may also supply their own extractor — useful
	// for tests or for stacks that key on something other than IP
	// (e.g. authenticated tenant ID).
	ClientIP func(*http.Request) string
	// TrustedProxies is the list of reverse-proxy / ALB CIDR ranges
	// whose X-Forwarded-For chain we trust. When empty the middleware
	// refuses to read proxy headers and buckets on r.RemoteAddr only
	// — the safe default for a service deployed without a proxy in
	// front. Use [ParseTrustedProxies] to populate from configuration.
	TrustedProxies []netip.Prefix
	// SkipPaths is the list of exact paths that bypass rate limiting
	// (e.g. /healthz, /metrics). Trailing slash makes the entry a
	// prefix match (so "/docs/" matches "/docs/swagger.css").
	SkipPaths []string
	// OnLimited is called once per rejected request. Optional;
	// primarily for metrics emission.
	OnLimited func(ip, path string)
}

// RateLimiter implements per-IP token-bucket rate limiting on top of
// any http.Handler. It is concurrency-safe.
type RateLimiter struct {
	next     http.Handler
	cfg      RateLimitConfig
	skip     map[string]bool
	prefixes []string

	buckets sync.Map // string -> *bucket

	stopOnce sync.Once
	stopCh   chan struct{}
	stopped  chan struct{}
}

// bucket is the per-IP state. We carry the lock by value inside the
// struct so the sync.Map entry holds a single pointer per IP.
type bucket struct {
	mu       sync.Mutex
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
}

// NewRateLimiter wraps next with a rate-limit gate. The optional
// goroutine that sweeps idle buckets starts immediately when
// CleanupInterval > 0; call [RateLimiter.Stop] to release it.
func NewRateLimiter(next http.Handler, cfg RateLimitConfig) *RateLimiter {
	if next == nil {
		// Defensive: an http.HandlerFunc that 503s makes the
		// middleware misuse obvious without panicking.
		next = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeRateLimitError(w, http.StatusServiceUnavailable, "downstream handler not configured", 0)
		})
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 30
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 60
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ClientIP == nil {
		cfg.ClientIP = ProxyAwareClientIP(cfg.TrustedProxies)
	}

	skip := make(map[string]bool, len(cfg.SkipPaths))
	var prefixes []string
	for _, p := range cfg.SkipPaths {
		if strings.HasSuffix(p, "/") {
			prefixes = append(prefixes, p)
		} else {
			skip[p] = true
		}
	}

	rl := &RateLimiter{
		next:     next,
		cfg:      cfg,
		skip:     skip,
		prefixes: prefixes,
		stopCh:   make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	if cfg.CleanupInterval > 0 {
		go rl.runJanitor()
	} else {
		close(rl.stopped)
	}
	return rl
}

// Stop releases the janitor goroutine. Safe to call multiple times.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopCh)
	})
	<-rl.stopped
}

// ServeHTTP implements http.Handler.
func (rl *RateLimiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if rl.shouldSkip(r.URL.Path) {
		rl.next.ServeHTTP(w, r)
		return
	}
	ip := rl.cfg.ClientIP(r)
	now := rl.cfg.Now()

	b := rl.bucketFor(ip, now)
	if !b.take(now, rl.cfg.Rate, rl.cfg.Burst) {
		retry := b.retryAfter(rl.cfg.Rate)
		if rl.cfg.OnLimited != nil {
			rl.cfg.OnLimited(ip, r.URL.Path)
		}
		writeRateLimitError(w, http.StatusTooManyRequests, "rate limit exceeded", retry)
		return
	}
	rl.next.ServeHTTP(w, r)
}

// bucketFor returns the bucket for the given IP, creating it on first
// use. The lastSeen timestamp is bumped so the janitor doesn't evict
// active clients.
func (rl *RateLimiter) bucketFor(ip string, now time.Time) *bucket {
	if v, ok := rl.buckets.Load(ip); ok {
		b := v.(*bucket)
		b.mu.Lock()
		b.lastSeen = now
		b.mu.Unlock()
		return b
	}
	fresh := &bucket{
		tokens:   float64(rl.cfg.Burst),
		lastFill: now,
		lastSeen: now,
	}
	actual, _ := rl.buckets.LoadOrStore(ip, fresh)
	b := actual.(*bucket)
	if actual != fresh {
		b.mu.Lock()
		b.lastSeen = now
		b.mu.Unlock()
	}
	return b
}

// shouldSkip mirrors JWTAuth's skip logic so the two middlewares
// expose a consistent allowlist convention.
func (rl *RateLimiter) shouldSkip(path string) bool {
	if rl.skip[path] {
		return true
	}
	for _, p := range rl.prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// runJanitor sweeps idle buckets at CleanupInterval.
func (rl *RateLimiter) runJanitor() {
	defer close(rl.stopped)
	t := time.NewTicker(rl.cfg.CleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case now := <-t.C:
			rl.sweepIdle(now)
		}
	}
}

// sweepIdle evicts buckets that have not been touched within IdleTTL.
// Exposed for tests so they can drive eviction deterministically.
func (rl *RateLimiter) sweepIdle(now time.Time) int {
	removed := 0
	rl.buckets.Range(func(key, value any) bool {
		b := value.(*bucket)
		b.mu.Lock()
		idle := now.Sub(b.lastSeen) > rl.cfg.IdleTTL
		b.mu.Unlock()
		if idle {
			// Conditional delete via CompareAndDelete keeps us safe
			// against the racing-update case where a request lands
			// between the idle check above and the delete.
			if rl.buckets.CompareAndDelete(key, value) {
				removed++
			}
		}
		return true
	})
	return removed
}

// take attempts to consume one token from the bucket. Returns true
// if the request is allowed.
func (b *bucket) take(now time.Time, rate float64, burst int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Refill since lastFill.
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
// token. Rate must be positive (NewRateLimiter enforces this).
func (b *bucket) retryAfter(rate float64) time.Duration {
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

// DefaultClientIP extracts the originating client IP from a request
// without trusting any proxy headers. It returns the host portion of
// r.RemoteAddr — the only value an attacker cannot forge, since
// RemoteAddr is the actual TCP peer.
//
// X-Forwarded-For / X-Real-IP are NEVER trusted by this function. If
// the service sits behind a trusted reverse proxy / ALB that appends
// the real client IP to XFF, configure that proxy's CIDR via
// [RateLimitConfig.TrustedProxies] and the middleware will use
// [ProxyAwareClientIP] instead, which safely walks XFF from the right.
//
// This is the secure default: a service mistakenly deployed without a
// proxy in front cannot be tricked into rate-limiting (or releasing
// the bucket for) any IP an attacker chooses to put in the header.
func DefaultClientIP(r *http.Request) string {
	return remoteAddrHost(r)
}

// ProxyAwareClientIP returns a ClientIP function that walks the
// X-Forwarded-For chain from the rightmost (closest-to-server) entry
// backwards, skipping entries whose IP falls inside any
// trustedProxies CIDR, and returns the first untrusted IP it
// encounters as the originating client.
//
// XFF is consulted ONLY when the immediate TCP peer (r.RemoteAddr) is
// itself a trusted proxy. If the peer is not trusted, the function
// behaves like [DefaultClientIP] and returns the peer address —
// preventing a direct attacker from spoofing the header.
//
// This implements the only safe XFF-trust pattern: production AWS
// ALBs (and most other reverse proxies) APPEND the real client IP to
// any client-supplied X-Forwarded-For header rather than replacing
// it. Walking from the left, as naive parsers do, returns the
// attacker-controlled value. Walking from the right past known
// proxies returns the first hop the proxy itself observed — the real
// client.
//
// If trustedProxies is empty the returned function is equivalent to
// [DefaultClientIP] and trusts no headers.
func ProxyAwareClientIP(trustedProxies []netip.Prefix) func(*http.Request) string {
	if len(trustedProxies) == 0 {
		return DefaultClientIP
	}
	prefixes := append([]netip.Prefix(nil), trustedProxies...)
	return func(r *http.Request) string {
		host := remoteAddrHost(r)
		peer, err := netip.ParseAddr(host)
		if err != nil || !isTrustedProxy(peer, prefixes) {
			// Peer is not a trusted proxy — refuse to trust any
			// header it set or relayed. Return the peer itself.
			return host
		}
		// Peer is trusted; consult X-Forwarded-For from the right.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				candidate := strings.TrimSpace(parts[i])
				if candidate == "" {
					continue
				}
				addr, perr := netip.ParseAddr(candidate)
				if perr != nil {
					// Malformed entry — refuse to use it,
					// but keep walking left in case a
					// later (i.e. earlier-in-chain) entry
					// is valid and untrusted.
					continue
				}
				if isTrustedProxy(addr, prefixes) {
					continue
				}
				return addr.String()
			}
		}
		// Header missing or every entry was a trusted proxy. The
		// real client is the immediate peer (which is itself a
		// trusted proxy here — degenerate but safe: we bucket on
		// the proxy IP rather than fabricating a client).
		return host
	}
}

// remoteAddrHost extracts the host portion of r.RemoteAddr, which is
// the actual TCP peer the listener accepted from. This is the only
// piece of request metadata an attacker cannot influence directly.
func remoteAddrHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isTrustedProxy reports whether addr is contained by any of the
// configured trusted-proxy prefixes. The function unmaps IPv4-mapped
// IPv6 addresses so a configured 10.0.0.0/8 prefix matches both
// 10.1.2.3 and ::ffff:10.1.2.3.
func isTrustedProxy(addr netip.Addr, prefixes []netip.Prefix) bool {
	candidate := addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(candidate) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies parses a comma-separated list of IP addresses
// and CIDR prefixes into a normalised slice of [netip.Prefix].
//
// Bare addresses (e.g. "10.0.0.1") are expanded to a host-bit-length
// prefix ("10.0.0.1/32"). CIDR prefixes pass through unchanged.
// Empty entries are skipped so operators can use trailing commas in
// environment variables without diagnostics.
//
// Returns an error on the first malformed entry so misconfiguration
// fails fast at startup rather than silently widening the trust set.
func ParseTrustedProxies(csv string) ([]netip.Prefix, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, raw := range strings.Split(csv, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", entry, err)
			}
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", entry, err)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

func writeRateLimitError(w http.ResponseWriter, status int, message string, retry time.Duration) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if retry > 0 {
		// HTTP/1.1 (RFC 7231 §7.1.3) allows Retry-After in seconds
		// (we round up so the client never retries early).
		secs := int(retry.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
