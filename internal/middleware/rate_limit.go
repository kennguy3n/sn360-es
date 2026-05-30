package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BucketStore is the storage-agnostic interface a [RateLimiter]
// consults to decide whether a request is allowed. Implementations
// must be concurrency-safe — the middleware calls Take from any
// number of goroutines on hot paths.
//
// Two implementations live in this package: the default in-memory
// store (memoryBucketStore, used when RateLimitConfig.Store is nil)
// and a Redis adapter (NewRedisBucketStore, used to share token
// state across replicas). Tests may inject a third implementation
// directly via RateLimitConfig.Store.
//
// Contract:
//
//   - Take consumes one token from the bucket identified by
//     clientKey at the given rate / burst. Returns allowed=true if
//     the request may proceed; allowed=false plus a positive
//     retryAfter when the bucket is empty. An error must be returned
//     only for truly exceptional conditions (Redis hard-down, etc.)
//     — empty-bucket is a normal (allowed=false) result, not an
//     error.
//   - Implementations must apply refill / TTL atomically so two
//     concurrent Takes against the same clientKey cannot both
//     succeed if only one token is available.
//   - rate and burst may change between calls (e.g. per-tenant
//     limits) — Take must validate every call rather than assuming
//     they were checked at construction.
//   - Eviction is the implementation's responsibility — the
//     RateLimiter does NOT track per-client state outside the
//     store. Implementations MUST either evict idle entries
//     themselves (e.g. Redis via PEXPIRE) OR implement
//     [IdleSweeper] so the RateLimiter's janitor can call them.
//     A custom in-process store that does neither will leak
//     memory on every unique clientKey it ever sees; the
//     RateLimiter logs a warning at construction time when a
//     custom store is wired as [RateLimitConfig.FailureModeFallback]
//     without implementing IdleSweeper, but cannot detect the
//     same gap on the primary [RateLimitConfig.Store] (Redis
//     stores are the typical primary and do not need
//     IdleSweeper).
type BucketStore interface {
	Take(ctx context.Context, clientKey string, rate float64, burst int) (allowed bool, retryAfter time.Duration, err error)
}

// ErrBucketStoreUnavailable is returned by Take when the backing
// store is hard-down (e.g. Redis network partition). The middleware
// applies the configured FailureMode to decide whether to allow or
// deny the request in this state.
var ErrBucketStoreUnavailable = errors.New("rate-limit: bucket store unavailable")

// ErrFallbackStore wraps errors from the FailureModeFallback store
// so an OnStoreError callback (which fires for BOTH primary and
// fallback failures) can distinguish them with errors.Is. The
// wrap is opt-in for metric labels — callers can ignore it and
// still see the underlying error via errors.Unwrap.
var ErrFallbackStore = errors.New("rate-limit: fallback store error")

// IdleSweeper is implemented by BucketStore implementations that
// hold per-client state in-process and need an external janitor to
// evict idle entries. The RateLimiter calls SweepIdle on the
// owned in-process store AND on any FailureModeFallback store that
// implements it, so a memory store wired as the Redis fallback
// doesn't leak entries during a Redis outage.
//
// Redis-backed stores intentionally do NOT implement this — Redis
// handles its own eviction via PEXPIRE on the per-bucket key.
//
// CONTRACT FOR CUSTOM BUCKET STORES: any in-process BucketStore
// implementation that accumulates per-client state and is wired
// as [RateLimitConfig.FailureModeFallback] MUST implement this
// interface. The RateLimiter's janitor uses an interface probe
// (cfg.FailureModeFallback.(IdleSweeper)) to decide whether to
// run; a fallback that does not satisfy IdleSweeper will silently
// accumulate entries during every Redis outage until the process
// restarts. A warning is logged at NewRateLimiter time when this
// gap is detected so misconfiguration surfaces operationally
// instead of as an OOMKill weeks later.
//
// Returns the number of entries evicted in this sweep, used by
// the RateLimiter for janitor metrics. May return 0 (no idle
// entries) without error.
type IdleSweeper interface {
	SweepIdle(now time.Time, idleTTL time.Duration) int
}

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
	// Store is the underlying [BucketStore] backing the limiter.
	// When nil the middleware builds a default in-process
	// memoryBucketStore — preserving the single-replica behaviour
	// for callers that have not migrated to the Redis-backed store.
	// Set Store to a [redisBucketStore] (via [NewRedisBucketStore])
	// to share token state across every replica that points at the
	// same Redis — that is the configuration required for the
	// documented cluster-wide rate to actually hold.
	Store BucketStore
	// FailureMode controls how the middleware behaves when Store.Take
	// returns [ErrBucketStoreUnavailable] (e.g. Redis hard-down).
	// Defaults to FailureModeOpen for the HTTP-edge use case: a
	// rate-limiter failure should not bring the whole API down. Set
	// to FailureModeClosed for endpoints where an abusive client
	// must NOT slip through even at the cost of availability.
	FailureMode FailureMode
	// FailureModeFallback, when non-nil, is consulted whenever
	// Store.Take returns [ErrBucketStoreUnavailable] regardless of
	// FailureMode. Wiring a memoryBucketStore here gives the
	// limiter a soft-fall path: Redis hard-down degrades to per-
	// replica counting (less correct, still safe) instead of
	// fail-open or fail-closed. Optional.
	FailureModeFallback BucketStore
	// OnStoreError is called once per Take error. Use to emit
	// metrics / log Redis outages without coupling the middleware
	// to a particular logger. Optional.
	OnStoreError func(err error, clientKey string)
	// Logger receives a structured slog event each time the
	// middleware falls back from the primary Store to
	// FailureModeFallback. When nil the middleware logs via
	// slog.Default(). Set to slog.New(slog.DiscardHandler) in tests
	// that don't want the noise.
	Logger *slog.Logger
	// CleanupInterval is how often the janitor sweeps idle buckets.
	// A zero value selects the 1-minute default (so callers that
	// leave the field unset still get sensible behaviour). A
	// negative value disables the janitor entirely — the bucket map
	// grows unbounded until [RateLimiter.Stop] is called, so use
	// negative only in tests that drive eviction manually via
	// the export-only helper RateLimiterSweepIdle.
	//
	// Only applies to the default in-process store; the Redis store
	// relies on PEXPIRE for eviction.
	CleanupInterval time.Duration
	// IdleTTL is the grace period after which an idle bucket is
	// evicted. Defaults to 5 minutes. Only applies to the default
	// in-process store.
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

// FailureMode describes how the middleware reacts to a hard
// Store.Take failure (e.g. Redis network partition).
type FailureMode int

const (
	// FailureModeOpen allows the request through when the bucket
	// store is unavailable. This is the default — a stuck
	// rate-limiter that 503s every request is usually worse than
	// a temporarily un-counted request.
	FailureModeOpen FailureMode = 0
	// FailureModeClosed rejects requests with 503 when the bucket
	// store is unavailable. Use for endpoints where an abusive
	// client must NOT slip through (e.g. password-reset, auth
	// flows) even at the cost of availability.
	FailureModeClosed FailureMode = 1
)

// RateLimiter implements rate limiting on top of any http.Handler
// using a pluggable [BucketStore]. It is concurrency-safe.
type RateLimiter struct {
	next     http.Handler
	cfg      RateLimitConfig
	logger   *slog.Logger
	skip     map[string]bool
	prefixes []string

	// store is the actively-consulted BucketStore. For the default
	// in-process configuration this points at the same
	// memoryBucketStore as memStore (memStore holds the typed
	// reference so the janitor / sweepIdle stay reachable). When
	// Store is supplied via RateLimitConfig.Store, memStore is nil
	// and the embedded janitor never starts.
	store BucketStore
	// memStore is the in-process store. Non-nil only when the
	// limiter owns it (i.e. RateLimitConfig.Store was unset). It
	// keeps the per-IP map reachable so the janitor and the test
	// helper RateLimiterSweepIdle can find it.
	memStore *memoryBucketStore

	stopOnce sync.Once
	stopCh   chan struct{}
	stopped  chan struct{}
}

// NewRateLimiter wraps next with a rate-limit gate. The optional
// goroutine that sweeps idle buckets starts immediately when
// CleanupInterval > 0 AND the limiter owns an in-process store; call
// [RateLimiter.Stop] to release it.
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

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	rl := &RateLimiter{
		next:     next,
		cfg:      cfg,
		logger:   logger,
		skip:     skip,
		prefixes: prefixes,
		stopCh:   make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	if cfg.Store != nil {
		// Caller-supplied store (typically the Redis adapter).
		// The primary store handles its own eviction (Redis
		// PEXPIRE), but if FailureModeFallback is a stateful
		// in-process store — the standard wiring for Redis +
		// memory soft-fall — the janitor MUST run so that
		// fallback's per-client map doesn't accumulate entries
		// during a Redis outage. We detect that case by probing
		// for the IdleSweeper interface.
		rl.store = cfg.Store
		_, fallbackSweeps := cfg.FailureModeFallback.(IdleSweeper)
		// Warn loudly when a non-IdleSweeper fallback is wired.
		// The probe above will silently skip the janitor for
		// that store, which means an operator who plugged in a
		// custom BucketStore without reading the interface
		// contract will only see the memory leak as an OOMKill
		// weeks into a Redis outage. Logging at construction
		// time gives them a chance to fix the misconfiguration
		// before it bites. Stays at WARN (not FATAL) because
		// some custom stores genuinely self-evict (e.g. a
		// stateless adapter that proxies to another Redis); the
		// contract documents that case as the implementer's
		// responsibility to assert.
		if cfg.FailureModeFallback != nil && !fallbackSweeps {
			logger.Warn(
				"rate-limit: FailureModeFallback does not implement IdleSweeper; "+
					"per-client entries may leak during primary-store outages. "+
					"Custom BucketStore implementations wired as fallback must implement "+
					"IdleSweeper or guarantee self-eviction (see BucketStore docstring).",
				slog.String("fallback_type", fmt.Sprintf("%T", cfg.FailureModeFallback)),
			)
		}
		if fallbackSweeps && cfg.CleanupInterval > 0 {
			go rl.runJanitor()
		} else {
			close(rl.stopped)
		}
	} else {
		// Default in-process store, owned by this limiter.
		mem := newMemoryBucketStore(cfg.Now)
		rl.memStore = mem
		rl.store = mem
		if cfg.CleanupInterval > 0 {
			go rl.runJanitor()
		} else {
			close(rl.stopped)
		}
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
	allowed, retry, err := rl.take(r.Context(), ip)
	if err != nil {
		rl.handleStoreError(w, r, ip, err)
		return
	}
	if !allowed {
		if rl.cfg.OnLimited != nil {
			rl.cfg.OnLimited(ip, r.URL.Path)
		}
		writeRateLimitError(w, http.StatusTooManyRequests, "rate limit exceeded", retry)
		return
	}
	rl.next.ServeHTTP(w, r)
}

// take consults the configured store, falling back to
// FailureModeFallback (if set) when the primary store is hard-down.
// The fallback path preserves the per-replica counting behaviour for
// callers that wired Redis as the primary store: a Redis outage
// degrades correctness (back to per-replica buckets) but not
// availability.
//
// OnStoreError fires for the primary store error AND for any
// fallback-store error — the fallback path is also load-bearing
// (a dead Redis with a misconfigured / dead memory fallback is a
// real failure mode worth alerting on) and operators monitoring
// the RateLimitStoreErrorsTotal metric need both signals to
// distinguish "primary degraded, fallback healthy" from "both
// dead, requests are failing open".
func (rl *RateLimiter) take(ctx context.Context, ip string) (bool, time.Duration, error) {
	allowed, retry, err := rl.store.Take(ctx, ip, rl.cfg.Rate, rl.cfg.Burst)
	if err == nil {
		return allowed, retry, nil
	}
	if rl.cfg.OnStoreError != nil {
		rl.cfg.OnStoreError(err, ip)
	}
	if rl.cfg.FailureModeFallback != nil && errors.Is(err, ErrBucketStoreUnavailable) {
		rl.logger.WarnContext(ctx, "rate-limit: primary store unavailable, using fallback",
			slog.String("client_key", ip),
			slog.Any("error", err))
		fbAllowed, fbRetry, fbErr := rl.cfg.FailureModeFallback.Take(ctx, ip, rl.cfg.Rate, rl.cfg.Burst)
		if fbErr != nil && rl.cfg.OnStoreError != nil {
			// Wrap so the metric callback can distinguish primary
			// vs fallback by errors.Is(err, ErrFallbackStore) if
			// it wants to. The wrap doesn't change the
			// availability semantics — the request still fails
			// through to handleStoreError below.
			rl.cfg.OnStoreError(fmt.Errorf("%w: %v", ErrFallbackStore, fbErr), ip)
		}
		return fbAllowed, fbRetry, fbErr
	}
	return false, 0, err
}

// handleStoreError emits the configured failure-mode response when
// the primary store (and its fallback, if any) cannot answer.
func (rl *RateLimiter) handleStoreError(w http.ResponseWriter, r *http.Request, ip string, err error) {
	rl.logger.ErrorContext(r.Context(), "rate-limit: bucket store error",
		slog.String("client_key", ip),
		slog.String("path", r.URL.Path),
		slog.Any("error", err))
	switch rl.cfg.FailureMode {
	case FailureModeClosed:
		writeRateLimitError(w, http.StatusServiceUnavailable,
			"rate limiter unavailable", time.Second)
	default:
		// FailureModeOpen — let the request through so a
		// rate-limiter outage cannot 503 the entire API. The
		// error is already logged and any caller-supplied metric
		// callback (OnStoreError) has fired.
		rl.next.ServeHTTP(w, r)
	}
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

// runJanitor sweeps idle buckets at CleanupInterval. Only the
// default in-process store needs this; the Redis store relies on
// PEXPIRE.
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
//
// Sweeps two stores when wired:
//
//  1. rl.memStore — the owned in-process store (when the primary
//     is the default memory store). Same behaviour as before.
//  2. rl.cfg.FailureModeFallback — when it implements
//     [IdleSweeper] (i.e. it's a memory store wired as the
//     soft-fall behind Redis). Without this, the fallback map
//     grows unboundedly across repeated Redis outages — each
//     unique IP that hits the fallback path adds one entry that
//     never gets evicted.
//
// Returns the total number of entries removed across both stores.
func (rl *RateLimiter) sweepIdle(now time.Time) int {
	removed := 0
	if rl.memStore != nil {
		removed += rl.memStore.sweepIdle(now, rl.cfg.IdleTTL)
	}
	if sweeper, ok := rl.cfg.FailureModeFallback.(IdleSweeper); ok {
		removed += sweeper.SweepIdle(now, rl.cfg.IdleTTL)
	}
	return removed
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
		// HTTP/1.1 (RFC 7231 §7.1.3) allows Retry-After in seconds.
		// Round UP to the next whole second so a client respecting
		// the header never retries before the bucket actually has a
		// token — `int(retry.Seconds())` would truncate 1.5s to 1s
		// and invite a doomed retry one tick before refill.
		ms := retry.Milliseconds()
		secs := int((ms + 999) / 1000)
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
