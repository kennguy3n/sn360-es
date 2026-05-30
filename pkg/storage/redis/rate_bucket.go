package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Package-level errors emitted by RateBucketStore.

// ErrInvalidRateLimit is returned when Take is called with a
// non-positive rate or burst. Caught at construction time when
// possible, but Take also validates because rate / burst can be
// per-tenant config that changes at runtime.
var ErrInvalidRateLimit = errors.New("redis: rate-bucket rate and burst must be positive")

// rateBucketLua is the atomic refill-and-take script. Keeping the
// refill, the take, and the persistence in a single Lua call avoids
// the read-modify-write race that would let two replicas each see
// `tokens=1` and both decrement to `tokens=0` (i.e. two requests pass
// even though only one token existed). KEYS[1] is the bucket key
// (typically `ratelimit:<namespace>:<client_id>`); ARGV is documented
// in RateBucketStore.Take.
//
// Storage layout per bucket: a Redis hash with two float-encoded
// fields, `tokens` (current bucket level) and `last_fill_ms` (the
// unix-millisecond timestamp at which `tokens` was last computed).
// The hash auto-expires after ttl_ms so idle clients do not balloon
// memory — same eviction semantics as the in-memory limiter's
// IdleTTL, just enforced by Redis.
//
// Returns a 2-element array {allowed, retry_after_ms}:
//   - allowed: 1 if a token was consumed, 0 if the request must be
//     rejected with 429.
//   - retry_after_ms: when allowed=0, the integer milliseconds until
//     the bucket regains exactly one token (i.e. the soonest the
//     caller could retry and succeed). 0 when allowed=1.
const rateBucketLua = `
local raw = redis.call('HMGET', KEYS[1], 'tokens', 'last_fill_ms')
local now_ms = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])

local tokens
local last_fill_ms
if raw[1] == false then
  tokens = burst
  last_fill_ms = now_ms
else
  tokens = tonumber(raw[1])
  last_fill_ms = tonumber(raw[2])
  local elapsed_ms = now_ms - last_fill_ms
  if elapsed_ms > 0 then
    tokens = tokens + (elapsed_ms / 1000.0) * rate
    if tokens > burst then
      tokens = burst
    end
    last_fill_ms = now_ms
  end
end

local allowed = 0
local retry_after_ms = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  local deficit = 1 - tokens
  retry_after_ms = math.ceil((deficit / rate) * 1000)
  if retry_after_ms < 0 then
    retry_after_ms = 0
  end
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'last_fill_ms', last_fill_ms)
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return {allowed, retry_after_ms}
`

// RateBucketStore is a Redis-backed token-bucket store shared across
// every replica that points at the same Redis. It is the cluster-wide
// counterpart to the in-memory bucket store inside
// internal/middleware/rate_limit.go — instead of each replica keeping
// its own bucket map (so N replicas = N× the documented rate), every
// replica calls the same Lua script against the same Redis hash, so
// the published rate is the cluster-wide rate.
//
// The store does not cache buckets locally: every Take is one Redis
// round-trip (a single EVALSHA / EVAL of rateBucketLua). For the
// HTTP-edge use case the extra ~1 ms is the price of correct
// cross-replica counting. Callers that want a stricter latency budget
// can place the store behind a circuit breaker that falls back to
// local counting under Redis hard-down conditions — see the wiring
// helpers in internal/middleware.
type RateBucketStore struct {
	rdb       *goredis.Client
	keyPrefix string
	// ttl is the auto-expiry written into every bucket hash. A
	// reasonable lower bound is the time it takes a fully-drained
	// bucket to refill from 0 to burst — anything sooner would
	// evict mid-refill and reset the bucket to burst, which would
	// effectively reward the abusive client by handing it `burst`
	// fresh tokens. RateBucketStore.Take computes that lower bound
	// on the fly and the configured ttl is the maximum, used only
	// when it exceeds the computed lower bound.
	ttl time.Duration
	// script is preloaded so the hot path uses EVALSHA, falling
	// back to EVAL on cache eviction.
	script *goredis.Script
	// now is injectable for tests.
	now func() time.Time
}

// RateBucketConfig wires a RateBucketStore.
type RateBucketConfig struct {
	// KeyPrefix is prepended to every bucket key. Set this to a
	// stable, deployment-scoped string so multiple services on the
	// same Redis cannot collide on the same client identifier
	// (e.g. two services both bucketing on "1.2.3.4"). Required.
	KeyPrefix string
	// TTL is the auto-expiry written on every bucket hash. Defaults
	// to 10 minutes. The effective TTL on each write is max(TTL,
	// time-to-refill-from-empty) so a drained bucket cannot be
	// reset by eviction.
	TTL time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

// NewRateBucketStore constructs a RateBucketStore. The script is
// pre-loaded so the first Take call does not pay the EVAL upload
// cost (and so a misconfigured Redis fails closed at boot, not on
// first request).
func NewRateBucketStore(ctx context.Context, c *Client, cfg RateBucketConfig) (*RateBucketStore, error) {
	if c == nil {
		return nil, errors.New("redis: rate-bucket store requires a non-nil client")
	}
	if cfg.KeyPrefix == "" {
		return nil, errors.New("redis: rate-bucket store requires a key prefix")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	script := goredis.NewScript(rateBucketLua)
	// Pre-load. On Redis Cluster Script.Load shards by hash slot —
	// for a single primary it is a single command.
	if _, err := script.Load(ctx, c.Raw()).Result(); err != nil {
		return nil, fmt.Errorf("redis: rate-bucket script load: %w", err)
	}
	return &RateBucketStore{
		rdb:       c.Raw(),
		keyPrefix: cfg.KeyPrefix,
		ttl:       cfg.TTL,
		script:    script,
		now:       cfg.Now,
	}, nil
}

// Take consumes one token from the bucket identified by clientKey at
// the configured rate/burst. Returns:
//
//   - allowed: true if a token was available and consumed; the
//     caller may serve the request.
//   - retryAfter: when allowed=false, the duration until the bucket
//     regains one token. Zero when allowed=true.
//
// Every Take is exactly one Redis round-trip via EVALSHA. The
// underlying script (rateBucketLua) atomically refills + takes +
// persists, so two replicas calling Take concurrently cannot both
// succeed when only one token is available.
//
// clientKey is the per-client identifier (IP, tenant ID, API key
// hash, …). The store concatenates the configured KeyPrefix and
// clientKey to form the Redis hash key.
func (s *RateBucketStore) Take(ctx context.Context, clientKey string, rate float64, burst int) (bool, time.Duration, error) {
	if rate <= 0 || burst <= 0 {
		return false, 0, ErrInvalidRateLimit
	}
	if clientKey == "" {
		return false, 0, errors.New("redis: rate-bucket clientKey is required")
	}
	now := s.now()
	// effective TTL: refill-from-empty time, rounded up, but at
	// least the configured ttl. Refill time = burst/rate seconds.
	refillMs := int64((float64(burst) / rate) * 1000.0)
	ttlMs := s.ttl.Milliseconds()
	if refillMs > ttlMs {
		ttlMs = refillMs
	}
	key := s.keyPrefix + ":" + clientKey
	res, err := s.script.Run(ctx, s.rdb, []string{key},
		now.UnixMilli(), rate, burst, ttlMs,
	).Result()
	if err != nil {
		return false, 0, fmt.Errorf("redis: rate-bucket take: %w", err)
	}
	allowed, retryAfter, err := parseRateBucketReply(res)
	if err != nil {
		return false, 0, err
	}
	return allowed, retryAfter, nil
}

// parseRateBucketReply normalises the Lua reply across go-redis
// versions: the script returns a 2-element table that go-redis
// decodes as []any. Older Redis builds may surface the numerics as
// strings ("1" / "0") rather than int64 — the parser tolerates
// both.
func parseRateBucketReply(res any) (bool, time.Duration, error) {
	arr, ok := res.([]any)
	if !ok || len(arr) != 2 {
		return false, 0, fmt.Errorf("redis: rate-bucket: unexpected reply shape %T", res)
	}
	allowed, err := asInt64(arr[0])
	if err != nil {
		return false, 0, fmt.Errorf("redis: rate-bucket: allowed field: %w", err)
	}
	retryMs, err := asInt64(arr[1])
	if err != nil {
		return false, 0, fmt.Errorf("redis: rate-bucket: retry-after field: %w", err)
	}
	return allowed == 1, time.Duration(retryMs) * time.Millisecond, nil
}

// asInt64 coerces an arbitrary Redis reply value to int64. Lua
// table elements arrive as int64 from go-redis when the value fits;
// floats and strings appear for legacy / mis-typed values.
func asInt64(v any) (int64, error) {
	switch t := v.(type) {
	case int64:
		return t, nil
	case int:
		return int64(t), nil
	case float64:
		return int64(t), nil
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, err
		}
		return n, nil
	default:
		return 0, fmt.Errorf("unsupported type %T", v)
	}
}

// Reset deletes the bucket for clientKey. Intended for operational
// use (e.g. an SRE clearing a bucket after a false-positive ban) and
// for tests. Not called in the request hot path.
func (s *RateBucketStore) Reset(ctx context.Context, clientKey string) error {
	if clientKey == "" {
		return errors.New("redis: rate-bucket Reset requires a clientKey")
	}
	return s.rdb.Del(ctx, s.keyPrefix+":"+clientKey).Err()
}
