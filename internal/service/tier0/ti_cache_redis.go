package tier0

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/intel"
	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

// RedisTICache caches threat-intel hash lookups in Redis.
//
// Both positive and negative results are cached. The cache layer
// sits between the gate and the IntelStore: every hash the gate
// queries is checked against Redis first; misses fall through and
// the result is written back with TTL.
//
// Negative caching matters because the dominant case in production
// is "no match" — most messages don't hit any IOC. Without a
// negative cache, every Tier 0 evaluation would hit Postgres,
// turning the gate into a per-message DB call. With it, hot domains
// (gmail.com, outlook.com, etc.) are cached for the TTL and the DB
// only sees novel hashes.
//
// Cache invalidation: the worker does NOT proactively invalidate on
// upsert. A hash that's freshly added to intel_indicators will not
// hit the cache until the existing (negative) TTL expires — at most
// CacheTTL after the upsert. The default 5-minute TTL keeps the
// staleness window tolerable while still cutting >99% of DB queries
// on a typical workload.
type RedisTICache struct {
	Client *redis.Client
	// Prefix is prepended to every Redis key. Defaults to
	// "intel:ticache:". Configurable per-deployment so tenants
	// sharing a Redis instance can scope their caches.
	Prefix string
	// TTL is the lifetime of cached entries. Default 5 minutes.
	TTL time.Duration
	// Logger receives cache-write errors. Optional.
	Logger *slog.Logger
}

// redisCacheEntry is the serialised form of a TICacheEntry. We use
// JSON because the cardinality is tiny (one row per matched
// indicator) and gob-encoding is overkill.
type redisCacheEntry struct {
	Matches []intel.MatchedIndicator `json:"matches,omitempty"`
}

// keyFor returns the namespaced Redis key for a single hash.
func (r *RedisTICache) keyFor(hash []byte) string {
	prefix := r.Prefix
	if prefix == "" {
		prefix = "intel:ticache:"
	}
	return prefix + hex.EncodeToString(hash)
}

// GetHashes implements TICache.
//
// We do not use MGET because we want each entry to report its
// presence independently — Redis MGET returns a flat array of
// (string, nil) entries and we'd have to walk twice. A pipelined
// individual GET is just as efficient on a non-cluster Redis and
// preserves the per-hash error path.
func (r *RedisTICache) GetHashes(ctx context.Context, hashes [][]byte) []TICacheEntry {
	out := make([]TICacheEntry, len(hashes))
	if r == nil || r.Client == nil {
		return out
	}
	for i, h := range hashes {
		val, ok, err := r.Client.Get(ctx, r.keyFor(h))
		if err != nil {
			r.warn("ti_cache: redis get", err)
			continue
		}
		if !ok {
			continue
		}
		var e redisCacheEntry
		if err := json.Unmarshal([]byte(val), &e); err != nil {
			r.warn("ti_cache: decode", err)
			continue
		}
		out[i] = TICacheEntry{Present: true, Matches: e.Matches}
	}
	return out
}

// SetHash implements TICache.
func (r *RedisTICache) SetHash(ctx context.Context, hash []byte, matches []intel.MatchedIndicator) {
	if r == nil || r.Client == nil {
		return
	}
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	b, err := json.Marshal(redisCacheEntry{Matches: matches})
	if err != nil {
		// json.Marshal on a slice of plain structs cannot fail
		// short of an OOM; the guard is defensive.
		r.warn("ti_cache: encode", err)
		return
	}
	if err := r.Client.Set(ctx, r.keyFor(hash), string(b), ttl); err != nil {
		r.warn("ti_cache: redis set", err)
	}
}

func (r *RedisTICache) warn(msg string, err error) {
	if r.Logger == nil || errors.Is(err, context.Canceled) {
		return
	}
	r.Logger.Warn(msg, slog.Any("error", err))
}

// MustBeTICache compile-time asserts that RedisTICache satisfies the
// TICache interface. Detected at build-time so refactors that change
// the signatures break the build, not production.
var _ TICache = (*RedisTICache)(nil)
