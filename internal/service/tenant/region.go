package tenant

// Tenant region resolver (WS-7a multi-region routing).
//
// The tenant-context binder (HTTP middleware + NATS consumer entry)
// resolves the tenant's region BEFORE acquiring a Postgres conn so it
// can pick the right regional pool. This file implements that resolver:
//
//   - RegionResolver is the small interface the binder depends on.
//
//   - RegionLookup is the Postgres-backed source — given a tenant id,
//     it reads `region` from the `tenants` table on the catalog DB
//     (the home-region pool by convention). The `tenants` table is
//     NOT under RLS (per `migrations/0018_row_level_security.up.sql`
//     — only per-tenant tables carry the policy), so the lookup
//     runs on an unbound conn and does not require WithCrossTenant.
//
//   - CachedRegionResolver wraps a source with a TTL cache. The
//     cache is keyed by tenant id with a 5-minute default TTL —
//     tenant region is essentially immutable (changing it requires a
//     data migration), so the cache catches the steady-state load
//     while still allowing operators to migrate a tenant without a
//     binary restart.
//
//   - On cache miss + lookup failure, the resolver returns the error
//     (fail closed). The binder rejects the request with 5xx /
//     redelivery instead of silently routing to the default region.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// DefaultRegionCacheTTL is the cache lifetime used by
// NewCachedRegionResolver when the caller passes a zero / negative
// TTL. Five minutes is short enough to pick up a manual region change
// without a binary restart, and long enough that high-QPS tenants
// hit the cache on essentially every request.
const DefaultRegionCacheTTL = 5 * time.Minute

// ErrTenantUnknown is returned by RegionLookup / RegionResolver when
// the tenant id is not present in the catalog (or has been deleted).
// The binder maps this to a 4xx / explicit message-drop so a typoed
// tenant id surfaces as a clear error rather than a silent route to
// the home region's pool.
var ErrTenantUnknown = errors.New("tenant: unknown tenant id")

// RegionResolver returns the region label for the supplied tenant id.
//
// Implementations MUST return a non-empty region string on success.
// On unknown tenants, return ErrTenantUnknown so call-sites can
// distinguish a real lookup failure (transient DB error, redelivery
// expected) from a configuration error (typoed tenant id, fail-fast
// rejection expected).
type RegionResolver interface {
	ResolveRegion(ctx context.Context, tenantID string) (string, error)
}

// ResolverFunc is the function-adapter for RegionResolver.
type ResolverFunc func(ctx context.Context, tenantID string) (string, error)

// ResolveRegion implements RegionResolver.
func (f ResolverFunc) ResolveRegion(ctx context.Context, tenantID string) (string, error) {
	return f(ctx, tenantID)
}

// RegionLookup is the Postgres-backed RegionResolver. It reads from a
// supplied TenantRepository which the wiring layer points at the
// home-region (catalog) pool. The `tenants` table is not RLS-scoped
// so the lookup runs without any tenant binding.
//
// This is the bottom of the resolver stack — production deployments
// wrap it in CachedRegionResolver so the catalog DB is not hit on
// every request.
type RegionLookup struct {
	tenants repository.TenantRepository
}

// NewRegionLookup constructs a RegionLookup backed by the supplied
// repository.
func NewRegionLookup(tenants repository.TenantRepository) *RegionLookup {
	return &RegionLookup{tenants: tenants}
}

// ResolveRegion implements RegionResolver.
func (l *RegionLookup) ResolveRegion(ctx context.Context, tenantID string) (string, error) {
	if l == nil || l.tenants == nil {
		return "", errors.New("tenant: RegionLookup: tenants repository is not wired")
	}
	if strings.TrimSpace(tenantID) == "" {
		return "", errors.New("tenant: RegionLookup: tenantID is empty")
	}
	t, err := l.tenants.GetByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", fmt.Errorf("%w: %s", ErrTenantUnknown, tenantID)
		}
		return "", fmt.Errorf("tenant: RegionLookup: GetByID: %w", err)
	}
	region := strings.TrimSpace(t.Region)
	if region == "" {
		return "", fmt.Errorf("tenant: RegionLookup: tenant %s has empty region column (data migration issue?)", tenantID)
	}
	return region, nil
}

// regionCacheEntry holds the cached region label and the absolute
// expiry time. We deliberately do NOT cache errors: a transient DB
// failure should retry on the next request (the request rate already
// throttles repeated cache-misses), and an ErrTenantUnknown is rare
// enough that re-fetching is cheap.
type regionCacheEntry struct {
	region    string
	expiresAt time.Time
}

// CachedRegionResolver wraps a RegionResolver with a TTL-bounded
// in-memory cache. Concurrent ResolveRegion calls for the same
// uncached tenant are NOT coalesced — the cache is intentionally
// kept simple. The fan-out is bounded by the binder's QPS, and the
// extra duplicate lookup is a single SELECT against a tiny
// non-RLS table.
type CachedRegionResolver struct {
	src RegionResolver
	ttl time.Duration

	mu    sync.RWMutex
	cache map[string]regionCacheEntry

	// now is injected for tests so the TTL behaviour can be
	// exercised deterministically. Defaults to time.Now.
	now func() time.Time
}

// NewCachedRegionResolver wraps src with a TTL cache. A zero /
// negative ttl falls back to DefaultRegionCacheTTL. Passing src=nil
// returns nil — the caller is responsible for nil-checking, but in
// practice the wiring layer always constructs a real source.
func NewCachedRegionResolver(src RegionResolver, ttl time.Duration) *CachedRegionResolver {
	if src == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = DefaultRegionCacheTTL
	}
	return &CachedRegionResolver{
		src:   src,
		ttl:   ttl,
		cache: make(map[string]regionCacheEntry),
		now:   time.Now,
	}
}

// ResolveRegion implements RegionResolver.
//
// On cache hit (entry exists AND has not expired) returns the
// cached region without touching the wrapped source. On miss /
// stale entry, delegates to src; successful results are cached
// for ttl, errors are NOT cached so the next request retries.
func (c *CachedRegionResolver) ResolveRegion(ctx context.Context, tenantID string) (string, error) {
	if c == nil {
		return "", errors.New("tenant: CachedRegionResolver: nil receiver")
	}
	if strings.TrimSpace(tenantID) == "" {
		return "", errors.New("tenant: CachedRegionResolver: tenantID is empty")
	}
	now := c.now()
	c.mu.RLock()
	entry, ok := c.cache[tenantID]
	c.mu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.region, nil
	}
	region, err := c.src.ResolveRegion(ctx, tenantID)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.cache[tenantID] = regionCacheEntry{
		region:    region,
		expiresAt: c.now().Add(c.ttl),
	}
	c.mu.Unlock()
	return region, nil
}

// Invalidate drops the cached entry for tenantID. Operators who
// migrate a tenant between regions can call this (via an admin
// endpoint) to force the next request to re-fetch from the catalog.
// Calling Invalidate on a non-cached tenant is a no-op.
func (c *CachedRegionResolver) Invalidate(tenantID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.cache, tenantID)
	c.mu.Unlock()
}

// Len returns the number of cached entries (including expired ones
// that have not yet been refreshed). Exposed for tests and for an
// optional Prometheus gauge.
func (c *CachedRegionResolver) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}
