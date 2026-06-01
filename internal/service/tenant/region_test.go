package tenant

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// stubTenantRepo is a minimal in-memory TenantRepository good enough for
// the resolver tests. It satisfies the full interface so the
// region.go code path stays unchanged from production.
type stubTenantRepo struct {
	get func(ctx context.Context, id string) (*repository.Tenant, error)
}

func (s *stubTenantRepo) Create(ctx context.Context, t *repository.Tenant) error {
	return errors.New("stub: Create not implemented")
}
func (s *stubTenantRepo) GetByID(ctx context.Context, id string) (*repository.Tenant, error) {
	return s.get(ctx, id)
}
func (s *stubTenantRepo) GetByName(ctx context.Context, name string) (*repository.Tenant, error) {
	return nil, errors.New("stub: GetByName not implemented")
}
func (s *stubTenantRepo) UpdateStatus(ctx context.Context, id, status string) error {
	return errors.New("stub: UpdateStatus not implemented")
}
func (s *stubTenantRepo) List(ctx context.Context, limit int) ([]repository.Tenant, error) {
	return nil, errors.New("stub: List not implemented")
}
func (s *stubTenantRepo) IterateActive(ctx context.Context, batchSize int, yield func([]repository.Tenant) error) error {
	return errors.New("stub: IterateActive not implemented")
}

// TestRegionLookup_HappyPath confirms a populated tenant resolves to
// its region — the entire reason the resolver exists.
func TestRegionLookup_HappyPath(t *testing.T) {
	t.Parallel()

	repo := &stubTenantRepo{
		get: func(_ context.Context, id string) (*repository.Tenant, error) {
			return &repository.Tenant{ID: id, Region: "us-east-1"}, nil
		},
	}
	region, err := NewRegionLookup(repo).ResolveRegion(context.Background(), "tnt-1")
	if err != nil {
		t.Fatalf("ResolveRegion: %v", err)
	}
	if region != "us-east-1" {
		t.Fatalf("region = %q, want us-east-1", region)
	}
}

// TestRegionLookup_UnknownTenant: ErrNotFound from the repo must map
// to ErrTenantUnknown so the binder can fail fast on typoed tenant
// ids instead of waiting on a redelivery cycle.
func TestRegionLookup_UnknownTenant(t *testing.T) {
	t.Parallel()

	repo := &stubTenantRepo{
		get: func(_ context.Context, _ string) (*repository.Tenant, error) {
			return nil, repository.ErrNotFound
		},
	}
	_, err := NewRegionLookup(repo).ResolveRegion(context.Background(), "tnt-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTenantUnknown) {
		t.Fatalf("err = %v, want ErrTenantUnknown", err)
	}
}

// TestRegionLookup_EmptyRegionColumn: a tenant row with a blank
// region is a data integrity error, not a default. The lookup must
// surface the explicit "empty region column" message so operators
// catch the bad row (vs. silently routing it to the home pool).
func TestRegionLookup_EmptyRegionColumn(t *testing.T) {
	t.Parallel()

	repo := &stubTenantRepo{
		get: func(_ context.Context, id string) (*repository.Tenant, error) {
			return &repository.Tenant{ID: id, Region: "   "}, nil
		},
	}
	_, err := NewRegionLookup(repo).ResolveRegion(context.Background(), "tnt-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "empty region") {
		t.Fatalf("err = %q, expected to mention empty region", err)
	}
}

// TestRegionLookup_EmptyTenantID and TestRegionLookup_NilRepo guard
// the two trivial misuses that would otherwise crash the catalog DB
// or panic on a nil deref.
func TestRegionLookup_EmptyTenantID(t *testing.T) {
	t.Parallel()

	repo := &stubTenantRepo{get: func(context.Context, string) (*repository.Tenant, error) {
		t.Fatal("Get must not be called for empty tenantID")
		return nil, nil
	}}
	_, err := NewRegionLookup(repo).ResolveRegion(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty tenantID, got nil")
	}
}

func TestRegionLookup_NilRepo(t *testing.T) {
	t.Parallel()

	_, err := NewRegionLookup(nil).ResolveRegion(context.Background(), "tnt-1")
	if err == nil {
		t.Fatal("expected error for nil repo, got nil")
	}
}

// TestCachedRegionResolver_CachesHit + TestCachedRegionResolver_CacheMissCount
// together pin the "hit the source once per TTL" steady-state
// behaviour of the cache. A regression here would either cause every
// request to round-trip the catalog DB (defeating the cache) or
// freeze a stale region forever (defeating the TTL).
func TestCachedRegionResolver_CachesHits(t *testing.T) {
	t.Parallel()

	var calls int32
	src := ResolverFunc(func(_ context.Context, _ string) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "us-east-1", nil
	})
	cr := NewCachedRegionResolver(src, time.Minute)

	for i := 0; i < 10; i++ {
		region, err := cr.ResolveRegion(context.Background(), "tnt-1")
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if region != "us-east-1" {
			t.Fatalf("iter %d: region = %q", i, region)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("source called %d times across 10 lookups, want 1", got)
	}
	if cr.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", cr.Len())
	}
}

// TestCachedRegionResolver_TTLExpires uses the injectable clock to
// confirm that after TTL the next call re-fetches from the source.
// The previous test handles cache hits; this one guards the upper
// bound (no infinite caching of stale values).
func TestCachedRegionResolver_TTLExpires(t *testing.T) {
	t.Parallel()

	var calls int32
	src := ResolverFunc(func(_ context.Context, _ string) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "us-east-1", nil
	})
	cr := NewCachedRegionResolver(src, 500*time.Millisecond)
	cr.now = func() time.Time {
		return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	}

	if _, err := cr.ResolveRegion(context.Background(), "tnt-1"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Advance the clock past TTL.
	cr.now = func() time.Time {
		return time.Date(2026, 6, 1, 0, 1, 0, 0, time.UTC)
	}
	if _, err := cr.ResolveRegion(context.Background(), "tnt-1"); err != nil {
		t.Fatalf("post-TTL call: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("source called %d times across cached + post-TTL lookups, want 2", got)
	}
}

// TestCachedRegionResolver_ErrorsAreNotCached is critical for fail-
// closed semantics: a transient catalog-DB blip must NOT poison the
// cache for the next 5 minutes. The wrapper must retry the source
// every request until success.
func TestCachedRegionResolver_ErrorsAreNotCached(t *testing.T) {
	t.Parallel()

	var calls int32
	src := ResolverFunc(func(_ context.Context, _ string) (string, error) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			return "", errors.New("transient catalog db blip")
		}
		return "us-east-1", nil
	})
	cr := NewCachedRegionResolver(src, time.Minute)

	for i := 0; i < 2; i++ {
		if _, err := cr.ResolveRegion(context.Background(), "tnt-1"); err == nil {
			t.Fatalf("call %d: expected error, got nil (errors must not be cached)", i)
		}
	}
	region, err := cr.ResolveRegion(context.Background(), "tnt-1")
	if err != nil {
		t.Fatalf("third call: %v", err)
	}
	if region != "us-east-1" {
		t.Fatalf("region = %q, want us-east-1", region)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("source called %d times across 3 lookups, want 3 (no error caching)", got)
	}
}

// TestCachedRegionResolver_Invalidate covers the admin path: when an
// operator migrates a tenant's region, calling Invalidate drops the
// cached entry so the next request picks up the new region without
// waiting for TTL.
func TestCachedRegionResolver_Invalidate(t *testing.T) {
	t.Parallel()

	var region atomic.Value
	region.Store("us-east-1")
	var calls int32
	src := ResolverFunc(func(_ context.Context, _ string) (string, error) {
		atomic.AddInt32(&calls, 1)
		return region.Load().(string), nil
	})
	cr := NewCachedRegionResolver(src, time.Hour)

	if got, _ := cr.ResolveRegion(context.Background(), "tnt-1"); got != "us-east-1" {
		t.Fatalf("first call: %q", got)
	}
	region.Store("eu-west-1")
	if got, _ := cr.ResolveRegion(context.Background(), "tnt-1"); got != "us-east-1" {
		t.Fatalf("post-migrate without invalidate: %q (cache should still serve old value)", got)
	}
	cr.Invalidate("tnt-1")
	if got, _ := cr.ResolveRegion(context.Background(), "tnt-1"); got != "eu-west-1" {
		t.Fatalf("post-invalidate: %q, want eu-west-1", got)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("source called %d times, want 2", got)
	}
}

// TestCachedRegionResolver_DefaultTTL pins the documented constant —
// passing 0 / negative TTL must fall back to DefaultRegionCacheTTL
// rather than caching for zero seconds (which would degrade to a
// per-request DB lookup).
func TestCachedRegionResolver_DefaultTTL(t *testing.T) {
	t.Parallel()

	for _, ttl := range []time.Duration{0, -1, -1 * time.Hour} {
		cr := NewCachedRegionResolver(ResolverFunc(func(context.Context, string) (string, error) {
			return "us-east-1", nil
		}), ttl)
		if cr.ttl != DefaultRegionCacheTTL {
			t.Fatalf("ttl=%v: got %v, want %v", ttl, cr.ttl, DefaultRegionCacheTTL)
		}
	}
}

// TestCachedRegionResolver_NilSrcReturnsNil guards against the
// trivial misuse where a wiring layer passed nil for the source —
// the constructor returns nil so the caller's downstream nil check
// triggers, rather than panicking later under load.
func TestCachedRegionResolver_NilSrcReturnsNil(t *testing.T) {
	t.Parallel()

	if cr := NewCachedRegionResolver(nil, time.Minute); cr != nil {
		t.Fatalf("NewCachedRegionResolver(nil): got %v, want nil", cr)
	}
}
