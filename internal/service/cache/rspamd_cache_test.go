package cache

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRspamdCache_KeyDependsOnContent(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{TTL: time.Minute})
	k1 := c.Key("acme", []byte("payload-1"))
	k2 := c.Key("acme", []byte("payload-2"))
	if k1 == k2 {
		t.Fatal("different payloads must produce different keys")
	}
	if k3 := c.Key("acme", []byte("payload-1")); k3 != k1 {
		t.Fatal("same (tenant, payload) must produce same key")
	}
}

// TestRspamdCache_KeyTenantIsolation asserts that two tenants with
// byte-identical raw mail do NOT collide in the cache. Without the
// tenantID being mixed into the hash, this would be the timing
// side-channel Devin Review flagged: tenant A could probe whether
// tenant B had recently seen a known-content email by observing cache
// hit/miss latency.
func TestRspamdCache_KeyTenantIsolation(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{TTL: time.Minute})
	kA := c.Key("tenant-a", []byte("same-payload"))
	kB := c.Key("tenant-b", []byte("same-payload"))
	if kA == kB {
		t.Fatal("two tenants must not share the same cache key for identical content")
	}
	if !strings.Contains(kA, "tenant-a:") || !strings.Contains(kB, "tenant-b:") {
		t.Fatalf("key must include tenantID prefix for SCAN-MATCH invalidation; kA=%s kB=%s", kA, kB)
	}
}

func TestRspamdCache_RequiresTenantID(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{TTL: time.Minute})
	ctx := context.Background()
	if _, _, err := c.Get(ctx, "", []byte("raw")); !errors.Is(err, ErrMissingTenantID) {
		t.Fatalf("Get with empty tenantID = %v, want ErrMissingTenantID", err)
	}
	if err := c.Set(ctx, "", []byte("raw"), RspamdResult{}); !errors.Is(err, ErrMissingTenantID) {
		t.Fatalf("Set with empty tenantID = %v, want ErrMissingTenantID", err)
	}
	if err := c.Invalidate(ctx, "", []byte("raw")); !errors.Is(err, ErrMissingTenantID) {
		t.Fatalf("Invalidate with empty tenantID = %v, want ErrMissingTenantID", err)
	}
}

func TestRspamdCache_SetGet(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{TTL: time.Minute})
	ctx := context.Background()
	stored := RspamdResult{
		Score:         7.5,
		RequiredScore: 15,
		Action:        "add header",
		Symbols:       map[string]float64{"DKIM_VALID": -1},
		SPF:           "pass",
		StoredAt:      time.Now().UTC().Truncate(time.Second),
	}
	if err := c.Set(ctx, "acme", []byte("raw"), stored); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.Get(ctx, "acme", []byte("raw"))
	if err != nil || !ok {
		t.Fatalf("expected hit, got ok=%v err=%v", ok, err)
	}
	if got.Score != stored.Score || got.Action != stored.Action || got.SPF != stored.SPF {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	// Defence in depth: the same raw mail under a different tenant
	// must NOT see acme's cache entry.
	if _, ok, _ := c.Get(ctx, "evil", []byte("raw")); ok {
		t.Fatal("cross-tenant Get returned acme's cache entry")
	}
}

func TestRspamdCache_TTLExpires(t *testing.T) {
	client, srv, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{TTL: 2 * time.Second})
	ctx := context.Background()
	_ = c.Set(ctx, "acme", []byte("raw"), RspamdResult{Score: 1})
	srv.FastForward(3 * time.Second)
	_, ok, _ := c.Get(ctx, "acme", []byte("raw"))
	if ok {
		t.Fatal("expected entry to be expired")
	}
}

func TestRspamdCache_Invalidate(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{TTL: time.Minute})
	ctx := context.Background()
	_ = c.Set(ctx, "acme", []byte("raw"), RspamdResult{Score: 1})
	if err := c.Invalidate(ctx, "acme", []byte("raw")); err != nil {
		t.Fatal(err)
	}
	_, ok, _ := c.Get(ctx, "acme", []byte("raw"))
	if ok {
		t.Fatal("entry should be gone after Invalidate")
	}
}

func TestRspamdCache_DefaultTTLAndPrefix(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{})
	if c.cfg.TTL != 30*time.Minute {
		t.Fatalf("default TTL = %s", c.cfg.TTL)
	}
	if c.cfg.KeyPrefix != "rspamd_cache:" {
		t.Fatalf("default prefix = %s", c.cfg.KeyPrefix)
	}
}
