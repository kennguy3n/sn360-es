package cache

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/kennguy3n/sn360-es/internal/constant"
	redisclient "github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

const (
	testTenantA = "tenant-aaaaaaaa-1111"
	testTenantB = "tenant-bbbbbbbb-2222"
)

// newTestClient spins up a miniredis instance and returns a wrapped
// redis client + a teardown func.
func newTestClient(t *testing.T) (*redisclient.Client, *miniredis.Miniredis, func()) {
	t.Helper()
	srv := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: srv.Addr()})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("ping miniredis: %v", err)
	}
	return redisclient.FromRaw(rdb), srv, func() {
		_ = rdb.Close()
	}
}

func TestAICache_KeyIsDeterministic(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, err := NewAICache(client, AICacheConfig{TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	// Same canonical input → same key, regardless of whitespace or case.
	k1, err := c.Key(testTenantA, "Hello   WORLD\n", "Example.com")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	k2, err := c.Key(testTenantA, "hello world", "example.com")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if k1 != k2 {
		t.Fatalf("normalised inputs should yield same key:\nk1=%s\nk2=%s", k1, k2)
	}
	k3, err := c.Key(testTenantA, "hello world", "other.com")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if k3 == k1 {
		t.Fatal("different sender domain must change the key")
	}
}

// TestAICache_KeyTenantIsolation is the regression test for the
// cross-tenant cache leak: the same (body, senderDomain) under two
// different tenants must produce two different keys, and the tenant ID
// must appear verbatim in the key so that a Redis SCAN by prefix can
// enumerate / delete a single tenant's cache without affecting others
// (used by the cryptographic-erasure flow).
func TestAICache_KeyTenantIsolation(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: time.Minute})

	body, sender := "identical body", "vendor.example.com"
	kA, err := c.Key(testTenantA, body, sender)
	if err != nil {
		t.Fatalf("Key A: %v", err)
	}
	kB, err := c.Key(testTenantB, body, sender)
	if err != nil {
		t.Fatalf("Key B: %v", err)
	}
	if kA == kB {
		t.Fatalf("tenants must not share cache entries:\nkA=%s\nkB=%s", kA, kB)
	}
	// Tenant ID is embedded verbatim so a SCAN ai_cache:<tenantID>:*
	// enumerates exactly that tenant's entries — required for
	// per-tenant cryptographic erasure.
	if !strings.Contains(kA, testTenantA) {
		t.Fatalf("tenant id must be embedded in key, got %s", kA)
	}
	if !strings.Contains(kB, testTenantB) {
		t.Fatalf("tenant id must be embedded in key, got %s", kB)
	}
}

// TestAICache_KeyReturnsErrorOnEmptyTenantID is the contract that
// keeps misuse loud: Key never silently returns a (non-tenant) key for
// an empty tenantID — it returns ErrMissingTenantID, identical to the
// public Get/Set/Invalidate entry points. This prevents a future
// caller from inadvertently writing an entry under a no-tenant prefix
// that another tenant could then read.
func TestAICache_KeyReturnsErrorOnEmptyTenantID(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: time.Minute})
	key, err := c.Key("", "body", "sender.com")
	if !errors.Is(err, ErrMissingTenantID) {
		t.Fatalf("expected ErrMissingTenantID, got %v", err)
	}
	if key != "" {
		t.Fatalf("expected empty key on validation failure, got %q", key)
	}
}

func TestAICache_GetMiss(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: time.Minute})
	res, ok, err := c.Get(context.Background(), testTenantA, "body", "sender.com")
	if err != nil || ok {
		t.Fatalf("expected miss, got res=%v ok=%v err=%v", res, ok, err)
	}
}

func TestAICache_SetGetRoundtrip(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: time.Minute})
	ctx := context.Background()
	stored := AIResult{
		Tier:     constant.TierWarning,
		Category: constant.CategoryLikelyPhishing,
		Score:    72,
		StoredAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := c.Set(ctx, testTenantA, "body", "sender.com", stored); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok, err := c.Get(ctx, testTenantA, "body", "sender.com")
	if err != nil || !ok {
		t.Fatalf("expected hit, got ok=%v err=%v", ok, err)
	}
	if got.Tier != stored.Tier || got.Score != stored.Score || got.Category != stored.Category {
		t.Fatalf("mismatch: %+v vs %+v", got, stored)
	}
	// Tenant B must NOT see tenant A's entry.
	if _, ok, _ := c.Get(ctx, testTenantB, "body", "sender.com"); ok {
		t.Fatal("tenant B leaked tenant A's entry")
	}
}

func TestAICache_TTLExpires(t *testing.T) {
	client, srv, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: 5 * time.Second})
	ctx := context.Background()
	if err := c.Set(ctx, testTenantA, "body", "sender.com", AIResult{Tier: constant.TierCaution}); err != nil {
		t.Fatal(err)
	}
	srv.FastForward(6 * time.Second)
	_, ok, _ := c.Get(ctx, testTenantA, "body", "sender.com")
	if ok {
		t.Fatal("expected entry to be expired after fast-forward")
	}
}

func TestAICache_Invalidate(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: time.Minute})
	ctx := context.Background()
	_ = c.Set(ctx, testTenantA, "body", "sender.com", AIResult{Tier: constant.TierWarning})
	if err := c.Invalidate(ctx, testTenantA, "body", "sender.com"); err != nil {
		t.Fatal(err)
	}
	_, ok, _ := c.Get(ctx, testTenantA, "body", "sender.com")
	if ok {
		t.Fatal("expected invalidated entry to be absent")
	}
}

func TestAICache_GetSetInvalidateRejectEmptyTenant(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: time.Minute})
	ctx := context.Background()

	if _, _, err := c.Get(ctx, "", "body", "sender.com"); !errors.Is(err, ErrMissingTenantID) {
		t.Fatalf("Get with empty tenant: got %v, want ErrMissingTenantID", err)
	}
	if err := c.Set(ctx, "", "body", "sender.com", AIResult{}); !errors.Is(err, ErrMissingTenantID) {
		t.Fatalf("Set with empty tenant: got %v, want ErrMissingTenantID", err)
	}
	if err := c.Invalidate(ctx, "", "body", "sender.com"); !errors.Is(err, ErrMissingTenantID) {
		t.Fatalf("Invalidate with empty tenant: got %v, want ErrMissingTenantID", err)
	}
}

func TestNewAICache_RejectsNilClient(t *testing.T) {
	if _, err := NewAICache(nil, AICacheConfig{}); err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestAICache_DefaultsTTLAndPrefix(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, err := NewAICache(client, AICacheConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.cfg.TTL; got != time.Hour {
		t.Fatalf("default TTL = %s", got)
	}
	if got := c.cfg.KeyPrefix; got != "ai_cache:" {
		t.Fatalf("default prefix = %s", got)
	}
}
