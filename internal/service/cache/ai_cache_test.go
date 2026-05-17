package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/kennguy3n/sn360-es/internal/constant"
	redisclient "github.com/kennguy3n/sn360-es/pkg/storage/redis"
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
	k1 := c.Key("Hello   WORLD\n", "Example.com")
	k2 := c.Key("hello world", "example.com")
	if k1 != k2 {
		t.Fatalf("normalised inputs should yield same key:\nk1=%s\nk2=%s", k1, k2)
	}
	if k3 := c.Key("hello world", "other.com"); k3 == k1 {
		t.Fatal("different sender domain must change the key")
	}
}

func TestAICache_GetMiss(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: time.Minute})
	res, ok, err := c.Get(context.Background(), "body", "sender.com")
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
	if err := c.Set(ctx, "body", "sender.com", stored); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok, err := c.Get(ctx, "body", "sender.com")
	if err != nil || !ok {
		t.Fatalf("expected hit, got ok=%v err=%v", ok, err)
	}
	if got.Tier != stored.Tier || got.Score != stored.Score || got.Category != stored.Category {
		t.Fatalf("mismatch: %+v vs %+v", got, stored)
	}
}

func TestAICache_TTLExpires(t *testing.T) {
	client, srv, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: 5 * time.Second})
	ctx := context.Background()
	if err := c.Set(ctx, "body", "sender.com", AIResult{Tier: constant.TierCaution}); err != nil {
		t.Fatal(err)
	}
	srv.FastForward(6 * time.Second)
	_, ok, _ := c.Get(ctx, "body", "sender.com")
	if ok {
		t.Fatal("expected entry to be expired after fast-forward")
	}
}

func TestAICache_Invalidate(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewAICache(client, AICacheConfig{TTL: time.Minute})
	ctx := context.Background()
	_ = c.Set(ctx, "body", "sender.com", AIResult{Tier: constant.TierWarning})
	if err := c.Invalidate(ctx, "body", "sender.com"); err != nil {
		t.Fatal(err)
	}
	_, ok, _ := c.Get(ctx, "body", "sender.com")
	if ok {
		t.Fatal("expected invalidated entry to be absent")
	}
}

func TestNewAICache_RejectsNilClient(t *testing.T) {
	if _, err := NewAICache(nil, AICacheConfig{}); !errors.Is(err, errors.Unwrap(err)) && err == nil {
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
