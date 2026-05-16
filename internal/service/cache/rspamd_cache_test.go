package cache

import (
	"context"
	"testing"
	"time"
)

func TestRspamdCache_KeyDependsOnContent(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{TTL: time.Minute})
	k1 := c.Key([]byte("payload-1"))
	k2 := c.Key([]byte("payload-2"))
	if k1 == k2 {
		t.Fatal("different payloads must produce different keys")
	}
	if k3 := c.Key([]byte("payload-1")); k3 != k1 {
		t.Fatal("same payload must produce same key")
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
	if err := c.Set(ctx, []byte("raw"), stored); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.Get(ctx, []byte("raw"))
	if err != nil || !ok {
		t.Fatalf("expected hit, got ok=%v err=%v", ok, err)
	}
	if got.Score != stored.Score || got.Action != stored.Action || got.SPF != stored.SPF {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestRspamdCache_TTLExpires(t *testing.T) {
	client, srv, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{TTL: 2 * time.Second})
	ctx := context.Background()
	_ = c.Set(ctx, []byte("raw"), RspamdResult{Score: 1})
	srv.FastForward(3 * time.Second)
	_, ok, _ := c.Get(ctx, []byte("raw"))
	if ok {
		t.Fatal("expected entry to be expired")
	}
}

func TestRspamdCache_Invalidate(t *testing.T) {
	client, _, done := newTestClient(t)
	defer done()
	c, _ := NewRspamdCache(client, RspamdCacheConfig{TTL: time.Minute})
	ctx := context.Background()
	_ = c.Set(ctx, []byte("raw"), RspamdResult{Score: 1})
	if err := c.Invalidate(ctx, []byte("raw")); err != nil {
		t.Fatal(err)
	}
	_, ok, _ := c.Get(ctx, []byte("raw"))
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
