//go:build integration
// +build integration

package redis_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	storageredis "github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

func startRedis(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	c, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "docker") {
			t.Skipf("docker not available, skipping: %v", err)
		}
		t.Fatalf("start redis: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	uri, err := c.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	// strip "redis://" scheme — our wrapper takes a bare host:port.
	addr := strings.TrimPrefix(uri, "redis://")
	addr = strings.TrimSuffix(addr, "/")
	return addr
}

func newClient(t *testing.T, addr string) *storageredis.Client {
	t.Helper()
	c, err := storageredis.New(context.Background(), storageredis.Config{Addr: addr})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRedisIntegration_StringRoundtripWithTTL(t *testing.T) {
	addr := startRedis(t)
	c := newClient(t, addr)
	ctx := context.Background()

	if err := c.Set(ctx, "ai_cache:abc", `{"verdict":"phishing"}`, 200*time.Millisecond); err != nil {
		t.Fatalf("set: %v", err)
	}
	v, found, err := c.Get(ctx, "ai_cache:abc")
	if err != nil || !found || v != `{"verdict":"phishing"}` {
		t.Fatalf("get: v=%q found=%v err=%v", v, found, err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, found, _ := c.Get(ctx, "ai_cache:abc"); found {
		t.Fatalf("expected ai_cache:abc to expire")
	}
}

func TestRedisIntegration_HashAndPipeline(t *testing.T) {
	addr := startRedis(t)
	c := newClient(t, addr)
	ctx := context.Background()

	if err := c.HSet(ctx, "tenant:abc:thresholds", map[string]string{
		"caution":  "0.30",
		"warning":  "0.55",
		"highrisk": "0.85",
	}); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if err := c.Set(ctx, "tenant:abc:weights", "v1", 0); err != nil {
		t.Fatalf("set: %v", err)
	}

	p := c.Pipeline()
	p.QueueGet("tenant:abc:weights")
	p.QueueGet("tenant:abc:missing")
	p.QueueHGetAll("tenant:abc:thresholds")
	if got := p.Len(); got != 3 {
		t.Fatalf("pipeline len=%d", got)
	}
	res, err := p.Exec(ctx)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	v, found, _ := res.GetString("tenant:abc:weights")
	if !found || v != "v1" {
		t.Fatalf("weights: v=%q found=%v", v, found)
	}
	if _, found, _ := res.GetString("tenant:abc:missing"); found {
		t.Fatal("missing key should not be found in pipeline result")
	}
	h, found, _ := res.GetHash("tenant:abc:thresholds")
	if !found || h["caution"] != "0.30" || h["highrisk"] != "0.85" {
		t.Fatalf("hash: %v found=%v", h, found)
	}
}

func TestRedisIntegration_ScanPrefix(t *testing.T) {
	addr := startRedis(t)
	c := newClient(t, addr)
	ctx := context.Background()

	for _, k := range []string{
		"label:tenant1:phishing",
		"label:tenant1:spam",
		"label:tenant2:phishing",
		"unrelated:tenant1",
	} {
		if err := c.Set(ctx, k, "x", 0); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}

	var collected []string
	if err := c.ScanPrefix(ctx, "label:tenant1:", 16, func(batch []string) error {
		collected = append(collected, batch...)
		return nil
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("expected 2 keys, got %d (%v)", len(collected), collected)
	}
}

func TestRedisIntegration_DelRemovesKeys(t *testing.T) {
	addr := startRedis(t)
	c := newClient(t, addr)
	ctx := context.Background()
	for _, k := range []string{"k1", "k2", "k3"} {
		_ = c.Set(ctx, k, "v", 0)
	}
	if err := c.Del(ctx, "k1", "k3"); err != nil {
		t.Fatalf("del: %v", err)
	}
	if _, found, _ := c.Get(ctx, "k1"); found {
		t.Fatal("k1 should be gone")
	}
	if _, found, _ := c.Get(ctx, "k2"); !found {
		t.Fatal("k2 should remain")
	}
}
