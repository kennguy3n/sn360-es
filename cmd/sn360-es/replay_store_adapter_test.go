package main

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

func newTestSingleUseStore(t *testing.T) (redisSingleUseStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return redisSingleUseStore{client: redis.FromRaw(rdb), prefix: "action:jti:"}, mr
}

// TestRedisSingleUseStore_MarkConsumed locks in the single-use contract
// for the Redis-backed store: the first redemption of a jti is fresh and
// any later one within the TTL window observes alreadyConsumed=true.
func TestRedisSingleUseStore_MarkConsumed(t *testing.T) {
	store, _ := newTestSingleUseStore(t)
	ctx := context.Background()

	already, err := store.MarkConsumed(ctx, "tok-1", 10*time.Minute)
	if err != nil {
		t.Fatalf("first MarkConsumed: %v", err)
	}
	if already {
		t.Fatal("first redemption must report alreadyConsumed=false")
	}

	already, err = store.MarkConsumed(ctx, "tok-1", 10*time.Minute)
	if err != nil {
		t.Fatalf("second MarkConsumed: %v", err)
	}
	if !already {
		t.Fatal("replayed jti must report alreadyConsumed=true")
	}

	already, err = store.MarkConsumed(ctx, "tok-2", 10*time.Minute)
	if err != nil {
		t.Fatalf("distinct MarkConsumed: %v", err)
	}
	if already {
		t.Fatal("a distinct jti must be independent")
	}

	if _, err := store.MarkConsumed(ctx, "", time.Minute); err == nil {
		t.Fatal("empty token id must be rejected")
	}
}

// TestRedisSingleUseStore_FloorsNonPositiveTTL is the regression guard
// for the floor: a non-positive TTL must not create a no-expiry key
// (which would leak the consumed-jti entry forever), matching
// InMemorySingleUseStore. The entry must carry a positive TTL.
func TestRedisSingleUseStore_FloorsNonPositiveTTL(t *testing.T) {
	store, mr := newTestSingleUseStore(t)
	ctx := context.Background()

	if _, err := store.MarkConsumed(ctx, "tok-zero", 0); err != nil {
		t.Fatalf("MarkConsumed(ttl=0): %v", err)
	}
	if ttl := mr.TTL("action:jti:tok-zero"); ttl <= 0 {
		t.Fatalf("ttl=0 must be floored to a positive expiry, got %v (no-expiry key leaks forever)", ttl)
	}

	if _, err := store.MarkConsumed(ctx, "tok-neg", -5*time.Second); err != nil {
		t.Fatalf("MarkConsumed(ttl<0): %v", err)
	}
	if ttl := mr.TTL("action:jti:tok-neg"); ttl <= 0 {
		t.Fatalf("negative ttl must be floored to a positive expiry, got %v", ttl)
	}
}
