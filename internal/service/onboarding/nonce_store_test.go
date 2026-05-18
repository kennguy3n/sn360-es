package onboarding

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisNonceStore_MarkUsed(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := &RedisNonceStore{client: client}
	ctx := context.Background()

	// First use should succeed.
	alreadyUsed, err := store.MarkUsed(ctx, "nonce-1", 10*time.Minute)
	if err != nil {
		t.Fatalf("MarkUsed first: %v", err)
	}
	if alreadyUsed {
		t.Error("first call should return alreadyUsed=false")
	}

	// Second use of the same nonce should report already used.
	alreadyUsed, err = store.MarkUsed(ctx, "nonce-1", 10*time.Minute)
	if err != nil {
		t.Fatalf("MarkUsed second: %v", err)
	}
	if !alreadyUsed {
		t.Error("second call should return alreadyUsed=true")
	}

	// Different nonce should succeed.
	alreadyUsed, err = store.MarkUsed(ctx, "nonce-2", 10*time.Minute)
	if err != nil {
		t.Fatalf("MarkUsed different: %v", err)
	}
	if alreadyUsed {
		t.Error("different nonce should return alreadyUsed=false")
	}
}

func TestRedisNonceStore_TTLExpiry(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := &RedisNonceStore{client: client}
	ctx := context.Background()

	_, err = store.MarkUsed(ctx, "nonce-expire", 1*time.Minute)
	if err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}

	// Fast-forward past TTL.
	mr.FastForward(2 * time.Minute)

	// Should be able to reuse after TTL.
	alreadyUsed, err := store.MarkUsed(ctx, "nonce-expire", 1*time.Minute)
	if err != nil {
		t.Fatalf("MarkUsed after TTL: %v", err)
	}
	if alreadyUsed {
		t.Error("after TTL expiry, nonce should be reusable")
	}
}
