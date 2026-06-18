package action

import (
	"context"
	"testing"
	"time"
)

func TestInMemorySingleUseStoreMarkConsumed(t *testing.T) {
	s := NewInMemorySingleUseStore()
	ctx := context.Background()

	already, err := s.MarkConsumed(ctx, "jti-1", time.Minute)
	if err != nil {
		t.Fatalf("first MarkConsumed: %v", err)
	}
	if already {
		t.Fatal("first use must report alreadyConsumed=false")
	}

	already, err = s.MarkConsumed(ctx, "jti-1", time.Minute)
	if err != nil {
		t.Fatalf("second MarkConsumed: %v", err)
	}
	if !already {
		t.Fatal("second use of the same id must report alreadyConsumed=true")
	}

	// A different id is independent.
	already, err = s.MarkConsumed(ctx, "jti-2", time.Minute)
	if err != nil {
		t.Fatalf("MarkConsumed jti-2: %v", err)
	}
	if already {
		t.Fatal("a distinct id must be treated as fresh")
	}
}

func TestInMemorySingleUseStoreExpiry(t *testing.T) {
	s := NewInMemorySingleUseStore()
	ctx := context.Background()

	if _, err := s.MarkConsumed(ctx, "jti-x", time.Millisecond); err != nil {
		t.Fatalf("MarkConsumed: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	// After the TTL elapses the id is reclaimable, so it reads as fresh.
	already, err := s.MarkConsumed(ctx, "jti-x", time.Minute)
	if err != nil {
		t.Fatalf("MarkConsumed after expiry: %v", err)
	}
	if already {
		t.Error("an expired entry must be treated as fresh")
	}
}

func TestInMemorySingleUseStoreRejectsEmptyID(t *testing.T) {
	s := NewInMemorySingleUseStore()
	if _, err := s.MarkConsumed(context.Background(), "", time.Minute); err == nil {
		t.Error("empty id must be rejected")
	}
}
