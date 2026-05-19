package onboarding

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// NonceStore prevents replay of OAuth state tokens. After a state
// token is verified, we mark its nonce as used; subsequent attempts
// to use the same nonce are rejected.
type NonceStore interface {
	MarkUsed(ctx context.Context, nonce string, ttl time.Duration) (alreadyUsed bool, err error)
}

// RedisNonceStore implements NonceStore using Redis SET NX EX.
type RedisNonceStore struct {
	client redis.Cmdable
	prefix string
}

// NewRedisNonceStore constructs a nonce store. prefix defaults to
// "onboarding:nonce:" if empty.
func NewRedisNonceStore(client redis.Cmdable, prefix string) (*RedisNonceStore, error) {
	if client == nil {
		return nil, fmt.Errorf("onboarding: RedisNonceStore requires a Redis client")
	}
	if prefix == "" {
		prefix = "onboarding:nonce:"
	}
	return &RedisNonceStore{client: client, prefix: prefix}, nil
}

// MarkUsed attempts to set the nonce key with NX (only if not exists)
// and the given TTL. Returns true if the nonce was already consumed.
func (s *RedisNonceStore) MarkUsed(ctx context.Context, nonce string, ttl time.Duration) (bool, error) {
	if nonce == "" {
		return false, fmt.Errorf("onboarding: empty nonce")
	}
	key := s.prefix + nonce
	set, err := s.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("onboarding: nonce store: %w", err)
	}
	// SetNX returns true if the key was set (nonce is fresh).
	// If false, the key already existed (nonce was already used).
	return !set, nil
}

// InMemoryNonceStore is a test/fallback implementation. It is safe for
// concurrent use.
type InMemoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ops  uint64
}

// NewInMemoryNonceStore constructs an in-memory nonce store.
func NewInMemoryNonceStore() *InMemoryNonceStore {
	return &InMemoryNonceStore{seen: make(map[string]time.Time)}
}

// MarkUsed checks and marks a nonce. Periodically evicts expired
// entries so the map does not grow without bound.
func (s *InMemoryNonceStore) MarkUsed(_ context.Context, nonce string, ttl time.Duration) (bool, error) {
	if nonce == "" {
		return false, fmt.Errorf("onboarding: empty nonce")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()

	// Evict expired entries every 64 calls to amortise the cost.
	s.ops++
	if s.ops%64 == 0 {
		for k, exp := range s.seen {
			if now.After(exp) {
				delete(s.seen, k)
			}
		}
	}

	if exp, ok := s.seen[nonce]; ok {
		if now.Before(exp) {
			return true, nil
		}
	}
	s.seen[nonce] = now.Add(ttl)
	return false, nil
}
