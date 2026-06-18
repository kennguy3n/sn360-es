package action

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SingleUseStore records consumed action-token identifiers (the JWT
// `jti`) so a token can be redeemed at most once. It is the
// replay-protection primitive behind FeedbackService: the first
// redemption of a token records its jti, and any later redemption of
// the same token observes alreadyConsumed=true and is refused.
type SingleUseStore interface {
	// MarkConsumed atomically records id as consumed with the given
	// TTL. The caller sets the TTL to at least the token's remaining
	// lifetime so a jti cannot be replayed within its validity
	// window; the entry is reclaimed afterwards. It returns
	// alreadyConsumed=false the first time id is seen and
	// alreadyConsumed=true for every subsequent call inside the TTL
	// window.
	MarkConsumed(ctx context.Context, id string, ttl time.Duration) (alreadyConsumed bool, err error)
}

// InMemorySingleUseStore is the process-local SingleUseStore used when
// Redis is not configured (single-instance dev / test). It is safe for
// concurrent use. A multi-instance deployment wires the Redis-backed
// store instead so the single-use guarantee holds across the fleet.
type InMemorySingleUseStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ops  uint64
}

// NewInMemorySingleUseStore constructs an in-memory single-use store.
func NewInMemorySingleUseStore() *InMemorySingleUseStore {
	return &InMemorySingleUseStore{seen: make(map[string]time.Time)}
}

// MarkConsumed records id and reports whether it had already been
// consumed within its TTL. Expired entries are evicted periodically so
// the map does not grow without bound.
func (s *InMemorySingleUseStore) MarkConsumed(_ context.Context, id string, ttl time.Duration) (bool, error) {
	if id == "" {
		return false, fmt.Errorf("action: empty token id")
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

	if exp, ok := s.seen[id]; ok && now.Before(exp) {
		return true, nil
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	s.seen[id] = now.Add(ttl)
	return false, nil
}
