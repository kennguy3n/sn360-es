// Package redis hosts SN360-ES's thin Redis primitives. lock.go adds a
// distributed lock built on the canonical SET NX EX + Lua-release
// pattern.
//
// The lock semantics are deliberately narrow:
//
//  1. Acquire writes (key, value=UUID) only if the key does not exist,
//     expiring after `ttl`. Returns true on success, false when another
//     holder owns the key.
//  2. Release deletes the key ONLY when its current value still matches
//     the holder's UUID — a Lua script keeps the GET/DEL atomic so two
//     holders cannot race past an expired TTL.
//  3. Extend bumps the TTL using a similar GET/PEXPIRE Lua so callers
//     can keep a long-running cycle's lock alive without reacquiring.
//
// The lock is used by the ingestion poller (per-mailbox locks to
// dedupe across replicas) and by the periodic workers (leader
// election so only one replica runs a worker cycle).
//
// IMPORTANT: single-node Redis lock — split-brain caveat.
//
// This implementation targets a SINGLE Redis instance. In an HA
// Redis deployment (Sentinel failover, Cluster mode with replica
// promotion, multi-AZ replication with async streaming), the
// canonical SET NX EX primitive is NOT split-brain-safe:
//
//   - Replica promotion can lose the most recent SETs not yet
//     streamed from the primary.
//   - Two holders — the one that acquired against the deposed
//     primary, and a new acquirer against the freshly-promoted
//     replica — can each believe they own the lock simultaneously.
//
// The Redlock algorithm (multiple independent Redis instances,
// quorum acquire) addresses this at the lock layer but adds
// significant operational complexity (N independent instances,
// clock-drift tolerances, fault budgets). For SN360-ES we treat the
// Redis lock as an OPTIMISATION — it suppresses the common case of
// two-replica contention — and rely on APPLICATION-LAYER FENCING for
// correctness in safety-critical paths.
//
// Application-layer fencing is implemented as:
//
//  1. Persist the holder UUID (Token()) alongside the protected
//     resource where you can read-and-compare-and-swap atomically.
//  2. Make the critical operation idempotent at the persistence
//     layer (e.g. the quarantine release flow uses an atomic GETDEL
//     so two concurrent releases race to claim the encrypted
//     reference — only one wins, the loser short-circuits).
//
// In short: use this lock to suppress contention; use the
// persistence layer to enforce correctness. Document any
// safety-critical caller that doesn't follow this pattern.
package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// luaReleaseScript ensures we only delete the key when its current
// value matches the holder UUID. Without the compare the lock would
// be unsound: a stalled holder whose TTL expired and was re-acquired
// by another replica must not be able to delete the new holder's
// lock when it eventually finishes its work.
const luaReleaseScript = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
`

// luaExtendScript bumps the TTL in milliseconds when the caller still
// owns the lock. Returns 1 on success, 0 when the key has expired or
// a new holder has taken over.
const luaExtendScript = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("PEXPIRE", KEYS[1], ARGV[2])
else
    return 0
end
`

// DistributedLock is a single-key Redis lock. One value per holder;
// callers should construct a fresh instance per critical section
// (the random UUID is generated in NewDistributedLock).
type DistributedLock struct {
	client *Client
	key    string
	ttl    time.Duration
	value  string
}

// NewDistributedLock constructs a lock for the given key with the
// requested TTL. The value is a fresh random UUID so two holders of
// the same key (e.g. retries by the same caller) cannot accidentally
// release each other's lock. The TTL must be > 0; the constructor
// errors out otherwise so misconfiguration surfaces at boot.
func NewDistributedLock(client *Client, key string, ttl time.Duration) (*DistributedLock, error) {
	if client == nil {
		return nil, errors.New("redis: lock requires a client")
	}
	if key == "" {
		return nil, errors.New("redis: lock key is required")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("redis: lock ttl must be > 0, got %s", ttl)
	}
	value, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("redis: lock token: %w", err)
	}
	return &DistributedLock{client: client, key: key, ttl: ttl, value: value}, nil
}

// Key returns the underlying Redis key. Useful for logging.
func (l *DistributedLock) Key() string { return l.key }

// TTL returns the configured TTL.
func (l *DistributedLock) TTL() time.Duration { return l.ttl }

// Acquire attempts to take the lock. Returns true when the SET NX
// succeeds and the caller now owns the key. A false return means
// another holder already owns the lock; the caller should back off
// and try again later. Transport errors are surfaced as-is so the
// caller can decide whether to log-and-skip or fail closed.
func (l *DistributedLock) Acquire(ctx context.Context) (bool, error) {
	ok, err := l.client.rdb.SetNX(ctx, l.key, l.value, l.ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis: lock acquire %q: %w", l.key, err)
	}
	return ok, nil
}

// Release atomically deletes the key when the current value matches
// the holder's UUID. Returns true when the key was deleted by this
// call, false when the lock had already expired or was held by
// another replica (which is the legitimate outcome of a delayed
// release). Transport errors are surfaced as-is.
func (l *DistributedLock) Release(ctx context.Context) (bool, error) {
	res, err := l.client.rdb.Eval(ctx, luaReleaseScript, []string{l.key}, l.value).Result()
	if err != nil {
		// Redis returns redis.Nil on script success with empty
		// reply; in practice EVAL returns an integer 0/1 here so
		// any non-nil error is genuinely a transport issue.
		return false, fmt.Errorf("redis: lock release %q: %w", l.key, err)
	}
	n, ok := res.(int64)
	if !ok {
		return false, fmt.Errorf("redis: lock release %q: unexpected reply type %T", l.key, res)
	}
	return n == 1, nil
}

// Extend pushes the TTL forward by the supplied duration if the
// caller still owns the lock. Returns true on success, false when
// the lock has expired or been taken over (the caller should treat
// this as an immediate stop signal — it no longer owns the critical
// section). Transport errors are surfaced as-is.
func (l *DistributedLock) Extend(ctx context.Context, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, fmt.Errorf("redis: lock extend ttl must be > 0, got %s", ttl)
	}
	res, err := l.client.rdb.Eval(ctx, luaExtendScript, []string{l.key}, l.value, ttl.Milliseconds()).Result()
	if err != nil {
		return false, fmt.Errorf("redis: lock extend %q: %w", l.key, err)
	}
	n, ok := res.(int64)
	if !ok {
		return false, fmt.Errorf("redis: lock extend %q: unexpected reply type %T", l.key, res)
	}
	return n == 1, nil
}

// Token returns the random 16-byte hex-encoded value this lock
// instance writes into Redis on Acquire. It is the per-holder
// fingerprint Release / Extend / Owns compare against — callers
// that want application-layer fencing (see the package-level
// split-brain caveat) should persist Token() alongside the
// protected resource so a follow-up operation can compare-and-
// swap on the holder identity.
//
// Example: a quarantine release flow that acquires this lock,
// stores Token() into the encrypted reference, then on a later
// restore call verifies the stored token still matches the
// current holder's Token() before mutating the message. A split-
// brain replica that acquired against a stale primary will have
// a different Token() so the compare-and-swap fails.
func (l *DistributedLock) Token() string { return l.value }

// Owns reports whether the holder UUID still matches the current
// value of the key. It is informational — callers should not gate
// critical-section work on Owns because the underlying value can
// change between Owns and the next operation. Use Extend instead
// when you need an atomic ownership check + TTL push.
func (l *DistributedLock) Owns(ctx context.Context) (bool, error) {
	v, err := l.client.rdb.Get(ctx, l.key).Result()
	if errors.Is(err, goredis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("redis: lock owns %q: %w", l.key, err)
	}
	return v == l.value, nil
}

// randomToken returns a 16-byte hex-encoded random string. It uses
// crypto/rand so two locks created in the same nanosecond on the
// same process cannot collide; cryptographic strength is not
// required, but the alternative (time-based UUIDs) is more brittle.
func randomToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
