// Package ingestion polls real mailboxes (Google Workspace / Microsoft
// 365) for new messages and emits `es.evaluate.request` events. The
// checkpoint store tracks the last successfully polled timestamp per
// (tenant, mailbox) tuple so a restart, a crash, or a leader handover
// only fetches messages that arrived after the last successful poll.
//
// The store is keyed by tenant + a SHA-256 of the mailbox identifier
// (typically the user's primary email). Hashing avoids leaking the
// raw address into Redis keys while preserving idempotency: the same
// (tenant, mailbox) tuple always maps to the same key.
package ingestion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

// CheckpointStoreTTL is the TTL applied to checkpoint keys. We use a
// generous 90 days so a tenant that pauses for a quarter does not
// silently restart from zero (which would refetch a quarter of mail
// and overwhelm the pipeline). Operators that need a hard floor can
// override it via NewCheckpointStore.
const CheckpointStoreTTL = 90 * 24 * time.Hour

// CheckpointStore is a Redis-backed map of (tenant, mailbox) -> last
// successful poll timestamp. Implementations are safe for concurrent
// use.
type CheckpointStore interface {
	// Get returns the last poll timestamp for (tenantID, mailbox).
	// Returns (zero, false, nil) when no checkpoint exists yet.
	Get(ctx context.Context, tenantID, mailbox string) (time.Time, bool, error)
	// Set persists the timestamp atomically. ts must be non-zero;
	// callers should pass the timestamp of the latest message they
	// successfully published, not "time.Now()", so the next poll
	// resumes exactly where this one left off.
	Set(ctx context.Context, tenantID, mailbox string, ts time.Time) error
}

// RedisCheckpointStore is the production implementation backed by the
// SN360 Redis wrapper.
type RedisCheckpointStore struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

// NewCheckpointStore wraps client. prefix lets test deployments share
// a Redis without colliding (the default is "ingestion:checkpoint").
// ttl <= 0 is replaced with CheckpointStoreTTL.
func NewCheckpointStore(client *redis.Client, prefix string, ttl time.Duration) (*RedisCheckpointStore, error) {
	if client == nil {
		return nil, errors.New("ingestion: checkpoint store requires a redis client")
	}
	if prefix == "" {
		prefix = "ingestion:checkpoint"
	}
	if ttl <= 0 {
		ttl = CheckpointStoreTTL
	}
	return &RedisCheckpointStore{client: client, prefix: prefix, ttl: ttl}, nil
}

// Get returns the stored timestamp for the (tenantID, mailbox) pair.
//
// The implementation accepts both string-encoded RFC3339 (legacy)
// and unix-nano integer payloads so a key written by an older binary
// still parses correctly on rollback.
func (s *RedisCheckpointStore) Get(ctx context.Context, tenantID, mailbox string) (time.Time, bool, error) {
	if tenantID == "" || mailbox == "" {
		return time.Time{}, false, errors.New("ingestion: checkpoint Get requires tenant_id and mailbox")
	}
	key := s.keyFor(tenantID, mailbox)
	raw, ok, err := s.client.Get(ctx, key)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("ingestion: checkpoint Get %q: %w", key, err)
	}
	if !ok {
		return time.Time{}, false, nil
	}
	ts, perr := parseCheckpoint(raw)
	if perr != nil {
		// Bad payload: delete it so the next Set heals the key.
		_ = s.client.Del(ctx, key)
		return time.Time{}, false, fmt.Errorf("ingestion: checkpoint Get %q: parse %w", key, perr)
	}
	return ts, true, nil
}

// Set persists ts under the (tenantID, mailbox) pair.
func (s *RedisCheckpointStore) Set(ctx context.Context, tenantID, mailbox string, ts time.Time) error {
	if tenantID == "" || mailbox == "" {
		return errors.New("ingestion: checkpoint Set requires tenant_id and mailbox")
	}
	if ts.IsZero() {
		return errors.New("ingestion: checkpoint Set timestamp must be non-zero")
	}
	key := s.keyFor(tenantID, mailbox)
	value := strconv.FormatInt(ts.UTC().UnixNano(), 10)
	if err := s.client.Set(ctx, key, value, s.ttl); err != nil {
		return fmt.Errorf("ingestion: checkpoint Set %q: %w", key, err)
	}
	return nil
}

// keyFor returns the Redis key for (tenantID, mailbox).
// Format: `{prefix}:{tenantID}:{sha256(mailbox-lowercase)-hex}`.
// Hashing the mailbox avoids leaking the email address into Redis
// keys while keeping the lookup O(1).
func (s *RedisCheckpointStore) keyFor(tenantID, mailbox string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(mailbox))))
	return fmt.Sprintf("%s:%s:%s", s.prefix, tenantID, hex.EncodeToString(sum[:]))
}

// parseCheckpoint accepts either a unix-nano integer or an RFC3339
// timestamp. The two formats coexist so a rolling upgrade does not
// require a key migration.
func parseCheckpoint(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errors.New("empty checkpoint")
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		// Treat as unix-nanoseconds.
		return time.Unix(0, n).UTC(), nil
	}
	if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return ts.UTC(), nil
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognised checkpoint format: %q", raw)
}
