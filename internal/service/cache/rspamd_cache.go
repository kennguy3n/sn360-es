package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	redisclient "github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

// RspamdResult is the cached Rspamd verdict.
type RspamdResult struct {
	// Score is the raw Rspamd score (positive = spammy, negative = ham).
	Score float64 `json:"score"`
	// RequiredScore is the threshold that Rspamd was configured with at
	// scoring time. Stored alongside the score so the score engine can
	// normalise consistently even when the threshold changes.
	RequiredScore float64 `json:"required_score"`
	// Action is the Rspamd action (no action, greylist, add header,
	// rewrite subject, reject).
	Action string `json:"action,omitempty"`
	// Symbols is the symbol map (name -> weight). Optional.
	Symbols map[string]float64 `json:"symbols,omitempty"`
	// SPF/DKIM/DMARC verdicts (pass/fail/none/softfail).
	SPF   string `json:"spf,omitempty"`
	DKIM  string `json:"dkim,omitempty"`
	DMARC string `json:"dmarc,omitempty"`
	// StoredAt is when this entry was written to cache.
	StoredAt time.Time `json:"stored_at"`
}

// RspamdCacheConfig configures RspamdCache.
type RspamdCacheConfig struct {
	// TTL controls how long entries survive. Default 30m.
	TTL time.Duration
	// KeyPrefix overrides the default "rspamd_cache:" prefix.
	KeyPrefix string
}

// RspamdCache caches Rspamd verdicts keyed by the SHA-256 of the raw
// mail bytes. It is safe for concurrent use.
type RspamdCache struct {
	client *redisclient.Client
	cfg    RspamdCacheConfig
}

// NewRspamdCache constructs an RspamdCache. Client is required.
func NewRspamdCache(client *redisclient.Client, cfg RspamdCacheConfig) (*RspamdCache, error) {
	if client == nil {
		return nil, errors.New("cache: redis client is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Minute
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "rspamd_cache:"
	}
	return &RspamdCache{client: client, cfg: cfg}, nil
}

// Key returns the cache key for raw mail bytes. Exposed so callers and
// tests can verify determinism.
func (c *RspamdCache) Key(rawMail []byte) string {
	h := sha256.New()
	h.Write(rawMail)
	return c.cfg.KeyPrefix + hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached Rspamd verdict for rawMail.
func (c *RspamdCache) Get(ctx context.Context, rawMail []byte) (RspamdResult, bool, error) {
	raw, ok, err := c.client.Get(ctx, c.Key(rawMail))
	if err != nil || !ok {
		return RspamdResult{}, false, err
	}
	var out RspamdResult
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return RspamdResult{}, false, fmt.Errorf("rspamd_cache: unmarshal: %w", err)
	}
	return out, true, nil
}

// Set caches result under TTL.
func (c *RspamdCache) Set(ctx context.Context, rawMail []byte, result RspamdResult) error {
	if result.StoredAt.IsZero() {
		result.StoredAt = time.Now().UTC()
	}
	blob, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("rspamd_cache: marshal: %w", err)
	}
	return c.client.Set(ctx, c.Key(rawMail), string(blob), c.cfg.TTL)
}

// Invalidate removes the cache entry for rawMail.
func (c *RspamdCache) Invalidate(ctx context.Context, rawMail []byte) error {
	return c.client.Del(ctx, c.Key(rawMail))
}
