// Package cache hosts Redis-backed caches that short-circuit expensive
// downstream calls (AI inference, Rspamd) when the same content has been
// evaluated recently.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	redisclient "github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

// AIResult is the cached AI verdict. It is intentionally minimal so the
// cache stays small and the schema is stable.
type AIResult struct {
	Tier        constant.Tier      `json:"tier"`
	Category    constant.Category  `json:"category"`
	Secondary   []constant.Category `json:"secondary,omitempty"`
	Score       int                `json:"score"`
	Confidence  float64            `json:"confidence,omitempty"`
	ReasonCodes []string           `json:"reason_codes,omitempty"`
	Language    string             `json:"language,omitempty"`
	ModelTag    string             `json:"model_tag,omitempty"`
	StoredAt    time.Time          `json:"stored_at"`
}

// AICacheConfig configures AICache.
type AICacheConfig struct {
	// TTL controls how long entries survive. Default 1h.
	TTL time.Duration
	// KeyPrefix overrides the default "ai_cache:" prefix.
	KeyPrefix string
}

// AICache caches AI evaluation results keyed by a content fingerprint
// (normalised body + sender domain). It is safe for concurrent use.
type AICache struct {
	client *redisclient.Client
	cfg    AICacheConfig
}

// NewAICache constructs an AICache. Client is required.
func NewAICache(client *redisclient.Client, cfg AICacheConfig) (*AICache, error) {
	if client == nil {
		return nil, errors.New("cache: redis client is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "ai_cache:"
	}
	return &AICache{client: client, cfg: cfg}, nil
}

// Key returns the cache key for normalised body + sender domain.
// Exposed so callers (and tests) can verify determinism.
func (c *AICache) Key(body, senderDomain string) string {
	h := sha256.New()
	h.Write([]byte(normaliseBody(body)))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(strings.TrimSpace(senderDomain))))
	return c.cfg.KeyPrefix + hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached result for (body, senderDomain). The bool is
// false when there is no cache entry.
func (c *AICache) Get(ctx context.Context, body, senderDomain string) (AIResult, bool, error) {
	raw, ok, err := c.client.Get(ctx, c.Key(body, senderDomain))
	if err != nil || !ok {
		return AIResult{}, false, err
	}
	var out AIResult
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return AIResult{}, false, fmt.Errorf("ai_cache: unmarshal: %w", err)
	}
	return out, true, nil
}

// Set caches result for (body, senderDomain) under TTL.
func (c *AICache) Set(ctx context.Context, body, senderDomain string, result AIResult) error {
	if result.StoredAt.IsZero() {
		result.StoredAt = time.Now().UTC()
	}
	blob, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("ai_cache: marshal: %w", err)
	}
	return c.client.Set(ctx, c.Key(body, senderDomain), string(blob), c.cfg.TTL)
}

// Invalidate removes the cache entry for (body, senderDomain).
func (c *AICache) Invalidate(ctx context.Context, body, senderDomain string) error {
	return c.client.Del(ctx, c.Key(body, senderDomain))
}

// normaliseBody collapses whitespace and lowercases the body so trivial
// formatting differences do not bust the cache. Callers should strip
// reply quoted text and signatures upstream for best hit rate.
func normaliseBody(body string) string {
	body = strings.ToLower(body)
	body = strings.Join(strings.Fields(body), " ")
	return body
}
