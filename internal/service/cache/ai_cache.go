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

// ErrMissingTenantID is returned when a cache operation is called without
// a tenant ID. Every AI cache entry is tenant-scoped: a Tier 2 verdict
// depends on per-tenant context (vendor list, org graph, sensitivity
// tier), so sharing a verdict across tenants is both a correctness bug
// (wrong verdict for the second tenant) and a cost side-channel (tenant
// A subsidises tenant B's inference). Tenant ID is therefore mandatory
// and validated at the entry of every public method.
var ErrMissingTenantID = errors.New("ai_cache: tenant id is required")

// AIResult is the cached AI verdict. It is intentionally minimal so the
// cache stays small and the schema is stable.
type AIResult struct {
	Tier        constant.Tier       `json:"tier"`
	Category    constant.Category   `json:"category"`
	Secondary   []constant.Category `json:"secondary,omitempty"`
	Score       int                 `json:"score"`
	Confidence  float64             `json:"confidence,omitempty"`
	ReasonCodes []string            `json:"reason_codes,omitempty"`
	Language    string              `json:"language,omitempty"`
	ModelTag    string              `json:"model_tag,omitempty"`
	StoredAt    time.Time           `json:"stored_at"`
}

// AICacheConfig configures AICache.
type AICacheConfig struct {
	// TTL controls how long entries survive. Default 1h.
	TTL time.Duration
	// KeyPrefix overrides the default "ai_cache:" prefix.
	KeyPrefix string
}

// AICache caches AI evaluation results keyed by a content fingerprint
// (tenant ID + normalised body + sender domain). It is safe for
// concurrent use.
//
// The tenant ID is a mandatory component of the key. Two tenants that
// receive identical content do not share cache entries because Tier 2
// reasoning depends on tenant-specific context (vendor catalogue, org
// graph, sensitivity tier, per-tenant model fine-tuning). Sharing
// across tenants would (a) return a verdict computed under tenant A's
// context to tenant B and (b) act as a cross-tenant cost side-channel.
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

// Key returns the cache key for (tenantID, body, senderDomain). The
// returned key is namespaced by tenant so two tenants cannot share
// cache entries even when they receive byte-identical content. Empty
// tenantID is rejected at the public Get/Set/Invalidate entry points;
// Key panics on empty tenantID to make accidental cross-tenant fingerprinting
// impossible (the panic is caught by tests, never reached at runtime
// because Get/Set/Invalidate validate first).
func (c *AICache) Key(tenantID, body, senderDomain string) string {
	if tenantID == "" {
		panic("ai_cache: Key called with empty tenantID — callers must use Get/Set/Invalidate which validate")
	}
	h := sha256.New()
	// tenantID is bound into the key first so it cannot collide with a
	// (body, sender) pair from another tenant. The 0x00 separators are
	// length-binding so neither tenantID nor body can be crafted to
	// reproduce another tenant's hash.
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	h.Write([]byte(normaliseBody(body)))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(strings.TrimSpace(senderDomain))))
	return c.cfg.KeyPrefix + tenantID + ":" + hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached result for (tenantID, body, senderDomain). The
// bool is false when there is no cache entry. Returns ErrMissingTenantID
// if tenantID is empty.
func (c *AICache) Get(ctx context.Context, tenantID, body, senderDomain string) (AIResult, bool, error) {
	if tenantID == "" {
		return AIResult{}, false, ErrMissingTenantID
	}
	raw, ok, err := c.client.Get(ctx, c.Key(tenantID, body, senderDomain))
	if err != nil || !ok {
		return AIResult{}, false, err
	}
	var out AIResult
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return AIResult{}, false, fmt.Errorf("ai_cache: unmarshal: %w", err)
	}
	return out, true, nil
}

// Set caches result for (tenantID, body, senderDomain) under TTL.
// Returns ErrMissingTenantID if tenantID is empty.
func (c *AICache) Set(ctx context.Context, tenantID, body, senderDomain string, result AIResult) error {
	if tenantID == "" {
		return ErrMissingTenantID
	}
	if result.StoredAt.IsZero() {
		result.StoredAt = time.Now().UTC()
	}
	blob, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("ai_cache: marshal: %w", err)
	}
	return c.client.Set(ctx, c.Key(tenantID, body, senderDomain), string(blob), c.cfg.TTL)
}

// Invalidate removes the cache entry for (tenantID, body, senderDomain).
// Returns ErrMissingTenantID if tenantID is empty.
func (c *AICache) Invalidate(ctx context.Context, tenantID, body, senderDomain string) error {
	if tenantID == "" {
		return ErrMissingTenantID
	}
	return c.client.Del(ctx, c.Key(tenantID, body, senderDomain))
}

// normaliseBody collapses whitespace and lowercases the body so trivial
// formatting differences do not bust the cache. Callers should strip
// reply quoted text and signatures upstream for best hit rate.
func normaliseBody(body string) string {
	body = strings.ToLower(body)
	body = strings.Join(strings.Fields(body), " ")
	return body
}
