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

// RspamdCache caches Rspamd verdicts keyed by tenantID + the SHA-256 of
// the raw mail bytes. It is safe for concurrent use.
//
// The tenant ID is a mandatory component of the key even though Rspamd
// scoring itself is content-pure (SPF/DKIM/DMARC + regex-driven
// symbols). Sharing entries across tenants would create a
// content-addressed timing side-channel: tenant A could probe whether a
// known-content email had recently been seen by any other tenant by
// observing cache hit/miss latency. The cost of an extra Rspamd call on
// a cross-tenant miss is small (Rspamd is in-cluster) and the privacy
// property (tenant A learns nothing about tenant B's mail flow) is
// worth more than the inter-tenant cache reuse. The same rationale that
// applies to AICache (see ai_cache.go) applies here.
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

// Key returns the cache key for (tenantID, rawMail) along with a
// validation error. The returned key is namespaced by tenant so two
// tenants cannot share cache entries even when they receive
// byte-identical content. An empty tenantID returns ErrMissingTenantID
// and a zero-value key — Go's error-return idiom rather than a panic,
// so a misuse by future direct callers degrades gracefully instead of
// crashing the request.
//
// The 0x00 separator between tenantID and rawMail is length-binding:
// no choice of inputs can craft an alternative (tenantID, rawMail)
// pair that hashes to the same value for a different tenant. The
// tenantID is also embedded verbatim in the key prefix so an operator
// can run `SCAN MATCH rspamd_cache:<tid>:*` for per-tenant
// invalidation.
func (c *RspamdCache) Key(tenantID string, rawMail []byte) (string, error) {
	if tenantID == "" {
		return "", ErrMissingTenantID
	}
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	h.Write(rawMail)
	return c.cfg.KeyPrefix + tenantID + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

// Get returns the cached Rspamd verdict for (tenantID, rawMail).
// Returns ErrMissingTenantID if tenantID is empty.
func (c *RspamdCache) Get(ctx context.Context, tenantID string, rawMail []byte) (RspamdResult, bool, error) {
	key, err := c.Key(tenantID, rawMail)
	if err != nil {
		return RspamdResult{}, false, err
	}
	raw, ok, err := c.client.Get(ctx, key)
	if err != nil || !ok {
		return RspamdResult{}, false, err
	}
	var out RspamdResult
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return RspamdResult{}, false, fmt.Errorf("rspamd_cache: unmarshal: %w", err)
	}
	return out, true, nil
}

// Set caches result for (tenantID, rawMail) under TTL. Returns
// ErrMissingTenantID if tenantID is empty.
func (c *RspamdCache) Set(ctx context.Context, tenantID string, rawMail []byte, result RspamdResult) error {
	key, err := c.Key(tenantID, rawMail)
	if err != nil {
		return err
	}
	if result.StoredAt.IsZero() {
		result.StoredAt = time.Now().UTC()
	}
	blob, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("rspamd_cache: marshal: %w", err)
	}
	return c.client.Set(ctx, key, string(blob), c.cfg.TTL)
}

// Invalidate removes the cache entry for (tenantID, rawMail). Returns
// ErrMissingTenantID if tenantID is empty.
func (c *RspamdCache) Invalidate(ctx context.Context, tenantID string, rawMail []byte) error {
	key, err := c.Key(tenantID, rawMail)
	if err != nil {
		return err
	}
	return c.client.Del(ctx, key)
}
