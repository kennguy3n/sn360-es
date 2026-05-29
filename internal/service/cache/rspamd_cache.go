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

// Key returns the cache key for (tenantID, rawMail). The returned key
// is namespaced by tenant so two tenants cannot share cache entries
// even when they receive byte-identical content. Empty tenantID is
// rejected at the public Get/Set/Invalidate entry points; Key panics
// on empty tenantID to make accidental cross-tenant fingerprinting
// impossible (the panic is caught by tests, never reached at runtime
// because Get/Set/Invalidate validate first).
func (c *RspamdCache) Key(tenantID string, rawMail []byte) string {
	if tenantID == "" {
		panic("rspamd_cache: Key called with empty tenantID — callers must use Get/Set/Invalidate which validate")
	}
	h := sha256.New()
	// tenantID is bound into the key first so it cannot collide with a
	// rawMail payload from another tenant. The 0x00 separator is
	// length-binding so neither tenantID nor rawMail can be crafted to
	// reproduce another tenant's hash.
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	h.Write(rawMail)
	return c.cfg.KeyPrefix + tenantID + ":" + hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached Rspamd verdict for (tenantID, rawMail).
// Returns ErrMissingTenantID if tenantID is empty.
func (c *RspamdCache) Get(ctx context.Context, tenantID string, rawMail []byte) (RspamdResult, bool, error) {
	if tenantID == "" {
		return RspamdResult{}, false, ErrMissingTenantID
	}
	raw, ok, err := c.client.Get(ctx, c.Key(tenantID, rawMail))
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
	if tenantID == "" {
		return ErrMissingTenantID
	}
	if result.StoredAt.IsZero() {
		result.StoredAt = time.Now().UTC()
	}
	blob, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("rspamd_cache: marshal: %w", err)
	}
	return c.client.Set(ctx, c.Key(tenantID, rawMail), string(blob), c.cfg.TTL)
}

// Invalidate removes the cache entry for (tenantID, rawMail). Returns
// ErrMissingTenantID if tenantID is empty.
func (c *RspamdCache) Invalidate(ctx context.Context, tenantID string, rawMail []byte) error {
	if tenantID == "" {
		return ErrMissingTenantID
	}
	return c.client.Del(ctx, c.Key(tenantID, rawMail))
}
