// Package evaluate URL pre-scanner.
//
// Implements PROPOSAL.md §8 "URL pre-scanning" and ARCHITECTURE.md §5.3
// (parallel signal alongside Rspamd). The scanner runs against a
// pluggable URLIntelProvider (default: VirusTotal v3), caches verdicts
// in Redis under `url_scan:{sha256(url)}` with 1h TTL, and applies
// concurrency limits so a single malicious email with hundreds of
// links cannot DoS the inference pipeline.
//
// The package has zero hard dependencies on VirusTotal SDK packages so
// it can be compiled and tested in any environment.
package evaluate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// URLVerdict is the normalised scan outcome.
type URLVerdict string

const (
	// URLVerdictUnknown is used when no provider returned a definitive
	// answer (e.g. brand new URL, rate-limited).
	URLVerdictUnknown URLVerdict = "unknown"
	// URLVerdictClean means the URL is benign.
	URLVerdictClean URLVerdict = "clean"
	// URLVerdictSuspicious means at least one engine flagged the URL
	// but no clean consensus exists.
	URLVerdictSuspicious URLVerdict = "suspicious"
	// URLVerdictMalicious means multiple engines flagged the URL.
	URLVerdictMalicious URLVerdict = "malicious"
)

// URLScanResult is the per-URL result the scanner returns.
type URLScanResult struct {
	URL             string     `json:"url"`
	URLHash         string     `json:"url_hash"`
	Verdict         URLVerdict `json:"verdict"`
	Score           int        `json:"score"`
	Provider        string     `json:"provider"`
	MaliciousEngine int        `json:"malicious_engine_count"`
	SuspiciousCount int        `json:"suspicious_engine_count"`
	HarmlessCount   int        `json:"harmless_engine_count"`
	CachedAt        time.Time  `json:"cached_at,omitempty"`
	CachedHit       bool       `json:"cached_hit"`
	Err             string     `json:"error,omitempty"`
}

// URLIntelProvider is the abstraction across URL reputation services.
// The default implementation is the VirusTotal v3 client below; tests
// inject deterministic providers.
type URLIntelProvider interface {
	Name() string
	LookupURL(ctx context.Context, raw string) (URLScanResult, error)
}

// URLCache is the cache contract. Redis implementations can satisfy it
// via a thin adapter — the package does not depend on a specific Redis
// client.
type URLCache interface {
	Get(ctx context.Context, key string) (URLScanResult, bool, error)
	Set(ctx context.Context, key string, v URLScanResult, ttl time.Duration) error
}

// URLScannerConfig wires the scanner.
type URLScannerConfig struct {
	Provider    URLIntelProvider
	Cache       URLCache
	Logger      *slog.Logger
	Concurrency int           // 0 -> 4
	CacheTTL    time.Duration // 0 -> 1 hour
	PerScan     time.Duration // 0 -> 5s
	Now         func() time.Time
}

// URLScanner aggregates per-URL verdicts into a single signal usable
// by the scorer (`links` weight category).
type URLScanner struct {
	cfg URLScannerConfig
	log *slog.Logger
	now func() time.Time
	sem chan struct{}
}

// NewURLScanner constructs the scanner.
func NewURLScanner(cfg URLScannerConfig) (*URLScanner, error) {
	if cfg.Provider == nil {
		return nil, errors.New("url scanner: provider required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.PerScan <= 0 {
		cfg.PerScan = 5 * time.Second
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &URLScanner{
		cfg: cfg,
		log: cfg.Logger,
		now: now,
		sem: make(chan struct{}, cfg.Concurrency),
	}, nil
}

// CacheKey returns the Redis key for a URL. Exported so callers can
// pre-warm or introspect the cache from operations tooling.
func CacheKey(raw string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(raw))))
	return "url_scan:" + hex.EncodeToString(h[:])
}

// ScanURLs runs the configured provider against each URL in parallel
// (bounded by Concurrency), caches results, and returns the aggregated
// per-URL findings. Duplicate URLs in the input are deduplicated so a
// link spammed 50 times in an email only counts once.
func (s *URLScanner) ScanURLs(ctx context.Context, urls []string) ([]URLScanResult, error) {
	if s == nil {
		return nil, errors.New("url scanner: nil receiver")
	}
	deduped := dedupURLs(urls)
	if len(deduped) == 0 {
		return nil, nil
	}
	results := make([]URLScanResult, len(deduped))
	var wg sync.WaitGroup
	wg.Add(len(deduped))
	for i, u := range deduped {
		i, u := i, u
		go func() {
			defer wg.Done()
			results[i] = s.scanOne(ctx, u)
		}()
	}
	wg.Wait()
	return results, nil
}

// AggregateScore returns a 0-100 risk score across the supplied per-URL
// verdicts. Malicious findings dominate; suspicious add a smaller
// contribution; clean and unknown contribute zero. The output is the
// `links` weight category for the scorer.
func AggregateScore(results []URLScanResult) int {
	maxScore := 0
	for _, r := range results {
		if r.Score > maxScore {
			maxScore = r.Score
		}
	}
	return maxScore
}

func (s *URLScanner) scanOne(ctx context.Context, raw string) URLScanResult {
	key := CacheKey(raw)
	if s.cfg.Cache != nil {
		if got, ok, err := s.cfg.Cache.Get(ctx, key); err == nil && ok {
			got.CachedHit = true
			got.URL = raw
			got.URLHash = key
			return got
		} else if err != nil {
			s.log.WarnContext(ctx, "url_scanner: cache get failed", slog.Any("err", err))
		}
	}

	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	cctx, cancel := context.WithTimeout(ctx, s.cfg.PerScan)
	defer cancel()
	res, err := s.cfg.Provider.LookupURL(cctx, raw)
	if err != nil {
		s.log.WarnContext(ctx, "url_scanner: lookup failed",
			slog.String("url_hash", key),
			slog.Any("err", err),
		)
		return URLScanResult{URL: raw, URLHash: key, Provider: s.cfg.Provider.Name(), Verdict: URLVerdictUnknown, Err: err.Error(), CachedAt: s.now()}
	}
	res.URL = raw
	res.URLHash = key
	if res.Provider == "" {
		res.Provider = s.cfg.Provider.Name()
	}
	if res.Verdict == "" {
		res.Verdict = URLVerdictUnknown
	}
	res.CachedAt = s.now()
	if s.cfg.Cache != nil {
		if err := s.cfg.Cache.Set(ctx, key, res, s.cfg.CacheTTL); err != nil {
			s.log.WarnContext(ctx, "url_scanner: cache set failed", slog.Any("err", err))
		}
	}
	return res
}

func dedupURLs(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, u := range in {
		k := strings.ToLower(strings.TrimSpace(u))
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, u)
	}
	return out
}

// --- VirusTotal provider --------------------------------------------------

// vtMaxResponseBytes caps how much of a VirusTotal response we read. A
// VT v3 URL report is a few KiB of JSON; 1 MiB is ample headroom while
// preventing a misbehaving or compromised upstream from exhausting
// evaluator memory.
const vtMaxResponseBytes = 1 << 20

// VirusTotalProvider implements URLIntelProvider against the
// VirusTotal v3 REST API. It uses standard library HTTP with an
// optional override client for tests.
type VirusTotalProvider struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// VirusTotalConfig configures the provider.
type VirusTotalConfig struct {
	APIKey  string
	BaseURL string
	Client  *http.Client
}

// NewVirusTotalProvider constructs a configured provider.
func NewVirusTotalProvider(cfg VirusTotalConfig) (*VirusTotalProvider, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("virustotal: api key required")
	}
	base := cfg.BaseURL
	if base == "" {
		base = "https://www.virustotal.com/api/v3"
	}
	c := cfg.Client
	if c == nil {
		c = &http.Client{Timeout: 8 * time.Second}
	}
	return &VirusTotalProvider{httpClient: c, baseURL: base, apiKey: cfg.APIKey}, nil
}

// Name implements URLIntelProvider.
func (p *VirusTotalProvider) Name() string { return "virustotal" }

// LookupURL implements URLIntelProvider. VirusTotal addresses URLs by
// their URL-ID, which is base64url(sha256(url)) without padding; we
// hit the URL-ID lookup endpoint directly to avoid the indirection of
// the /urls submission endpoint.
func (p *VirusTotalProvider) LookupURL(ctx context.Context, raw string) (URLScanResult, error) {
	id := vtURLID(raw)
	endpoint := p.baseURL + "/urls/" + url.PathEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return URLScanResult{Verdict: URLVerdictUnknown}, fmt.Errorf("virustotal: build request: %w", err)
	}
	req.Header.Set("x-apikey", p.apiKey)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return URLScanResult{Verdict: URLVerdictUnknown}, fmt.Errorf("virustotal: request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, vtMaxResponseBytes))
	if err != nil {
		return URLScanResult{Verdict: URLVerdictUnknown}, fmt.Errorf("virustotal: read response: %w", err)
	}
	// Hitting the cap means the body was truncated; report that explicitly
	// rather than letting parseVTResponse surface an opaque JSON decode error.
	if len(body) >= vtMaxResponseBytes {
		return URLScanResult{Verdict: URLVerdictUnknown}, fmt.Errorf("virustotal: response exceeds %d byte cap", vtMaxResponseBytes)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return parseVTResponse(body)
	case http.StatusNotFound:
		return URLScanResult{Verdict: URLVerdictUnknown}, nil
	case http.StatusTooManyRequests:
		return URLScanResult{Verdict: URLVerdictUnknown}, errors.New("virustotal: rate limited")
	default:
		return URLScanResult{Verdict: URLVerdictUnknown}, fmt.Errorf("virustotal: http %d", resp.StatusCode)
	}
}

// vtURLID computes the VirusTotal URL identifier. The format is base64url
// of the SHA-256 of the URL with no padding.
func vtURLID(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

type vtResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Suspicious int `json:"suspicious"`
				Malicious  int `json:"malicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

func parseVTResponse(body []byte) (URLScanResult, error) {
	var v vtResponse
	if err := json.Unmarshal(body, &v); err != nil {
		return URLScanResult{Verdict: URLVerdictUnknown}, fmt.Errorf("virustotal: decode: %w", err)
	}
	s := v.Data.Attributes.LastAnalysisStats
	verdict := URLVerdictClean
	score := 0
	switch {
	case s.Malicious >= 2:
		verdict = URLVerdictMalicious
		score = 100
	case s.Malicious == 1 || s.Suspicious >= 2:
		verdict = URLVerdictSuspicious
		score = 70
	case s.Suspicious == 1:
		verdict = URLVerdictSuspicious
		score = 40
	case s.Harmless == 0 && s.Malicious == 0 && s.Suspicious == 0:
		verdict = URLVerdictUnknown
		score = 0
	}
	return URLScanResult{
		Verdict:         verdict,
		Score:           score,
		MaliciousEngine: s.Malicious,
		SuspiciousCount: s.Suspicious,
		HarmlessCount:   s.Harmless,
		Provider:        "virustotal",
	}, nil
}

// --- In-memory cache (tests) ---------------------------------------------

// MemoryURLCache is a thread-safe in-memory cache used by tests. It
// respects the supplied TTL and lazily expires entries on Get.
type MemoryURLCache struct {
	mu    sync.Mutex
	items map[string]memoryURLEntry
	now   func() time.Time
}

type memoryURLEntry struct {
	value     URLScanResult
	expiresAt time.Time
}

// NewMemoryURLCache constructs a fresh cache.
func NewMemoryURLCache() *MemoryURLCache {
	return &MemoryURLCache{items: map[string]memoryURLEntry{}, now: func() time.Time { return time.Now().UTC() }}
}

// Get implements URLCache.
func (c *MemoryURLCache) Get(_ context.Context, key string) (URLScanResult, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok {
		return URLScanResult{}, false, nil
	}
	if c.now().After(e.expiresAt) {
		delete(c.items, key)
		return URLScanResult{}, false, nil
	}
	return e.value, true, nil
}

// Set implements URLCache.
func (c *MemoryURLCache) Set(_ context.Context, key string, v URLScanResult, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = memoryURLEntry{value: v, expiresAt: c.now().Add(ttl)}
	return nil
}
