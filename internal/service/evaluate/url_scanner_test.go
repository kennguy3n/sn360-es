package evaluate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeURLProvider struct {
	name    string
	calls   atomic.Int32
	results map[string]URLScanResult
	err     error
}

func (f *fakeURLProvider) Name() string { return f.name }

func (f *fakeURLProvider) LookupURL(_ context.Context, raw string) (URLScanResult, error) {
	f.calls.Add(1)
	if f.err != nil {
		return URLScanResult{}, f.err
	}
	if r, ok := f.results[raw]; ok {
		return r, nil
	}
	return URLScanResult{Verdict: URLVerdictUnknown}, nil
}

func TestURLScanner_ScanURLs_Aggregates(t *testing.T) {
	p := &fakeURLProvider{
		name: "fake",
		results: map[string]URLScanResult{
			"https://bad.example.com":   {Verdict: URLVerdictMalicious, Score: 100, MaliciousEngine: 5},
			"https://maybe.example.com": {Verdict: URLVerdictSuspicious, Score: 60, SuspiciousCount: 1},
			"https://good.example.com":  {Verdict: URLVerdictClean, Score: 0, HarmlessCount: 70},
		},
	}
	s, err := NewURLScanner(URLScannerConfig{Provider: p, Cache: NewMemoryURLCache()})
	if err != nil {
		t.Fatalf("NewURLScanner: %v", err)
	}
	res, err := s.ScanURLs(context.Background(), []string{
		"https://bad.example.com",
		"https://maybe.example.com",
		"https://good.example.com",
	})
	if err != nil {
		t.Fatalf("ScanURLs: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("results: %d", len(res))
	}
	if got := AggregateScore(res); got != 100 {
		t.Fatalf("aggregate score: %d", got)
	}
}

func TestURLScanner_DedupesAndCaches(t *testing.T) {
	p := &fakeURLProvider{
		name: "fake",
		results: map[string]URLScanResult{
			"https://bad.example.com": {Verdict: URLVerdictMalicious, Score: 100},
		},
	}
	cache := NewMemoryURLCache()
	s, _ := NewURLScanner(URLScannerConfig{Provider: p, Cache: cache})
	// Same URL repeated 4 times — should only trigger one provider call.
	_, _ = s.ScanURLs(context.Background(), []string{
		"https://bad.example.com",
		"https://bad.example.com",
		"https://bad.example.com",
		"https://bad.example.com",
	})
	if got := p.calls.Load(); got != 1 {
		t.Fatalf("provider calls after dedupe: %d", got)
	}
	// Second call should hit the cache.
	res, _ := s.ScanURLs(context.Background(), []string{"https://bad.example.com"})
	if p.calls.Load() != 1 {
		t.Fatalf("provider calls after cache hit: %d", p.calls.Load())
	}
	if !res[0].CachedHit {
		t.Fatal("expected cached_hit=true")
	}
}

func TestURLScanner_ProviderErrorIsRecorded(t *testing.T) {
	p := &fakeURLProvider{name: "fake", err: errors.New("rate limit")}
	s, _ := NewURLScanner(URLScannerConfig{Provider: p})
	res, _ := s.ScanURLs(context.Background(), []string{"https://x"})
	if len(res) != 1 || res[0].Verdict != URLVerdictUnknown {
		t.Fatalf("expected unknown verdict, got %+v", res)
	}
	if res[0].Err == "" {
		t.Fatal("expected error string in result")
	}
}

func TestURLScanner_EmptyInput(t *testing.T) {
	p := &fakeURLProvider{name: "fake"}
	s, _ := NewURLScanner(URLScannerConfig{Provider: p})
	res, err := s.ScanURLs(context.Background(), nil)
	if err != nil || res != nil {
		t.Fatalf("ScanURLs(nil): %v / %+v", err, res)
	}
}

func TestNewURLScanner_RequiresProvider(t *testing.T) {
	if _, err := NewURLScanner(URLScannerConfig{}); err == nil {
		t.Fatal("expected error for nil provider")
	}
}

func TestVirusTotalProvider_ParsesStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "key-1" {
			t.Errorf("missing api key header")
		}
		_, _ = w.Write([]byte(`{
			"data": {
				"attributes": {
					"last_analysis_stats": {
						"harmless": 80,
						"malicious": 3,
						"suspicious": 1,
						"undetected": 5,
						"timeout": 0
					}
				}
			}
		}`))
	}))
	t.Cleanup(srv.Close)

	p, err := NewVirusTotalProvider(VirusTotalConfig{APIKey: "key-1", BaseURL: srv.URL, Client: srv.Client()})
	if err != nil {
		t.Fatalf("NewVirusTotalProvider: %v", err)
	}
	res, err := p.LookupURL(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("LookupURL: %v", err)
	}
	if res.Verdict != URLVerdictMalicious || res.Score != 100 {
		t.Fatalf("unexpected verdict: %+v", res)
	}
	if res.MaliciousEngine != 3 || res.SuspiciousCount != 1 {
		t.Fatalf("counts: %+v", res)
	}
}

func TestVirusTotalProvider_RateLimitedReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	p, _ := NewVirusTotalProvider(VirusTotalConfig{APIKey: "key-1", BaseURL: srv.URL, Client: srv.Client()})
	_, err := p.LookupURL(context.Background(), "https://example.com")
	if err == nil {
		t.Fatal("expected rate limit error")
	}
}

func TestVirusTotalProvider_NotFoundIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	p, _ := NewVirusTotalProvider(VirusTotalConfig{APIKey: "key-1", BaseURL: srv.URL, Client: srv.Client()})
	res, err := p.LookupURL(context.Background(), "https://nope")
	if err != nil || res.Verdict != URLVerdictUnknown {
		t.Fatalf("expected unknown verdict, got %+v / %v", res, err)
	}
}

func TestVirusTotalProvider_BodyExactlyAtCapIsAccepted(t *testing.T) {
	// A valid response padded with insignificant trailing whitespace to
	// exactly the cap must parse, not be rejected as oversized.
	core := `{"data":{"attributes":{"last_analysis_stats":{"harmless":80,"malicious":3,"suspicious":1,"undetected":5,"timeout":0}}}}`
	body := core + strings.Repeat(" ", vtMaxResponseBytes-len(core))
	if len(body) != vtMaxResponseBytes {
		t.Fatalf("setup: body is %d bytes, want %d", len(body), vtMaxResponseBytes)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	p, _ := NewVirusTotalProvider(VirusTotalConfig{APIKey: "key-1", BaseURL: srv.URL, Client: srv.Client()})
	res, err := p.LookupURL(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("LookupURL at exact cap: %v", err)
	}
	if res.MaliciousEngine != 3 {
		t.Fatalf("unexpected parse: %+v", res)
	}
}

func TestVirusTotalProvider_OversizedBodyReturnsCapError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", vtMaxResponseBytes+1)))
	}))
	t.Cleanup(srv.Close)
	p, _ := NewVirusTotalProvider(VirusTotalConfig{APIKey: "key-1", BaseURL: srv.URL, Client: srv.Client()})
	_, err := p.LookupURL(context.Background(), "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "byte cap") {
		t.Fatalf("expected cap error, got %v", err)
	}
}

func TestCacheKey_Stable(t *testing.T) {
	a := CacheKey("https://example.com/")
	b := CacheKey("HTTPS://EXAMPLE.COM/  ")
	if a != b {
		t.Fatalf("cache keys differ: %q vs %q", a, b)
	}
}

func TestMemoryURLCache_TTLExpires(t *testing.T) {
	c := NewMemoryURLCache()
	c.now = func() time.Time { return time.Unix(1000, 0) }
	if err := c.Set(context.Background(), "k", URLScanResult{Score: 1}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	c.now = func() time.Time { return time.Unix(1000+120, 0) }
	if _, ok, _ := c.Get(context.Background(), "k"); ok {
		t.Fatal("expected cache miss after TTL")
	}
}
