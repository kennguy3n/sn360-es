package misp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

func TestDecode_FixtureMaps(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/restsearch_page1.json")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	res, err := Decode(f)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// 6 attributes; mutex dropped → 5 mapped, two of which are
	// (url|domain) at threat_level=1, sha256, ip-src and one
	// to_ids=false url → severity 30.
	if got := len(res.Indicators); got != 5 {
		t.Fatalf("got %d indicators; want 5: %#v", got, res.Indicators)
	}

	want := map[string]intel.IndicatorType{
		"http://bad.example.com/dropper":     intel.IndicatorURL,
		"bad.example.com":                    intel.IndicatorDomain,
		"203.0.113.42":                       intel.IndicatorIP,
		"http://informational.example.org/x": intel.IndicatorURL,
	}
	for _, ind := range res.Indicators {
		if expectedType, ok := want[ind.Indicator]; ok {
			if ind.Type != expectedType {
				t.Errorf("%q type = %q; want %q", ind.Indicator, ind.Type, expectedType)
			}
			delete(want, ind.Indicator)
		}
		if ind.Indicator == "http://informational.example.org/x" {
			if ind.Severity != 30 {
				t.Errorf("to_ids=false should drop severity to 30; got %d", ind.Severity)
			}
		}
		if ind.Indicator == "bad.example.com" {
			if ind.Severity != 90 {
				t.Errorf("threat_level=1 + to_ids should be severity 90; got %d", ind.Severity)
			}
		}
		if ind.Type == intel.IndicatorSHA256 {
			if len(ind.Indicator) != 64 {
				t.Errorf("sha256 length %d; want 64", len(ind.Indicator))
			}
		}
	}
	for missing := range want {
		t.Errorf("did not see indicator %q", missing)
	}
}

func TestPoll_AuthAndPagination(t *testing.T) {
	t.Parallel()
	page1, _ := os.ReadFile("testdata/restsearch_page1.json")
	calls := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/events/restSearch" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "test-key" {
			http.Error(w, "no auth", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req searchRequest
		_ = json.Unmarshal(body, &req)
		calls.Add(1)
		if req.Page == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(page1)
			return
		}
		// Second page returns the empty-array termination
		// signal so the loop exits cleanly.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response": []}`))
	}))
	defer srv.Close()

	p, err := New(intel.FeedConfig{
		Provider: Provider,
		URL:      srv.URL,
		APIKey:   "test-key",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if calls.Load() < 1 {
		t.Error("server received zero requests")
	}
	if len(res.Indicators) != 5 {
		t.Errorf("Indicators count = %d; want 5", len(res.Indicators))
	}
}

func TestNew_RejectsMissingAPIKey(t *testing.T) {
	t.Parallel()
	_, err := New(intel.FeedConfig{Provider: Provider, URL: "https://x/"})
	if err == nil || !strings.Contains(err.Error(), "api key") {
		t.Errorf("expected api-key error, got %v", err)
	}
}

func TestPoll_NonRetryableUpstreamError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	p, _ := New(intel.FeedConfig{Provider: Provider, URL: srv.URL, APIKey: "x"})
	_, err := p.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403, got %v", err)
	}
}
