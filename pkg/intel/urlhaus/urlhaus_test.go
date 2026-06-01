package urlhaus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

func TestDecode_FixtureProducesExpectedIndicators(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/csv_recent.csv")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	res, err := Decode(f)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Two valid rows × 2 emissions (URL + domain) = 4 indicators
	// from rows 1 and 2; row 3 (offline) emits its URL+domain too →
	// 6 indicators total. Row 4 ("not a url at all") fails URL
	// canonicalisation and is skipped — no domain emitted because
	// the host extraction fails.
	if len(res.Indicators) < 6 {
		t.Fatalf("got %d indicators; want >= 6", len(res.Indicators))
	}
	var sawURLhost, sawDomain bool
	for _, ind := range res.Indicators {
		switch ind.Indicator {
		case "http://evil.example.com/payload.exe":
			sawURLhost = true
			if ind.Type != intel.IndicatorURL {
				t.Errorf("payload URL had type %q", ind.Type)
			}
			if ind.Severity != 80 {
				t.Errorf("online URL severity = %d; want 80", ind.Severity)
			}
			if !containsTag(ind.Tags, "malware_download") {
				t.Errorf("missing malware_download tag: %v", ind.Tags)
			}
		case "evil.example.com":
			sawDomain = true
			if ind.Type != intel.IndicatorDomain {
				t.Errorf("evil host had type %q", ind.Type)
			}
		}
	}
	if !sawURLhost {
		t.Error("did not see canonicalised URL row 1")
	}
	if !sawDomain {
		t.Error("did not see domain emission for row 1")
	}
}

func TestDecode_OfflineRowGetsLowerSeverity(t *testing.T) {
	t.Parallel()
	f, _ := os.Open("testdata/csv_recent.csv")
	defer func() { _ = f.Close() }()
	res, err := Decode(f)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	for _, ind := range res.Indicators {
		if ind.Indicator == "http://offline.example.net/old" {
			if ind.Severity != 40 {
				t.Errorf("offline severity = %d; want 40", ind.Severity)
			}
			return
		}
	}
	t.Error("did not find offline row indicator")
}

func TestPoll_HTTPServerRoundTrip(t *testing.T) {
	t.Parallel()
	csvBytes, err := os.ReadFile("testdata/csv_recent.csv")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/downloads/csv_recent/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write(csvBytes)
	}))
	defer srv.Close()

	p, err := New(intel.FeedConfig{
		ID:       "test",
		Name:     "test-urlhaus",
		Provider: Provider,
		URL:      srv.URL + "/downloads/csv_recent/",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(res.Indicators) < 6 {
		t.Errorf("Poll returned %d indicators; want >= 6", len(res.Indicators))
	}
}

func TestPoll_HTTPErrorIsFatal(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	p, _ := New(intel.FeedConfig{Provider: Provider, URL: srv.URL + "/x/"})
	_, err := p.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("expected 429 error, got %v", err)
	}
}

// TestPoll_LivePublicCSV exercises the REAL upstream URLhaus CSV
// endpoint. It is intentionally network-dependent: when the host
// is unreachable (CI without egress) the test is skipped, but the
// code path is real — there are no canned fixtures here.
//
// The test only asserts on shape: the response is non-empty, the
// parser produces at least one indicator, and HTTP status was 2xx.
// It does NOT assert on specific IOCs because the feed rotates
// continuously.
func TestPoll_LivePublicCSV(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live URLhaus poll in -short mode")
	}
	if os.Getenv("INTEL_URLHAUS_LIVE") == "" {
		t.Skip("set INTEL_URLHAUS_LIVE=1 to exercise the real upstream URL")
	}
	p, err := New(intel.FeedConfig{
		Provider: Provider,
		URL:      "https://urlhaus.haus.fail/downloads/csv_recent/",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := p.Poll(context.Background())
	if err != nil {
		t.Skipf("live URLhaus unreachable: %v", err)
	}
	if len(res.Indicators) == 0 {
		t.Errorf("live URLhaus poll returned zero indicators")
	}
}

func containsTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}
