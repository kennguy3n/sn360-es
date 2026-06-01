package csv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

func TestParseOptions_Defaults(t *testing.T) {
	t.Parallel()
	opts, err := parseOptions(url.Values{})
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	if opts.Type != intel.IndicatorDomain {
		t.Errorf("default type = %q; want domain", opts.Type)
	}
	if opts.Column != 0 || opts.Severity != 60 || opts.SkipHeader {
		t.Errorf("unexpected defaults: %+v", opts)
	}
}

func TestParseOptions_Full(t *testing.T) {
	t.Parallel()
	v := url.Values{}
	v.Set("type", "url")
	v.Set("column", "2")
	v.Set("severity", "85")
	v.Add("tag", "phishtank")
	v.Add("tag", "open-source")
	v.Set("skip_header", "true")
	v.Set("comment", "#")
	opts, err := parseOptions(v)
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	if opts.Type != intel.IndicatorURL {
		t.Errorf("type = %q", opts.Type)
	}
	if opts.Column != 2 || opts.Severity != 85 || !opts.SkipHeader || opts.Comment != '#' {
		t.Errorf("opts = %+v", opts)
	}
	if len(opts.Tags) != 2 {
		t.Errorf("tags = %v", opts.Tags)
	}
}

func TestParseOptions_Rejects(t *testing.T) {
	t.Parallel()
	bad := []url.Values{
		{"type": []string{"bogus"}},
		{"column": []string{"-1"}},
		{"severity": []string{"500"}},
		{"comment": []string{"##"}},
		{"skip_header": []string{"maybe"}},
	}
	for _, b := range bad {
		_, err := parseOptions(b)
		if err == nil {
			t.Errorf("expected error for %v", b)
		}
	}
}

func TestDecode_FixtureWithHeaderAndComment(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/domains.csv")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	res, err := Decode(f, csvOptions{
		Type:       intel.IndicatorDomain,
		Column:     0,
		Severity:   75,
		SkipHeader: true,
		Comment:    '#',
		Tags:       []string{"src=phishtank"},
	})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// 3 valid domain rows (blank row dropped, comment dropped, header dropped)
	if len(res.Indicators) != 3 {
		t.Fatalf("got %d indicators; want 3", len(res.Indicators))
	}
	for _, ind := range res.Indicators {
		if ind.Severity != 75 {
			t.Errorf("severity = %d; want 75", ind.Severity)
		}
		if len(ind.Tags) != 1 || ind.Tags[0] != "src=phishtank" {
			t.Errorf("tags = %v", ind.Tags)
		}
	}
}

func TestPoll_RoundTripStripsKnobs(t *testing.T) {
	t.Parallel()
	csvBytes, _ := os.ReadFile("testdata/domains.csv")
	var lastQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.Query()
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write(csvBytes)
	}))
	defer srv.Close()

	feedURL := srv.URL + "/iocs.csv?type=domain&column=0&severity=75&skip_header=true&comment=%23&tag=src1&keep_me=1"
	p, err := New(intel.FeedConfig{
		Provider: Provider,
		URL:      feedURL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(res.Indicators) == 0 {
		t.Error("zero indicators")
	}
	// Server should have received only `keep_me=1`, not our knobs.
	if lastQuery.Get("keep_me") != "1" {
		t.Errorf("keep_me dropped: %v", lastQuery)
	}
	if lastQuery.Get("type") != "" || lastQuery.Get("severity") != "" {
		t.Errorf("knob params leaked to upstream: %v", lastQuery)
	}
}

func TestNew_RejectsBadQuery(t *testing.T) {
	t.Parallel()
	_, err := New(intel.FeedConfig{
		Provider: Provider,
		URL:      "https://x/iocs.csv?type=bogus",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid type") {
		t.Errorf("expected invalid-type error, got %v", err)
	}
}
