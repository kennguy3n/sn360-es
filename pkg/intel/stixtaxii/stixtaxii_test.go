package stixtaxii

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

func TestDecode_FixtureExtractsAllPatterns(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/objects_page1.json")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	res, err := Decode(f)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// indicators page1: 1 domain, 2 from compound (url + domain), 1 ip, 1 sha256 = 5 indicators
	if got := len(res.Indicators); got != 5 {
		for _, ind := range res.Indicators {
			t.Logf("  - %s (%s)", ind.Indicator, ind.Type)
		}
		t.Fatalf("got %d indicators; want 5", got)
	}

	seen := make(map[string]intel.IndicatorType)
	for _, ind := range res.Indicators {
		seen[ind.Indicator] = ind.Type
	}
	if seen["eviltaxii.example"] != intel.IndicatorDomain {
		t.Errorf("missing eviltaxii.example")
	}
	if seen["http://taxii-malware.example/dropper"] != intel.IndicatorURL {
		t.Errorf("missing taxii-malware URL")
	}
	if seen["taxii-malware.example"] != intel.IndicatorDomain {
		t.Errorf("missing taxii-malware domain")
	}
	if seen["198.51.100.7"] != intel.IndicatorIP {
		t.Errorf("missing IP indicator")
	}
}

func TestDecode_ConfidenceMapsToSeverity(t *testing.T) {
	t.Parallel()
	f, _ := os.Open("testdata/objects_page1.json")
	defer func() { _ = f.Close() }()
	res, _ := Decode(f)
	for _, ind := range res.Indicators {
		switch ind.Indicator {
		case "eviltaxii.example":
			if ind.Severity != 85 {
				t.Errorf("severity = %d; want 85", ind.Severity)
			}
		case "198.51.100.7":
			// No confidence → default 60
			if ind.Severity != 60 {
				t.Errorf("severity = %d; want 60", ind.Severity)
			}
		}
	}
}

func TestPoll_CursorPagination(t *testing.T) {
	t.Parallel()
	page1, _ := os.ReadFile("testdata/objects_page1.json")
	page2, _ := os.ReadFile("testdata/objects_page2.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		next := r.URL.Query().Get("next")
		if next == "cursor-page-2" {
			_, _ = w.Write(page2)
			return
		}
		_, _ = w.Write(page1)
	}))
	defer srv.Close()

	p, err := New(intel.FeedConfig{
		Provider: Provider,
		URL:      srv.URL + "/taxii2/collections/abcd/objects/",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	// page 1: 5 indicators, page 2: 1 indicator = 6
	if len(res.Indicators) != 6 {
		t.Errorf("got %d indicators; want 6", len(res.Indicators))
	}
}

func TestPoll_BearerAuthHeader(t *testing.T) {
	t.Parallel()
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/taxii+json")
		_, _ = w.Write([]byte(`{"more": false, "objects": []}`))
	}))
	defer srv.Close()
	p, _ := New(intel.FeedConfig{
		Provider: Provider,
		URL:      srv.URL + "/x/",
		APIKey:   "taxii-token",
	})
	_, _ = p.Poll(context.Background())
	if gotAuth != "Bearer taxii-token" {
		t.Errorf("auth header = %q; want Bearer taxii-token", gotAuth)
	}
}

func TestPoll_HTTPErrorFatal(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer srv.Close()
	p, _ := New(intel.FeedConfig{Provider: Provider, URL: srv.URL + "/x/"})
	_, err := p.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 error, got %v", err)
	}
}

func TestParsePattern_DropsUnsupportedClauses(t *testing.T) {
	t.Parallel()
	in := "[some-unsupported:value = 'x'] OR [domain-name:value = 'real.example']"
	cls := parsePattern(in)
	if len(cls) != 1 {
		t.Fatalf("got %d clauses; want 1", len(cls))
	}
	if cls[0].typ != intel.IndicatorDomain || cls[0].value != "real.example" {
		t.Errorf("clause = %+v", cls[0])
	}
}

func TestParsePattern_UnquoteEscapes(t *testing.T) {
	t.Parallel()
	in := `[domain-name:value = 'has\'apostrophe.example']`
	cls := parsePattern(in)
	if len(cls) != 1 {
		t.Fatalf("clauses = %d", len(cls))
	}
	if cls[0].value != "has'apostrophe.example" {
		t.Errorf("value = %q", cls[0].value)
	}
}

func TestBoolish_VariantParsings(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		`true`:       true,
		`false`:      false,
		`"true"`:     true,
		`"false"`:    false,
		`1`:          true,
		`0`:          false,
		`"1"`:        true,
		`"0"`:        false,
		`null`:       false,
	}
	for in, want := range cases {
		var b boolish
		if err := b.UnmarshalJSON([]byte(in)); err != nil {
			t.Errorf("UnmarshalJSON(%q): %v", in, err)
			continue
		}
		if bool(b) != want {
			t.Errorf("%q → %v; want %v", in, bool(b), want)
		}
	}
}
