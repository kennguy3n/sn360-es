package tier0

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// stubChecker is a hand-rolled TIChecker fake — preferred over a
// mock-by-codegen because it makes the test's intent obvious.
type stubChecker struct {
	matches []intel.MatchedIndicator
	err     error
	calls   int
}

func (s *stubChecker) Check(_ context.Context, _ dto.EvaluateRequest, _ dto.RiskSignals) ([]intel.MatchedIndicator, error) {
	s.calls++
	return s.matches, s.err
}

type stubObserver struct {
	lookups []string
	matches []string
}

func (s *stubObserver) ObserveLookup(outcome string) { s.lookups = append(s.lookups, outcome) }
func (s *stubObserver) ObserveMatch(tier string)     { s.matches = append(s.matches, tier) }

func mkMatch(name string, severity int, kind intel.IndicatorType) intel.MatchedIndicator {
	return intel.MatchedIndicator{
		Indicator:     name,
		IndicatorType: kind,
		FeedID:        "feed-" + name,
		FeedName:      "feed-" + name,
		Severity:      severity,
	}
}

func TestApplyTIMatch_BlockSeverity(t *testing.T) {
	t.Parallel()
	checker := &stubChecker{
		matches: []intel.MatchedIndicator{mkMatch("evil.example", 80, intel.IndicatorDomain)},
	}
	obs := &stubObserver{}
	g := NewGate(DefaultGateConfig(), nil).
		WithTIChecker(checker).
		WithTIObserver(obs)
	out := g.ApplyWithContext(context.Background(),
		dto.EvaluateRequest{Sender: "atk@evil.example"},
		dto.RiskSignals{SenderDomain: "evil.example"})

	if out.Reason != "ti_match" {
		t.Errorf("Reason = %q; want ti_match", out.Reason)
	}
	if !out.Bypass || !out.SkipML {
		t.Errorf("expected Bypass+SkipML; got bypass=%v skipml=%v", out.Bypass, out.SkipML)
	}
	if out.ForcedCategory != constant.CategoryLikelyPhishing {
		t.Errorf("ForcedCategory = %q; want LikelyPhishing", out.ForcedCategory)
	}
	if out.TIMatch == nil || out.TIMatch.Severity != 80 {
		t.Errorf("TIMatch metadata not attached: %+v", out.TIMatch)
	}
	if got := obs.matches; !reflect.DeepEqual(got, []string{"block"}) {
		t.Errorf("ObserveMatch = %v; want [block]", got)
	}
	if got := obs.lookups; !reflect.DeepEqual(got, []string{"hit"}) {
		t.Errorf("ObserveLookup = %v; want [hit]", got)
	}
}

func TestApplyTIMatch_QuarantineSeverity(t *testing.T) {
	t.Parallel()
	checker := &stubChecker{
		matches: []intel.MatchedIndicator{mkMatch("sus.example", 60, intel.IndicatorDomain)},
	}
	g := NewGate(DefaultGateConfig(), nil).WithTIChecker(checker)
	out := g.ApplyWithContext(context.Background(),
		dto.EvaluateRequest{Sender: "x@sus.example"},
		dto.RiskSignals{SenderDomain: "sus.example"})
	if !out.Bypass || !out.SkipML {
		t.Fatal("expected Bypass+SkipML")
	}
	if out.ForcedCategory != constant.CategorySuspiciousURL {
		t.Errorf("ForcedCategory = %q; want SuspiciousURL", out.ForcedCategory)
	}
}

func TestApplyTIMatch_FlagSeverityDoesNotBypass(t *testing.T) {
	t.Parallel()
	checker := &stubChecker{
		matches: []intel.MatchedIndicator{mkMatch("low.example", 30, intel.IndicatorDomain)},
	}
	g := NewGate(DefaultGateConfig(), nil).WithTIChecker(checker)
	out := g.ApplyWithContext(context.Background(),
		dto.EvaluateRequest{Sender: "x@low.example"},
		dto.RiskSignals{SenderDomain: "low.example"})
	if out.Bypass {
		t.Error("flag-severity should NOT bypass")
	}
	if !out.ForceEscalate {
		t.Error("flag-severity should ForceEscalate to Tier 2")
	}
	if out.Reason != "ti_match" {
		t.Errorf("Reason = %q; want ti_match", out.Reason)
	}
	if out.TIMatch == nil || out.TIMatch.Severity != 30 {
		t.Errorf("TIMatch metadata not attached")
	}
}

func TestApplyTIMatch_OverridesInternalTrusted(t *testing.T) {
	t.Parallel()
	// Even a sender that would otherwise be internal-trusted-bypassed
	// MUST be quarantined when a high-severity IOC matches.
	checker := &stubChecker{
		matches: []intel.MatchedIndicator{mkMatch("internal.example", 90, intel.IndicatorDomain)},
	}
	g := NewGate(DefaultGateConfig(), nil).WithTIChecker(checker)
	out := g.ApplyWithContext(context.Background(),
		dto.EvaluateRequest{Sender: "boss@internal.example"},
		dto.RiskSignals{IsInternal: true, SenderDomain: "internal.example"})
	if out.Reason != "ti_match" {
		t.Errorf("Reason = %q; want ti_match (overrides internal_trusted)", out.Reason)
	}
	if out.ForcedCategory != constant.CategoryLikelyPhishing {
		t.Errorf("ForcedCategory = %q; want LikelyPhishing", out.ForcedCategory)
	}
}

func TestApplyTIMatch_NoMatchFallsThrough(t *testing.T) {
	t.Parallel()
	checker := &stubChecker{} // no matches
	obs := &stubObserver{}
	g := NewGate(DefaultGateConfig(), nil).WithTIChecker(checker).WithTIObserver(obs)
	out := g.ApplyWithContext(context.Background(),
		dto.EvaluateRequest{Sender: "x@internal.example"},
		dto.RiskSignals{IsInternal: true, SenderDomain: "internal.example"})
	if out.Reason != "internal_trusted" {
		t.Errorf("Reason = %q; want internal_trusted (fallthrough)", out.Reason)
	}
	if got := obs.lookups; !reflect.DeepEqual(got, []string{"miss"}) {
		t.Errorf("ObserveLookup = %v; want [miss]", got)
	}
}

func TestApplyTIMatch_LookupErrorIsSoftFail(t *testing.T) {
	t.Parallel()
	checker := &stubChecker{err: errors.New("db down")}
	obs := &stubObserver{}
	g := NewGate(DefaultGateConfig(), nil).WithTIChecker(checker).WithTIObserver(obs)
	out := g.ApplyWithContext(context.Background(),
		dto.EvaluateRequest{Sender: "x@internal.example"},
		dto.RiskSignals{IsInternal: true, SenderDomain: "internal.example"})
	if out.Reason != "internal_trusted" {
		t.Errorf("Reason = %q; want internal_trusted (soft-fail fallthrough)", out.Reason)
	}
	if got := obs.lookups; !reflect.DeepEqual(got, []string{"error"}) {
		t.Errorf("ObserveLookup = %v; want [error]", got)
	}
}

func TestApplyTIMatch_NoCheckerInstalled(t *testing.T) {
	t.Parallel()
	g := NewGate(DefaultGateConfig(), nil)
	out := g.ApplyWithContext(context.Background(),
		dto.EvaluateRequest{Sender: "x@internal.example"},
		dto.RiskSignals{IsInternal: true, SenderDomain: "internal.example"})
	if out.Reason != "internal_trusted" {
		t.Errorf("Reason = %q; expected internal_trusted (no checker)", out.Reason)
	}
}

func TestPickStrongest_MultiFeed(t *testing.T) {
	t.Parallel()
	matches := []intel.MatchedIndicator{
		{FeedID: "a", FeedName: "alpha", Severity: 40, Indicator: "x"},
		{FeedID: "b", FeedName: "beta", Severity: 80, Indicator: "x"},
		{FeedID: "c", FeedName: "gamma", Severity: 60, Indicator: "x"},
	}
	strongest, others := PickStrongest(matches)
	if strongest.FeedID != "b" {
		t.Errorf("strongest FeedID = %q; want b", strongest.FeedID)
	}
	sort.Strings(others)
	want := []string{"alpha", "gamma"}
	if !reflect.DeepEqual(others, want) {
		t.Errorf("additional feeds = %v; want %v", others, want)
	}
}

// TestHostFromURL_HandlesIPv6AndNonHTTPSchemes locks the behaviour of
// the URL → host extractor used by ExtractCandidates. The earlier
// hand-rolled version walked the separator list (/ : ? #) in order
// and broke on the first `:` inside the bracket pair of an IPv6 host,
// producing the nonsense host `[` for any IPv6 URL. Switching to
// net/url.Parse fixes that without losing the scheme guard that keeps
// mailto:/ftp:/file: out of the indicator candidate list.
func TestHostFromURL_HandlesIPv6AndNonHTTPSchemes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"http", "http://example.com/path", "example.com"},
		{"https with port", "https://Bad.Example.com:8443/x", "bad.example.com"},
		{"https with userinfo", "https://user:pw@example.com/x", "example.com"},
		{"http ipv4 with port", "http://1.2.3.4:80/z", "1.2.3.4"},
		{"http ipv6", "http://[::1]:8080/path", "::1"},
		{"https ipv6", "https://[2001:db8::1]/q?x=1", "2001:db8::1"},
		{"non-http scheme", "ftp://example.com/file", ""},
		{"mailto", "mailto:user@example.com", ""},
		{"malformed", "::not-a-url", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := hostFromURL(tc.in); got != tc.want {
				t.Errorf("hostFromURL(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestExtractCandidates_BodyAndSender(t *testing.T) {
	t.Parallel()
	req := dto.EvaluateRequest{
		Sender:    "alice@example.com",
		Recipient: "bob@uney.com",
		Subject:   "Hello",
		Body:      "Click http://phish.test/x and https://bad.example.com/y or http://1.2.3.4/z. Then ftp://nope.test/q",
	}
	got := ExtractCandidates(req, dto.RiskSignals{
		SenderDomain:    "example.com",
		RecipientDomain: "uney.com",
	})
	// Build a set of (type, value) pairs for assertions.
	keys := make([]string, 0, len(got))
	for _, c := range got {
		keys = append(keys, string(c.Type)+":"+c.Value)
	}
	sort.Strings(keys)
	want := []string{
		"domain:1.2.3.4",         // host extracted from http://1.2.3.4/z
		"domain:bad.example.com", // host extracted from URL
		"domain:example.com",     // sender
		"domain:phish.test",      // host extracted from URL
		"domain:uney.com",        // recipient
		"url:http://1.2.3.4/z",
		"url:http://phish.test/x",
		"url:https://bad.example.com/y",
	}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("got candidates:\n  %v\nwant:\n  %v", keys, want)
	}
}

func TestStoreTIChecker_DedupesHashes(t *testing.T) {
	t.Parallel()
	store := &countingStore{}
	c := &StoreTIChecker{Store: store}
	req := dto.EvaluateRequest{
		Sender: "x@example.com",
		Body:   "http://example.com/a http://example.com/b",
	}
	_, err := c.Check(context.Background(), req, dto.RiskSignals{SenderDomain: "example.com"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if store.callCount != 1 {
		t.Errorf("expected exactly 1 LookupByHash call; got %d", store.callCount)
	}
	// Sender domain + recipient domain (empty so absent) + url x2 + 1 unique domain (example.com) -> 3 unique hashes
	if store.lastHashCount < 1 {
		t.Errorf("expected at least 1 deduped hash; got %d", store.lastHashCount)
	}
}

func TestStoreTIChecker_CacheShortcircuit(t *testing.T) {
	t.Parallel()
	store := &countingStore{}
	cache := &fakeCache{
		entries: map[string]TICacheEntry{},
	}
	c := &StoreTIChecker{Store: store, Cache: cache}
	req := dto.EvaluateRequest{
		Sender: "x@cached.example",
		Body:   "",
	}
	// Prepopulate the cache so it returns a "present, empty"
	// (negative-cache) entry for every candidate hash.
	candidates := ExtractCandidates(req, dto.RiskSignals{SenderDomain: "cached.example"})
	for _, cand := range candidates {
		h, _ := intel.HashIndicator(cand.Type, cand.Value)
		cache.entries[string(h)] = TICacheEntry{Present: true}
	}
	_, err := c.Check(context.Background(), req, dto.RiskSignals{SenderDomain: "cached.example"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if store.callCount != 0 {
		t.Errorf("expected zero DB lookups (cache shortcircuit); got %d", store.callCount)
	}
}

type countingStore struct {
	callCount     int
	lastHashCount int
	matches       []intel.MatchedIndicator
}

func (s *countingStore) ListFeeds(_ context.Context) ([]intel.Feed, error) { return nil, nil }
func (s *countingStore) GetFeed(_ context.Context, _ string) (intel.Feed, error) {
	return intel.Feed{}, nil
}
func (s *countingStore) GetFeedByName(_ context.Context, _ string) (intel.Feed, error) {
	return intel.Feed{}, nil
}
func (s *countingStore) CreateFeed(_ context.Context, f intel.Feed) (intel.Feed, error) {
	return f, nil
}
func (s *countingStore) UpdateFeed(_ context.Context, _ string, _ intel.FeedPatch) (intel.Feed, error) {
	return intel.Feed{}, nil
}
func (s *countingStore) DeleteFeed(_ context.Context, _ string) error { return nil }
func (s *countingStore) RecordFeedResult(_ context.Context, _ string, _ bool, _ time.Time, _ string) error {
	return nil
}
func (s *countingStore) UpsertIndicators(_ context.Context, _ string, _ []intel.Indicator) (int, error) {
	return 0, nil
}
func (s *countingStore) LookupByHash(_ context.Context, hashes [][]byte) ([]intel.MatchedIndicator, error) {
	s.callCount++
	s.lastHashCount = len(hashes)
	return s.matches, nil
}
func (s *countingStore) FindByIndicator(_ context.Context, _ string) ([]intel.MatchedIndicator, error) {
	return nil, nil
}
func (s *countingStore) GarbageCollect(_ context.Context, _ time.Time) (int, error) { return 0, nil }
func (s *countingStore) RecordStaleAlert(_ context.Context, _, _ string, _ int, _ string, _ time.Time) error {
	return nil
}

type fakeCache struct {
	entries map[string]TICacheEntry
}

func (f *fakeCache) GetHashes(_ context.Context, hashes [][]byte) []TICacheEntry {
	out := make([]TICacheEntry, len(hashes))
	for i, h := range hashes {
		if e, ok := f.entries[string(h)]; ok {
			out[i] = e
		}
	}
	return out
}
func (f *fakeCache) SetHash(_ context.Context, _ []byte, _ []intel.MatchedIndicator) {}
