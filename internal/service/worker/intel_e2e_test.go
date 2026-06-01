package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// TestIntelEndToEnd_FeedToTierZeroMatch is the WS-5B.3 contract
// test: a feed becomes due, the worker pulls it via a stub poller,
// the IntelStore receives the indicators, and the next Tier 0 gate
// evaluation on a message with a matching URL emits `ti_match`
// with the correct override semantics (block / quarantine / flag).
//
// We exercise the path with the same MemoryIntelStore that the
// dev / unit-test wiring uses; the production PgIntelStore is
// schema-tested in repository/intel_pg_test.go.
func TestIntelEndToEnd_FeedToTierZeroMatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := repository.NewMemoryIntelStore()

	// Feed registered, then forced "due" by setting LastFetchedAt
	// in the past via the worker's natural path (initial state has
	// LastFetchedAt=nil which counts as due).
	feed, err := store.CreateFeed(ctx, intel.Feed{
		Name:          "urlhaus-e2e",
		Provider:      "urlhaus-e2e",
		URL:           "https://urlhaus.haus.fail/csv_recent/",
		FetchInterval: time.Minute,
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("create feed: %v", err)
	}

	// A "block" tier IOC (severity >= 75) — the gate must Bypass
	// and SkipML on the next message that mentions evil.example.
	ind := mustHashIndicator(t, intel.Indicator{
		Indicator: "evil.example",
		Type:      intel.IndicatorDomain,
		Severity:  85,
		Tags:      []string{"credential-harvesting"},
	})
	poller := &fakePoller{
		provider: "urlhaus-e2e",
		result:   intel.Result{Indicators: []intel.Indicator{ind}},
	}
	reg := intel.NewRegistry()
	registerFake(t, reg, "urlhaus-e2e", poller)

	job, err := NewIntelJob(IntelJobConfig{
		Interval:    time.Minute,
		Store:       store,
		Registry:    reg,
		GCInterval:  0, // disable GC in the e2e path
		FeedTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewIntelJob: %v", err)
	}

	// Single cycle. The worker's Run loop is interval-driven; we
	// drive a one-shot via the exported PollFeed entrypoint that
	// the admin /refresh handler uses, which is the same code
	// path the scheduled loop takes.
	upserted, err := job.PollFeed(ctx, feed.ID)
	if err != nil {
		t.Fatalf("PollFeed: %v", err)
	}
	if upserted != 1 {
		t.Errorf("upserted = %d; want 1", upserted)
	}

	// Tier 0 gate plumbed with the same store. The TIChecker
	// reads back the IOC the poller just wrote.
	checker := &tier0.StoreTIChecker{Store: store}
	gate := tier0.NewGate(tier0.GateConfig{
		SkipInternal: true,
		SkipVendor:   true,
	}, nil).WithTIChecker(checker)

	// A normal-looking message that mentions the IOC in its body.
	// The TI checker harvests URLs from the body and derives host
	// candidates from them — so the URL must use the canonicalised
	// host "evil.example" verbatim for the domain hash to match.
	req := dto.EvaluateRequest{
		MessageID: "msg-e2e",
		Sender:    "alice@partner.example",
		Body:      "Please review https://evil.example/reset and act fast.",
	}
	signals := dto.RiskSignals{}
	out := gate.ApplyWithContext(ctx, req, signals)
	if out.Reason != "ti_match" {
		t.Fatalf("Reason = %q; want ti_match (outcome=%+v)", out.Reason, out)
	}
	if out.TIMatch == nil {
		t.Fatalf("TIMatch metadata missing")
	}
	if out.TIMatch.IndicatorType != string(intel.IndicatorDomain) {
		t.Errorf("IndicatorType = %q", out.TIMatch.IndicatorType)
	}
	if !out.Bypass || !out.SkipML {
		t.Errorf("expected Bypass+SkipML on severity 85; out=%+v", out)
	}
	if out.ForcedCategory != constant.CategoryLikelyPhishing {
		t.Errorf("ForcedCategory = %q; want LikelyPhishing", out.ForcedCategory)
	}
	if len(out.TIMatch.Tags) == 0 || !strings.EqualFold(out.TIMatch.Tags[0], "credential-harvesting") {
		t.Errorf("Tags = %v; want [credential-harvesting]", out.TIMatch.Tags)
	}
}

// TestIntelEndToEnd_GCExpiresStale ensures stale indicators are
// purged by the worker's retention sweep and that the gate stops
// emitting ti_match for them afterward.
func TestIntelEndToEnd_GCExpiresStale(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC()
	backdated := now.Add(-60 * 24 * time.Hour)
	// Use a clock that returns the backdated timestamp so the
	// initial UpsertIndicators writes last_seen=backdated — same
	// effect as if the row had been inserted 60 days ago.
	store := repository.NewMemoryIntelStore().WithClock(func() time.Time { return backdated })
	feed, _ := store.CreateFeed(ctx, intel.Feed{
		Name: "gc-feed", Provider: "p", URL: "https://e/x",
		FetchInterval: time.Minute, Enabled: true,
	})
	// Seed an IOC dated 60 days ago so it's eligible for GC.
	hash, _ := intel.HashIndicator(intel.IndicatorDomain, "stale.example")
	if _, err := store.UpsertIndicators(ctx, feed.ID, []intel.Indicator{
		{Indicator: "stale.example", Type: intel.IndicatorDomain, Hash: hash, Severity: 80},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Switch the clock back to "now" for the subsequent GC step.
	store = store.WithClock(func() time.Time { return now })

	// First lookup confirms the IOC is present.
	matches, err := store.LookupByHash(ctx, [][]byte{hash})
	if err != nil || len(matches) != 1 {
		t.Fatalf("LookupByHash pre-GC: %d matches err=%v", len(matches), err)
	}

	// Run GC with a 30-day cutoff.
	cutoff := now.Add(-30 * 24 * time.Hour)
	n, err := store.GarbageCollect(ctx, cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 1 {
		t.Errorf("GC deleted = %d; want 1", n)
	}

	// Lookup now returns nothing — stale IOC is gone.
	matches, _ = store.LookupByHash(ctx, [][]byte{hash})
	if len(matches) != 0 {
		t.Errorf("post-GC LookupByHash returned %d matches; want 0", len(matches))
	}

	// The gate falls through to heuristic bypass rules when no
	// IOC matches; verify ti_match isn't spuriously emitted.
	gate := tier0.NewGate(tier0.GateConfig{}, nil).
		WithTIChecker(&tier0.StoreTIChecker{Store: store})
	out := gate.ApplyWithContext(ctx, dto.EvaluateRequest{
		MessageID: "msg",
		Body:      "https://stale.example/x",
	}, dto.RiskSignals{})
	if out.Reason == "ti_match" {
		t.Errorf("Reason = ti_match after GC; want fallthrough (outcome=%+v)", out)
	}
}

// mustHashIndicator fills in Hash before calling UpsertIndicators —
// the MemoryIntelStore (like PgIntelStore) treats Hash as a
// required input field set by Canonicalise() in the pollers.
func mustHashIndicator(t *testing.T, ind intel.Indicator) intel.Indicator {
	t.Helper()
	if len(ind.Hash) > 0 {
		return ind
	}
	h, err := intel.HashIndicator(ind.Type, ind.Indicator)
	if err != nil {
		t.Fatalf("HashIndicator: %v", err)
	}
	ind.Hash = h
	return ind
}
