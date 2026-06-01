package repository

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

func mkInd(t *testing.T, raw string, typ intel.IndicatorType, sev int) intel.Indicator {
	t.Helper()
	ind, err := intel.Canonicalise(intel.Indicator{
		Indicator: raw,
		Type:      typ,
		Severity:  sev,
	})
	if err != nil {
		t.Fatalf("Canonicalise(%q): %v", raw, err)
	}
	return ind
}

func TestMemoryIntelStore_CreateGetDelete(t *testing.T) {
	t.Parallel()
	store := NewMemoryIntelStore()
	ctx := context.Background()

	f, err := store.CreateFeed(ctx, intel.Feed{
		Name:     "urlhaus-test",
		Provider: "urlhaus",
		URL:      "https://urlhaus.example/csv",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	if f.ID == "" {
		t.Error("missing id")
	}
	if f.FetchInterval != 15*time.Minute {
		t.Errorf("default interval = %v; want 15m", f.FetchInterval)
	}
	got, err := store.GetFeed(ctx, f.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if got.Name != "urlhaus-test" {
		t.Errorf("got name %q", got.Name)
	}

	// duplicate name → ErrFeedExists
	_, err = store.CreateFeed(ctx, intel.Feed{
		Name:     "urlhaus-test",
		Provider: "urlhaus",
		URL:      "https://example/",
	})
	if err != intel.ErrFeedExists {
		t.Errorf("dup name err = %v; want ErrFeedExists", err)
	}

	if err := store.DeleteFeed(ctx, f.ID); err != nil {
		t.Fatalf("DeleteFeed: %v", err)
	}
	if _, err := store.GetFeed(ctx, f.ID); err != intel.ErrFeedNotFound {
		t.Errorf("post-delete get err = %v; want ErrFeedNotFound", err)
	}
}

func TestMemoryIntelStore_UpsertAndLookup(t *testing.T) {
	t.Parallel()
	store := NewMemoryIntelStore()
	ctx := context.Background()

	f, _ := store.CreateFeed(ctx, intel.Feed{
		Name: "urlhaus-test", Provider: "urlhaus", URL: "https://x/",
	})

	ind1 := mkInd(t, "evil.example.com", intel.IndicatorDomain, 80)
	ind2 := mkInd(t, "http://evil.example.com/dropper", intel.IndicatorURL, 80)

	n, err := store.UpsertIndicators(ctx, f.ID, []intel.Indicator{ind1, ind2})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if n != 2 {
		t.Errorf("Upsert n = %d; want 2", n)
	}

	matches, err := store.LookupByHash(ctx, [][]byte{ind1.Hash})
	if err != nil {
		t.Fatalf("LookupByHash: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %d; want 1", len(matches))
	}
	if matches[0].Indicator != "evil.example.com" {
		t.Errorf("matched indicator = %q", matches[0].Indicator)
	}
	if matches[0].FeedName != "urlhaus-test" {
		t.Errorf("feed name = %q", matches[0].FeedName)
	}

	// Upsert again with lower severity — GREATEST wins.
	low := mkInd(t, "evil.example.com", intel.IndicatorDomain, 30)
	_, _ = store.UpsertIndicators(ctx, f.ID, []intel.Indicator{low})
	matches, _ = store.LookupByHash(ctx, [][]byte{ind1.Hash})
	if matches[0].Severity != 80 {
		t.Errorf("severity dropped to %d; should stay 80", matches[0].Severity)
	}
}

func TestMemoryIntelStore_FindByIndicator(t *testing.T) {
	t.Parallel()
	store := NewMemoryIntelStore()
	ctx := context.Background()

	f, _ := store.CreateFeed(ctx, intel.Feed{
		Name: "csv-test", Provider: "csv", URL: "https://x/",
	})
	ind := mkInd(t, "phish.test", intel.IndicatorDomain, 50)
	_, _ = store.UpsertIndicators(ctx, f.ID, []intel.Indicator{ind})

	matches, err := store.FindByIndicator(ctx, "Phish.TEST")
	if err != nil {
		t.Fatalf("FindByIndicator: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %d; want 1", len(matches))
	}
}

func TestMemoryIntelStore_GarbageCollect(t *testing.T) {
	t.Parallel()
	clk := time.Date(2024, 1, 31, 0, 0, 0, 0, time.UTC)
	store := NewMemoryIntelStore().WithClock(func() time.Time { return clk })
	ctx := context.Background()

	feedA, _ := store.CreateFeed(ctx, intel.Feed{Name: "a", Provider: "csv", URL: "https://a/"})
	feedB, _ := store.CreateFeed(ctx, intel.Feed{Name: "b", Provider: "csv", URL: "https://b/"})

	stale := mkInd(t, "stale.example", intel.IndicatorDomain, 50)
	multi := mkInd(t, "multi.example", intel.IndicatorDomain, 50)
	freshOnA := mkInd(t, "freshA.example", intel.IndicatorDomain, 50)

	// 1. Insert stale + multi at the old timestamp.
	_, _ = store.UpsertIndicators(ctx, feedA.ID, []intel.Indicator{stale, multi})
	// 2. Advance the clock 31 days and insert multi on feedB so it
	//    becomes shadowed-fresh, and freshOnA on feedA so it has
	//    a new last_seen.
	clk = clk.Add(31 * 24 * time.Hour)
	_, _ = store.UpsertIndicators(ctx, feedB.ID, []intel.Indicator{multi})
	_, _ = store.UpsertIndicators(ctx, feedA.ID, []intel.Indicator{freshOnA})

	cutoff := clk.Add(-30 * 24 * time.Hour) // i.e. 1 day after first batch

	n, err := store.GarbageCollect(ctx, cutoff)
	if err != nil {
		t.Fatalf("GarbageCollect: %v", err)
	}
	// stale on feedA is older than cutoff and has no peer → deleted.
	// multi on feedA is older but feedB has a fresh row → retained.
	// freshOnA stays.
	if n != 1 {
		t.Errorf("deleted %d rows; want 1", n)
	}
	matches, _ := store.LookupByHash(ctx, [][]byte{stale.Hash, multi.Hash, freshOnA.Hash})
	sawMulti := false
	sawFresh := false
	for _, m := range matches {
		if m.Indicator == "stale.example" {
			t.Error("stale.example was not garbage-collected")
		}
		if m.Indicator == "multi.example" {
			sawMulti = true
		}
		if m.Indicator == "fresha.example" {
			sawFresh = true
		}
	}
	if !sawMulti {
		t.Error("multi-feed-referenced indicator missing after GC")
	}
	if !sawFresh {
		t.Error("fresh indicator missing after GC")
	}
}

func TestMemoryIntelStore_RecordFeedResult(t *testing.T) {
	t.Parallel()
	store := NewMemoryIntelStore()
	ctx := context.Background()
	f, _ := store.CreateFeed(ctx, intel.Feed{Name: "x", Provider: "csv", URL: "https://x/"})

	now := time.Now()
	if err := store.RecordFeedResult(ctx, f.ID, false, now, "boom"); err != nil {
		t.Fatalf("RecordFeedResult fail: %v", err)
	}
	got, _ := store.GetFeed(ctx, f.ID)
	if got.ConsecutiveFailures != 1 {
		t.Errorf("consecutive_failures = %d", got.ConsecutiveFailures)
	}
	if got.LastError != "boom" {
		t.Errorf("last_error = %q", got.LastError)
	}
	if got.LastOK == nil || *got.LastOK {
		t.Errorf("last_ok = %v; want false", got.LastOK)
	}

	if err := store.RecordFeedResult(ctx, f.ID, false, now, "still bad"); err != nil {
		t.Fatalf("RecordFeedResult: %v", err)
	}
	got, _ = store.GetFeed(ctx, f.ID)
	if got.ConsecutiveFailures != 2 {
		t.Errorf("after two fails consecutive_failures = %d", got.ConsecutiveFailures)
	}

	if err := store.RecordFeedResult(ctx, f.ID, true, now, ""); err != nil {
		t.Fatalf("success: %v", err)
	}
	got, _ = store.GetFeed(ctx, f.ID)
	if got.ConsecutiveFailures != 0 {
		t.Errorf("success should reset consecutive_failures, got %d", got.ConsecutiveFailures)
	}
	if got.LastError != "" {
		t.Errorf("success should clear last_error, got %q", got.LastError)
	}
}
