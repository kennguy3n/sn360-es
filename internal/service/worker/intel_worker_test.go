package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// fakeIntelMetrics captures observed metrics in-memory.
type fakeIntelMetrics struct {
	mu          sync.Mutex
	polls       []pollObservation
	staleAlerts []string
	gcDeleted   []int
}

type pollObservation struct {
	feed       string
	outcome    string
	latency    time.Duration
	indicators int
}

func (f *fakeIntelMetrics) ObserveIntelPoll(feed, outcome string, latency time.Duration, indicators int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls = append(f.polls, pollObservation{feed, outcome, latency, indicators})
}

func (f *fakeIntelMetrics) ObserveIntelStale(feed string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staleAlerts = append(f.staleAlerts, feed)
}

func (f *fakeIntelMetrics) ObserveIntelGC(deleted int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gcDeleted = append(f.gcDeleted, deleted)
}

// fakePoller is the stand-in for a real provider Poller inside the
// worker tests. It is NOT a substitute for the real pollers — those
// are tested in pkg/intel/<provider>; here we exercise the worker's
// dispatch / bookkeeping / stale-alert logic.
type fakePoller struct {
	provider string
	calls    atomic.Int32
	result   intel.Result
	err      error
}

func (p *fakePoller) Provider() string { return p.provider }
func (p *fakePoller) Poll(_ context.Context) (intel.Result, error) {
	p.calls.Add(1)
	return p.result, p.err
}

// registerFake registers a stateful poller into a private registry.
func registerFake(t *testing.T, reg *intel.Registry, provider string, p *fakePoller) {
	t.Helper()
	if err := reg.Register(provider, func(_ intel.FeedConfig) (intel.Poller, error) {
		return p, nil
	}); err != nil {
		t.Fatalf("register %s: %v", provider, err)
	}
}

func TestIntelJob_Run_HappyPath(t *testing.T) {
	t.Parallel()

	store := repository.NewMemoryIntelStore()
	ctx := context.Background()

	feed, err := store.CreateFeed(ctx, intel.Feed{
		Name:          "urlhaus-test",
		Provider:      "urlhaus-test",
		URL:           "https://example/csv",
		Enabled:       true,
		FetchInterval: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}

	ind, _ := intel.Canonicalise(intel.Indicator{
		Indicator: "bad.example",
		Type:      intel.IndicatorDomain,
		Severity:  80,
	})
	poller := &fakePoller{
		provider: "urlhaus-test",
		result:   intel.Result{Indicators: []intel.Indicator{ind}},
	}
	reg := intel.NewRegistry()
	registerFake(t, reg, "urlhaus-test", poller)

	metrics := &fakeIntelMetrics{}
	job, err := NewIntelJob(IntelJobConfig{
		Interval: time.Minute,
		Store:    store,
		Registry: reg,
		Metrics:  metrics,
	})
	if err != nil {
		t.Fatalf("NewIntelJob: %v", err)
	}
	if err := job.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if poller.calls.Load() != 1 {
		t.Errorf("expected 1 poll, got %d", poller.calls.Load())
	}

	got, _ := store.GetFeed(ctx, feed.ID)
	if got.LastOK == nil || !*got.LastOK {
		t.Errorf("LastOK = %v; want true", got.LastOK)
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d", got.ConsecutiveFailures)
	}
	if got.LastFetchedAt == nil {
		t.Error("LastFetchedAt not updated")
	}

	if len(metrics.polls) != 1 || metrics.polls[0].outcome != "ok" || metrics.polls[0].indicators != 1 {
		t.Errorf("unexpected metrics: %+v", metrics.polls)
	}

	// Match was upserted — verify by hash lookup.
	matches, _ := store.LookupByHash(ctx, [][]byte{ind.Hash})
	if len(matches) != 1 {
		t.Fatalf("matches = %d; want 1", len(matches))
	}
	if matches[0].FeedName != "urlhaus-test" {
		t.Errorf("matched feed = %q", matches[0].FeedName)
	}
}

func TestIntelJob_Run_NotDueIsSkipped(t *testing.T) {
	t.Parallel()
	store := repository.NewMemoryIntelStore()
	ctx := context.Background()

	now := time.Now().UTC()
	// Manually create a feed and inject a fresh last_fetched_at.
	feed, _ := store.CreateFeed(ctx, intel.Feed{
		Name: "x", Provider: "test", URL: "https://x/",
		Enabled: true, FetchInterval: time.Hour,
	})
	_ = store.RecordFeedResult(ctx, feed.ID, true, now, "")

	poller := &fakePoller{provider: "test"}
	reg := intel.NewRegistry()
	registerFake(t, reg, "test", poller)

	job, _ := NewIntelJob(IntelJobConfig{
		Interval: time.Minute,
		Store:    store,
		Registry: reg,
		Clock:    func() time.Time { return now.Add(time.Second) },
	})
	if err := job.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if poller.calls.Load() != 0 {
		t.Errorf("expected no polls; got %d", poller.calls.Load())
	}
}

func TestIntelJob_Run_DisabledIsSkipped(t *testing.T) {
	t.Parallel()
	store := repository.NewMemoryIntelStore()
	ctx := context.Background()

	_, _ = store.CreateFeed(ctx, intel.Feed{
		Name: "disabled", Provider: "test", URL: "https://x/",
		Enabled: false, FetchInterval: time.Minute,
	})

	poller := &fakePoller{provider: "test"}
	reg := intel.NewRegistry()
	registerFake(t, reg, "test", poller)

	job, _ := NewIntelJob(IntelJobConfig{
		Interval: time.Minute,
		Store:    store,
		Registry: reg,
	})
	if err := job.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if poller.calls.Load() != 0 {
		t.Errorf("disabled feed polled %d times", poller.calls.Load())
	}
}

func TestIntelJob_Run_StaleAlertOnThreshold(t *testing.T) {
	t.Parallel()
	store := repository.NewMemoryIntelStore()
	ctx := context.Background()

	feed, _ := store.CreateFeed(ctx, intel.Feed{
		Name: "y", Provider: "test", URL: "https://y/",
		Enabled: true, FetchInterval: time.Millisecond,
	})

	poller := &fakePoller{provider: "test", err: errors.New("503")}
	reg := intel.NewRegistry()
	registerFake(t, reg, "test", poller)

	metrics := &fakeIntelMetrics{}
	now := time.Now().UTC()
	job, _ := NewIntelJob(IntelJobConfig{
		Interval:       time.Minute,
		StaleThreshold: 3,
		Store:          store,
		Registry:       reg,
		Metrics:        metrics,
		Clock:          func() time.Time { return now },
	})

	// Three consecutive failures → alert on the third.
	for i := 0; i < 3; i++ {
		// Advance "now" past each fetch_interval so the feed is
		// always due.
		now = now.Add(time.Second)
		if err := job.Run(ctx); err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
	}
	got, _ := store.GetFeed(ctx, feed.ID)
	if got.ConsecutiveFailures != 3 {
		t.Errorf("ConsecutiveFailures = %d; want 3", got.ConsecutiveFailures)
	}
	if len(metrics.staleAlerts) != 1 {
		t.Errorf("expected 1 stale alert, got %d: %v",
			len(metrics.staleAlerts), metrics.staleAlerts)
	}
	alerts := store.StaleAlerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(alerts))
	}
	if alerts[0].FeedName != "y" {
		t.Errorf("audit feed = %q", alerts[0].FeedName)
	}
	if alerts[0].Failures != 3 {
		t.Errorf("audit failures = %d", alerts[0].Failures)
	}
	if !strings.Contains(alerts[0].LastError, "503") {
		t.Errorf("audit error = %q", alerts[0].LastError)
	}

	// A successful poll resets consecutive_failures; if the feed
	// fails again later we expect a *new* alert at the next 3-streak.
	poller.err = nil
	now = now.Add(time.Second)
	if err := job.Run(ctx); err != nil {
		t.Fatalf("Run success: %v", err)
	}
	got, _ = store.GetFeed(ctx, feed.ID)
	if got.ConsecutiveFailures != 0 {
		t.Errorf("after success ConsecutiveFailures = %d; want 0", got.ConsecutiveFailures)
	}
}

func TestIntelJob_Run_GCSweep(t *testing.T) {
	t.Parallel()
	now := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := repository.NewMemoryIntelStore().WithClock(clock)
	ctx := context.Background()

	feed, _ := store.CreateFeed(ctx, intel.Feed{
		Name: "z", Provider: "test", URL: "https://z/",
		Enabled: true, FetchInterval: time.Minute,
	})

	// Seed an indicator at the current clock, then advance 31 days.
	ind, _ := intel.Canonicalise(intel.Indicator{
		Indicator: "stale.example", Type: intel.IndicatorDomain, Severity: 50,
	})
	if _, err := store.UpsertIndicators(ctx, feed.ID, []intel.Indicator{ind}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	now = now.Add(31 * 24 * time.Hour)

	poller := &fakePoller{provider: "test"}
	reg := intel.NewRegistry()
	registerFake(t, reg, "test", poller)

	metrics := &fakeIntelMetrics{}
	job, _ := NewIntelJob(IntelJobConfig{
		Interval:    time.Minute,
		GCInterval:  time.Nanosecond, // run GC every cycle
		GCRetention: 30 * 24 * time.Hour,
		Store:       store,
		Registry:    reg,
		Metrics:     metrics,
		Clock:       clock,
	})
	if err := job.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(metrics.gcDeleted) != 1 || metrics.gcDeleted[0] != 1 {
		t.Errorf("expected GC to delete 1; got %v", metrics.gcDeleted)
	}
}

func TestIntelJob_Run_ConcurrencyCap(t *testing.T) {
	t.Parallel()
	store := repository.NewMemoryIntelStore()
	ctx := context.Background()

	// Seed 10 feeds and a barrier poller that blocks on a channel.
	reg := intel.NewRegistry()
	inFlight := atomic.Int32{}
	maxObserved := atomic.Int32{}
	release := make(chan struct{})

	reg.MustRegister("blocker", func(_ intel.FeedConfig) (intel.Poller, error) {
		return blockerPoller{
			inFlight:    &inFlight,
			maxObserved: &maxObserved,
			release:     release,
		}, nil
	})

	for i := 0; i < 10; i++ {
		_, _ = store.CreateFeed(ctx, intel.Feed{
			Name:          fmt.Sprintf("f%d", i),
			Provider:      "blocker",
			URL:           fmt.Sprintf("https://x/%d", i),
			Enabled:       true,
			FetchInterval: time.Nanosecond,
		})
	}

	job, _ := NewIntelJob(IntelJobConfig{
		Interval:      time.Minute,
		MaxConcurrent: 3,
		Store:         store,
		Registry:      reg,
	})

	done := make(chan error, 1)
	go func() { done <- job.Run(ctx) }()

	// Give the pool time to saturate, then release.
	time.Sleep(50 * time.Millisecond)
	if got := maxObserved.Load(); got > 3 {
		t.Errorf("concurrency cap breached: max in-flight = %d", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

type blockerPoller struct {
	inFlight    *atomic.Int32
	maxObserved *atomic.Int32
	release     <-chan struct{}
}

func (b blockerPoller) Provider() string { return "blocker" }
func (b blockerPoller) Poll(ctx context.Context) (intel.Result, error) {
	cur := b.inFlight.Add(1)
	defer b.inFlight.Add(-1)
	for {
		if m := b.maxObserved.Load(); cur > m {
			if b.maxObserved.CompareAndSwap(m, cur) {
				break
			}
		} else {
			break
		}
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		return intel.Result{}, ctx.Err()
	}
	return intel.Result{}, nil
}

func TestIntelJob_Run_ListFeedsError(t *testing.T) {
	t.Parallel()
	store := &errStore{
		MemoryIntelStore: repository.NewMemoryIntelStore(),
		ListErr:          errors.New("db down"),
	}
	job, _ := NewIntelJob(IntelJobConfig{
		Interval: time.Minute,
		Store:    store,
	})
	if err := job.Run(context.Background()); err == nil {
		t.Error("expected error; got nil")
	}
}

type errStore struct {
	*repository.MemoryIntelStore
	ListErr error
}

func (e *errStore) ListFeeds(_ context.Context) ([]intel.Feed, error) {
	return nil, e.ListErr
}
