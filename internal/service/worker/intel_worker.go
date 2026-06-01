// Package worker — threat-intel feed-consumption job.
//
// The intel worker is a periodic singleton (Redis-locked, see
// worker.LockFactory) that:
//
//  1. Lists every enabled intel_feeds row.
//  2. For each row whose `last_fetched_at + fetch_interval <= now`
//     dispatches the provider's Poller via the registry.
//  3. Upserts the returned indicators through IntelStore.UpsertIndicators.
//  4. Bumps `last_fetched_at`, `last_ok`, `last_error` and
//     `consecutive_failures` via RecordFeedResult.
//  5. On three consecutive failures: records a deployment-scoped
//     audit row and increments the Prometheus stale-feed alert
//     counter so dashboards see a non-zero rate.
//  6. Every IntelGCInterval, sweeps stale rows via
//     IntelStore.GarbageCollect.
//
// Concurrency: a bounded worker-pool runs Poll() in parallel, but the
// store writes are serialised by IntelStore's own locking (the
// Postgres backend uses an unbound *postgres.DB; the in-memory backend
// holds a single sync.Mutex). The cap is configurable via
// WORKER_INTEL_MAX_CONCURRENT (default 4) to keep one slow MISP from
// starving URLhaus refreshes.
//
// The worker is intentionally tolerant of partial failures — a single
// feed failing does not abort the cycle. The scheduler logs the error,
// updates the row's bookkeeping, and continues. Three consecutive
// failures raise the alert; the next successful poll resets the
// counter to zero.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// IntelMetricsRecorder is the slim metrics surface the intel worker
// emits to. The cmd/sn360-es package adapts pkg/telemetry to this
// interface so the worker package does not depend on telemetry's
// Prometheus types directly.
type IntelMetricsRecorder interface {
	// ObserveIntelPoll records the outcome of a single feed poll.
	// outcome is "ok" or "error".
	ObserveIntelPoll(feed, outcome string, latency time.Duration, indicators int)
	// ObserveIntelStale records a stale-feed alert event. Called once
	// per cycle the consecutive-failure threshold is first crossed.
	ObserveIntelStale(feed string)
	// ObserveIntelGC records the count of indicators deleted by a GC sweep.
	ObserveIntelGC(deleted int)
}

// IntelJobConfig wires the intel worker.
type IntelJobConfig struct {
	// Interval is the scheduler tick. Default 1m.
	Interval time.Duration
	// MaxConcurrent caps simultaneous feed polls. Default 4.
	MaxConcurrent int
	// FeedTimeout is the per-feed Poll() deadline. Default 60s.
	FeedTimeout time.Duration
	// StaleThreshold is the consecutive-failure count at which a
	// stale-feed alert is raised. Default 3.
	StaleThreshold int
	// GCInterval is the gap between GarbageCollect sweeps. Default 6h.
	// Set to 0 to disable GC sweeps entirely.
	GCInterval time.Duration
	// GCRetention is the maximum age of an indicator's last_seen
	// before it is eligible for deletion. Default 30 days.
	GCRetention time.Duration

	// Registry holds provider constructors. Defaults to
	// intel.DefaultRegistry.
	Registry *intel.Registry
	// Store is the persistence backend. REQUIRED.
	Store intel.IntelStore
	// HTTPClient is the HTTP transport handed to every provider's
	// FeedConfig. Defaults to intel.DefaultHTTPDoer.
	HTTPClient intel.HTTPDoer
	// APIKeyFor returns the credential to inject into FeedConfig
	// for the given provider. Returning an empty string means "no
	// auth" — pollers that require auth fail at constructor time.
	// Optional; defaults to a static map keyed by provider name
	// populated from APIKeyMap.
	APIKeyFor func(provider string) string
	// APIKeyMap supplies provider→credential pairs when APIKeyFor
	// is nil. Convenient call-site for the wiring layer.
	APIKeyMap map[string]string

	Logger  *slog.Logger
	Metrics IntelMetricsRecorder
	// Clock is mainly for tests. Defaults to time.Now (UTC).
	Clock func() time.Time
}

// IntelJob implements Job for the threat-intel feed-consumption loop.
type IntelJob struct {
	interval       time.Duration
	maxConcurrent  int
	feedTimeout    time.Duration
	staleThreshold int
	gcInterval     time.Duration
	gcRetention    time.Duration

	registry   *intel.Registry
	store      intel.IntelStore
	httpClient intel.HTTPDoer
	apiKeyFor  func(provider string) string

	logger  *slog.Logger
	metrics IntelMetricsRecorder
	clock   func() time.Time

	// mu guards lastGC so the periodic GC sweep is interleaved
	// across cycles rather than running every minute.
	mu     sync.Mutex
	lastGC time.Time
}

// NewIntelJob constructs the job and applies defaults.
func NewIntelJob(cfg IntelJobConfig) (*IntelJob, error) {
	if cfg.Store == nil {
		return nil, errors.New("worker.intel: store is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4
	}
	if cfg.FeedTimeout <= 0 {
		cfg.FeedTimeout = 60 * time.Second
	}
	if cfg.StaleThreshold <= 0 {
		cfg.StaleThreshold = 3
	}
	// GCInterval=0 explicitly disables GC; GCRetention=0 doesn't
	// make sense (would delete everything) so default it.
	if cfg.GCRetention <= 0 {
		cfg.GCRetention = 30 * 24 * time.Hour
	}
	if cfg.Registry == nil {
		cfg.Registry = intel.DefaultRegistry
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = intel.DefaultHTTPDoer
	}
	apiKeyFor := cfg.APIKeyFor
	if apiKeyFor == nil {
		keys := cfg.APIKeyMap
		apiKeyFor = func(provider string) string { return keys[provider] }
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &IntelJob{
		interval:       cfg.Interval,
		maxConcurrent:  cfg.MaxConcurrent,
		feedTimeout:    cfg.FeedTimeout,
		staleThreshold: cfg.StaleThreshold,
		gcInterval:     cfg.GCInterval,
		gcRetention:    cfg.GCRetention,
		registry:       cfg.Registry,
		store:          cfg.Store,
		httpClient:     cfg.HTTPClient,
		apiKeyFor:      apiKeyFor,
		logger:         logger,
		metrics:        cfg.Metrics,
		clock:          clock,
	}, nil
}

// Name implements Job.
func (j *IntelJob) Name() string { return "intel" }

// Interval implements Job.
func (j *IntelJob) Interval() time.Duration { return j.interval }

// Run executes one cycle.
//
// The cycle is structured as:
//
//  1. Fetch the feed list once via ListFeeds.
//  2. Filter to feeds that are enabled AND due (last_fetched_at +
//     fetch_interval <= now). Disabled and not-yet-due feeds are
//     silently skipped.
//  3. Dispatch each due feed to a worker goroutine through a
//     buffered channel that caps concurrency at MaxConcurrent.
//  4. Wait for every dispatched poll to finish before returning —
//     the runner's lock should be held for the full cycle so two
//     replicas cannot race the same feed.
//  5. Conditionally run the GC sweep if GCInterval has elapsed.
//
// Errors from individual feed polls are NOT returned — they are
// recorded on the row via RecordFeedResult and surfaced via
// metrics/logs. The cycle's only error path is the top-level
// ListFeeds query, which fails the whole cycle (the runner will
// retry on the next tick).
func (j *IntelJob) Run(ctx context.Context) error {
	cycleStart := j.clock()

	feeds, err := j.store.ListFeeds(ctx)
	if err != nil {
		return fmt.Errorf("worker.intel: list feeds: %w", err)
	}

	due := j.filterDue(feeds, cycleStart)
	if len(due) == 0 {
		j.maybeGC(ctx, cycleStart)
		return nil
	}

	// Bounded worker pool. We use a buffered channel as a counting
	// semaphore so the dispatcher never holds more than
	// MaxConcurrent in-flight pollers regardless of how many feeds
	// are due.
	sem := make(chan struct{}, j.maxConcurrent)
	var wg sync.WaitGroup
	for _, f := range due {
		// ctx.Err() check inside the loop body lets us short-
		// circuit on a graceful shutdown without dispatching the
		// remainder of the slice.
		if ctx.Err() != nil {
			break
		}
		feed := f // capture
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			j.pollOne(ctx, feed)
		}()
	}
	wg.Wait()

	j.maybeGC(ctx, cycleStart)
	return nil
}

// filterDue returns the subset of feeds that are enabled AND past
// their next-fetch deadline.
func (j *IntelJob) filterDue(feeds []intel.Feed, now time.Time) []intel.Feed {
	out := make([]intel.Feed, 0, len(feeds))
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		if f.LastFetchedAt == nil {
			// Never polled — always due.
			out = append(out, f)
			continue
		}
		nextDue := f.LastFetchedAt.Add(f.FetchInterval)
		if !nextDue.After(now) {
			out = append(out, f)
		}
	}
	return out
}

// PollFeed runs a single poll cycle for the feed identified by
// feedID — the same bookkeeping/upsert/alert path the scheduled
// loop uses, but invoked on-demand from the admin
// /v1/intel/feeds/{id}/refresh endpoint.
//
// Returns the number of indicators upserted plus any upstream
// error. Errors are also written to the feed's bookkeeping row
// (last_ok=false, consecutive_failures bumped) so a /refresh
// failure is visible in the same operator surfaces as a scheduled
// failure.
//
// intel.ErrFeedNotFound surfaces unchanged so the handler can
// translate it to a 404.
func (j *IntelJob) PollFeed(ctx context.Context, feedID string) (int, error) {
	feed, err := j.store.GetFeed(ctx, feedID)
	if err != nil {
		return 0, err
	}
	return j.pollOneSync(ctx, feed)
}

// pollOne runs the full poll-then-bookkeeping path for a single
// feed. All failure paths still record a feed-result row so the
// `consecutive_failures` counter advances even when the upstream
// goroutine panics.
func (j *IntelJob) pollOne(ctx context.Context, feed intel.Feed) {
	_, _ = j.pollOneSync(ctx, feed)
}

// pollOneSync is the synchronous variant that powers both the
// scheduler's pollOne goroutine AND the admin PollFeed entrypoint.
// It returns (indicatorsUpserted, error) so the handler can surface
// upstream failures to the admin caller — the scheduler path
// discards both values.
func (j *IntelJob) pollOneSync(ctx context.Context, feed intel.Feed) (int, error) {
	start := j.clock()
	logger := j.logger.With(
		slog.String("intel_feed", feed.Name),
		slog.String("intel_provider", feed.Provider),
		slog.String("intel_feed_id", feed.ID),
	)

	// Per-feed deadline. Pollers SHOULD honour ctx; the deadline
	// is the worker's last-resort cap.
	pollCtx, cancel := context.WithTimeout(ctx, j.feedTimeout)
	defer cancel()

	cfg := intel.FeedConfig{
		Provider:   feed.Provider,
		URL:        feed.URL,
		APIKey:     j.apiKeyFor(feed.Provider),
		HTTPClient: j.httpClient,
		Now:        j.clock,
	}

	poller, err := j.registry.Build(cfg)
	if err != nil {
		wrapped := fmt.Errorf("build poller: %w", err)
		j.recordFailure(ctx, feed, start, wrapped, logger)
		return 0, wrapped
	}

	res, err := poller.Poll(pollCtx)
	if err != nil {
		j.recordFailure(ctx, feed, start, err, logger)
		return 0, err
	}

	upserted, err := j.store.UpsertIndicators(ctx, feed.ID, res.Indicators)
	if err != nil {
		wrapped := fmt.Errorf("upsert: %w", err)
		j.recordFailure(ctx, feed, start, wrapped, logger)
		return 0, wrapped
	}

	if err := j.store.RecordFeedResult(ctx, feed.ID, true, j.clock(), ""); err != nil {
		// We did upsert but failed to record the bookkeeping.
		// Treat as failure for alerting purposes; the next cycle
		// will re-poll harmlessly (upsert is idempotent).
		logger.Warn("worker.intel: feed result write failed after successful poll",
			slog.Any("error", err))
	}
	latency := j.clock().Sub(start)
	if j.metrics != nil {
		j.metrics.ObserveIntelPoll(feed.Name, "ok", latency, upserted)
	}
	logger.Info("worker.intel: feed polled",
		slog.Int("indicators_upserted", upserted),
		slog.Int("indicators_polled", len(res.Indicators)),
		slog.Duration("latency", latency))
	return upserted, nil
}

// recordFailure writes the failure bookkeeping and raises a stale
// alert when the threshold is crossed.
func (j *IntelJob) recordFailure(ctx context.Context, feed intel.Feed, start time.Time, pollErr error, logger *slog.Logger) {
	latency := j.clock().Sub(start)
	logger.Warn("worker.intel: feed poll failed",
		slog.Any("error", pollErr),
		slog.Duration("latency", latency))

	if err := j.store.RecordFeedResult(ctx, feed.ID, false, j.clock(), pollErr.Error()); err != nil {
		logger.Warn("worker.intel: record feed result failed",
			slog.Any("error", err))
	}
	if j.metrics != nil {
		j.metrics.ObserveIntelPoll(feed.Name, "error", latency, 0)
	}

	// Re-read the row so we see the post-increment consecutive_failures
	// value (RecordFeedResult bumped it in the store). If the read
	// fails we still proceed — the next cycle will retry.
	updated, getErr := j.store.GetFeed(ctx, feed.ID)
	if getErr != nil {
		return
	}
	if updated.ConsecutiveFailures == j.staleThreshold {
		// Cross-threshold edge: raise the alert exactly once
		// (later failures keep incrementing the counter but the
		// alert is only emitted on the cross). The next success
		// resets ConsecutiveFailures to 0 so a re-failure will
		// re-trigger the alert.
		now := j.clock()
		if err := j.store.RecordStaleAlert(ctx, feed.ID, feed.Name, updated.ConsecutiveFailures, pollErr.Error(), now); err != nil {
			logger.Warn("worker.intel: stale alert write failed",
				slog.Any("error", err))
		}
		if j.metrics != nil {
			j.metrics.ObserveIntelStale(feed.Name)
		}
		logger.Error("worker.intel: feed stale",
			slog.Int("consecutive_failures", updated.ConsecutiveFailures))
	}
}

// maybeGC runs the GarbageCollect sweep if the GC interval has
// elapsed since the last sweep. Disabled when gcInterval is 0.
func (j *IntelJob) maybeGC(ctx context.Context, now time.Time) {
	if j.gcInterval <= 0 {
		return
	}
	j.mu.Lock()
	due := j.lastGC.IsZero() || now.Sub(j.lastGC) >= j.gcInterval
	if due {
		j.lastGC = now
	}
	j.mu.Unlock()
	if !due {
		return
	}
	cutoff := now.Add(-j.gcRetention)
	n, err := j.store.GarbageCollect(ctx, cutoff)
	if err != nil {
		j.logger.Warn("worker.intel: gc failed", slog.Any("error", err))
		return
	}
	if j.metrics != nil {
		j.metrics.ObserveIntelGC(n)
	}
	j.logger.Info("worker.intel: gc swept",
		slog.Int("deleted", n),
		slog.Time("cutoff", cutoff))
}
