package intel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Constructor builds a Poller from a FeedConfig. Each provider
// package (urlhaus, misp, stixtaxii, csv) registers exactly one
// constructor under its provider key via Register() in an init()
// block.
//
// Constructors should validate FeedConfig synchronously and return
// an error rather than producing a poller that fails on the first
// Poll() call — the worker treats a constructor error as a
// permanent fault on the feed (records last_ok=false, raises an
// alert) rather than a transient poll failure.
type Constructor func(FeedConfig) (Poller, error)

// Registry is a thread-safe provider → Constructor map.
//
// The package-level DefaultRegistry holds the four built-in
// providers; consumers can swap it for a custom registry in tests
// (e.g. to stub a single provider while leaving the others wired
// against real upstreams). The worker reads the registry by ref
// rather than by value so tests can mutate the live map without
// fighting Go's import-cycle rules.
type Registry struct {
	mu           sync.RWMutex
	constructors map[string]Constructor
}

// NewRegistry constructs an empty Registry. Most callers want
// DefaultRegistry instead — this exists so tests can build an
// isolated registry without polluting the package-level default.
func NewRegistry() *Registry {
	return &Registry{constructors: make(map[string]Constructor)}
}

// Register associates provider with constructor in r. Re-registering
// an existing provider returns an error; the wiring layer wants a
// loud failure if two packages claim the same key (which would
// otherwise produce a non-deterministic last-write-wins outcome).
func (r *Registry) Register(provider string, c Constructor) error {
	if provider == "" {
		return errors.New("intel: provider key required")
	}
	if c == nil {
		return errors.New("intel: constructor required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.constructors[provider]; dup {
		return fmt.Errorf("intel: provider %q already registered", provider)
	}
	r.constructors[provider] = c
	return nil
}

// MustRegister is the init-time wrapper used by the provider
// sub-packages. A duplicate registration panics so the binary
// fails to start rather than silently choosing one constructor
// over another.
func (r *Registry) MustRegister(provider string, c Constructor) {
	if err := r.Register(provider, c); err != nil {
		panic(err)
	}
}

// Build looks up the constructor for cfg.Provider and invokes it.
// Returns an ErrUnknownProvider when no constructor is registered.
func (r *Registry) Build(cfg FeedConfig) (Poller, error) {
	r.mu.RLock()
	c, ok := r.constructors[cfg.Provider]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, cfg.Provider)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = DefaultHTTPDoer
	}
	return c(cfg)
}

// Providers returns the registered provider keys in sorted order.
// Used by the admin API to advertise the supported set and by the
// validation hook on POST /v1/intel/feeds.
func (r *Registry) Providers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.constructors))
	for p := range r.constructors {
		out = append(out, p)
	}
	// Sort for stable API responses.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// ErrUnknownProvider is returned by Build when cfg.Provider has
// no constructor registered. Exported so callers can errors.Is
// against it.
var ErrUnknownProvider = errors.New("intel: unknown provider")

// DefaultRegistry holds the four built-in providers. The sub-
// packages call DefaultRegistry.MustRegister in their init()
// functions so the wiring layer only needs to import the
// sub-packages for their side effects (anonymous imports in
// cmd/sn360-es/wire_intel.go).
var DefaultRegistry = NewRegistry()

// IntelStore is the persistence contract the worker and admin
// handlers depend on. It is intentionally small — every Postgres
// query the pollers and gate need is exposed as a single method
// so the interface is testable without bringing the migration
// stack into the test process.
//
// All methods take ctx for cancellation; long-running operations
// (UpsertIndicators, GarbageCollect) must honour the deadline so
// the scheduler does not exceed its per-cycle budget.
type IntelStore interface {
	// ListFeeds returns every feed row, ordered by name. The
	// admin API and worker both call it. The worker filters by
	// `enabled` in Go rather than via a SQL predicate so a tenant
	// admin paging the list always sees disabled feeds too.
	ListFeeds(ctx context.Context) ([]Feed, error)

	// GetFeed returns the feed by id; ErrFeedNotFound when absent.
	GetFeed(ctx context.Context, id string) (Feed, error)
	// GetFeedByName returns the feed by name; ErrFeedNotFound when
	// absent. The worker uses it for de-dup during config reloads.
	GetFeedByName(ctx context.Context, name string) (Feed, error)

	// CreateFeed inserts a new feed; returns ErrFeedExists when
	// the name is taken. The returned Feed carries server-side
	// defaults (id, created_at).
	CreateFeed(ctx context.Context, f Feed) (Feed, error)

	// UpdateFeed applies the patch. Only the fields in the patch
	// struct that are non-nil are updated; passing a zero-value
	// patch (all nil) is a no-op. Returns the updated row.
	UpdateFeed(ctx context.Context, id string, patch FeedPatch) (Feed, error)

	// DeleteFeed removes the feed and cascades through to the
	// owned indicators via the FK ON DELETE CASCADE. Idempotent —
	// deleting a non-existent feed returns ErrFeedNotFound but
	// the absence of side effects is the same shape as a
	// successful delete from the caller's perspective.
	DeleteFeed(ctx context.Context, id string) error

	// RecordFeedResult writes the post-poll bookkeeping in one
	// statement: last_fetched_at, last_ok, last_error,
	// consecutive_failures. The worker calls it after every poll
	// (success and failure).
	RecordFeedResult(ctx context.Context, id string, ok bool, fetchedAt time.Time, errMsg string) error

	// UpsertIndicators applies an INSERT … ON CONFLICT (hash,
	// feed_id) DO UPDATE for each Indicator. The Indicator.Hash
	// must already be populated (call Canonicalise first); the
	// store does not re-canonicalise to keep the hot-path single-
	// pass. Returns the count of rows inserted-or-updated (used
	// by the /refresh admin endpoint to surface "n indicators
	// affected" to the operator).
	UpsertIndicators(ctx context.Context, feedID string, indicators []Indicator) (int, error)

	// LookupByHash is the single Tier 0 hot-path query. It returns
	// the matched indicators (with metadata) for the given hash
	// bytes, in arbitrary order. The implementation MUST use the
	// PK index to keep the query at index-only-scan cost; the gate
	// passes hashes through a Redis negative-cache layer before
	// reaching here.
	LookupByHash(ctx context.Context, hashes [][]byte) ([]MatchedIndicator, error)

	// FindByIndicator powers the admin GET /v1/intel/indicators
	// debug endpoint. It looks up a single (canonical) indicator
	// across all feeds. Returns an empty slice (not an error) when
	// no row matches.
	FindByIndicator(ctx context.Context, indicator string) ([]MatchedIndicator, error)

	// GarbageCollect removes indicators whose last_seen is older
	// than cutoff AND for which no other feed_id references the
	// same hash with a fresher last_seen. Returns the count of
	// rows deleted so the worker can metric it.
	GarbageCollect(ctx context.Context, cutoff time.Time) (int, error)

	// RecordStaleAlert writes a deployment-scoped audit row noting
	// that the named feed has crossed the consecutive-failure
	// threshold. Implementations write tenant_id=NULL (the column
	// is nullable for system-level events). The metadata blob is
	// stored verbatim and surfaces in the operator's audit UI;
	// callers should include at least feed_id and failure_count.
	//
	// The worker pairs the write with the
	// `sn360_intel_feed_stale_total{name=...}` Prometheus counter
	// so dashboards can correlate the alert with the audit row.
	RecordStaleAlert(ctx context.Context, feedID, feedName string, failures int, lastError string, occurredAt time.Time) error
}

// Feed is the in-memory shape of the intel_feeds row. The repository
// layer marshals between this struct and the SQL columns.
type Feed struct {
	ID                  string
	Name                string
	Provider            string
	URL                 string
	FetchInterval       time.Duration
	Enabled             bool
	LastFetchedAt       *time.Time
	LastOK              *bool
	LastError           string
	ConsecutiveFailures int
	CreatedAt           time.Time
}

// FeedPatch carries the fields the admin PATCH endpoint can mutate.
// Pointer types let callers distinguish "not in patch" from "set to
// zero". The repository layer translates non-nil pointers into the
// corresponding SQL SET clauses.
type FeedPatch struct {
	URL           *string
	FetchInterval *time.Duration
	Enabled       *bool
}

// MatchedIndicator is the per-row payload the Tier 0 gate consumes
// when LookupByHash returns hits. It carries enough metadata for
// the gate to construct a ti_match reason with the matching feed
// name, severity, indicator type and tags — operators need all of
// these on the audit log to triage a verdict after the fact.
type MatchedIndicator struct {
	Hash          []byte
	Indicator     string
	IndicatorType IndicatorType
	FeedID        string
	FeedName      string
	Severity      int
	Tags          []string
	LastSeen      time.Time
}

// Feed sentinels.
var (
	// ErrFeedNotFound is returned by Get/Update/Delete when no
	// row matches the supplied id (or name).
	ErrFeedNotFound = errors.New("intel: feed not found")
	// ErrFeedExists is returned by CreateFeed when the name
	// uniqueness constraint would be violated.
	ErrFeedExists = errors.New("intel: feed name already exists")
)
