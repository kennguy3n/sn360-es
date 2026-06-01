package repository

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// MemoryIntelStore is the in-memory implementation of
// intel.IntelStore. It mirrors PgIntelStore semantically — the same
// CRUD / Upsert / LookupByHash / GarbageCollect surface — and is the
// store the worker, evaluator and admin handlers use in unit tests.
//
// Concurrency: every public method takes mu, so concurrent callers
// are serialised. Tests that need parallel access (e.g. the
// scheduler's GC overlap test) can rely on the read paths blocking
// the write paths — there is no separate read lock.
type MemoryIntelStore struct {
	mu          sync.Mutex
	feeds       map[string]intel.Feed // keyed by id
	indicators  []memoryIndicator     // flat slice; small dataset for tests
	staleAlerts []MemoryStaleAlert    // recorded in RecordStaleAlert
	clock       func() time.Time
}

// MemoryStaleAlert captures the arguments passed to RecordStaleAlert
// so tests can assert that the worker raised the expected alert.
type MemoryStaleAlert struct {
	FeedID     string
	FeedName   string
	Failures   int
	LastError  string
	OccurredAt time.Time
}

// memoryIndicator is the row shape held in the slice.
type memoryIndicator struct {
	hash      []byte
	indicator string
	typ       intel.IndicatorType
	feedID    string
	firstSeen time.Time
	lastSeen  time.Time
	severity  int
	tags      []string
}

// NewMemoryIntelStore constructs an empty store with time.Now.
func NewMemoryIntelStore() *MemoryIntelStore {
	return &MemoryIntelStore{
		feeds:      make(map[string]intel.Feed),
		indicators: nil,
		clock:      time.Now,
	}
}

// WithClock overrides the clock seam.
func (m *MemoryIntelStore) WithClock(now func() time.Time) *MemoryIntelStore {
	m.clock = now
	return m
}

// ListFeeds returns every feed ordered by name.
func (m *MemoryIntelStore) ListFeeds(_ context.Context) ([]intel.Feed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]intel.Feed, 0, len(m.feeds))
	for _, f := range m.feeds {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GetFeed returns the feed by id.
func (m *MemoryIntelStore) GetFeed(_ context.Context, id string) (intel.Feed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.feeds[id]; ok {
		return f, nil
	}
	return intel.Feed{}, intel.ErrFeedNotFound
}

// GetFeedByName returns the feed by name.
func (m *MemoryIntelStore) GetFeedByName(_ context.Context, name string) (intel.Feed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.feeds {
		if f.Name == name {
			return f, nil
		}
	}
	return intel.Feed{}, intel.ErrFeedNotFound
}

// CreateFeed inserts a new feed. Auto-assigns id + created_at when
// unset; rejects duplicate names with ErrFeedExists.
func (m *MemoryIntelStore) CreateFeed(_ context.Context, f intel.Feed) (intel.Feed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.feeds {
		if existing.Name == f.Name {
			return intel.Feed{}, intel.ErrFeedExists
		}
	}
	if f.ID == "" {
		f.ID = uuid.NewString()
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = m.clock()
	}
	if f.FetchInterval <= 0 {
		f.FetchInterval = 15 * time.Minute
	}
	m.feeds[f.ID] = f
	return f, nil
}

// UpdateFeed applies patch.
func (m *MemoryIntelStore) UpdateFeed(_ context.Context, id string, patch intel.FeedPatch) (intel.Feed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.feeds[id]
	if !ok {
		return intel.Feed{}, intel.ErrFeedNotFound
	}
	if patch.URL != nil {
		f.URL = *patch.URL
	}
	if patch.FetchInterval != nil {
		f.FetchInterval = *patch.FetchInterval
	}
	if patch.Enabled != nil {
		f.Enabled = *patch.Enabled
	}
	m.feeds[id] = f
	return f, nil
}

// DeleteFeed removes the feed and its indicators (CASCADE).
func (m *MemoryIntelStore) DeleteFeed(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.feeds[id]; !ok {
		return intel.ErrFeedNotFound
	}
	delete(m.feeds, id)
	kept := m.indicators[:0]
	for _, ind := range m.indicators {
		if ind.feedID != id {
			kept = append(kept, ind)
		}
	}
	m.indicators = kept
	return nil
}

// RecordFeedResult writes the post-poll bookkeeping. On success
// resets consecutive_failures; on failure increments it.
func (m *MemoryIntelStore) RecordFeedResult(_ context.Context, id string, ok bool, fetchedAt time.Time, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, found := m.feeds[id]
	if !found {
		return intel.ErrFeedNotFound
	}
	f.LastFetchedAt = &fetchedAt
	f.LastOK = &ok
	if ok {
		f.LastError = ""
		f.ConsecutiveFailures = 0
	} else {
		f.LastError = errMsg
		f.ConsecutiveFailures++
	}
	m.feeds[id] = f
	return nil
}

// UpsertIndicators applies INSERT … ON CONFLICT semantics.
func (m *MemoryIntelStore) UpsertIndicators(_ context.Context, feedID string, indicators []intel.Indicator) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.feeds[feedID]; !ok {
		return 0, intel.ErrFeedNotFound
	}
	now := m.clock()
	n := 0
	for _, ind := range indicators {
		idx := m.findByHashAndFeed(ind.Hash, feedID)
		if idx < 0 {
			m.indicators = append(m.indicators, memoryIndicator{
				hash:      append([]byte(nil), ind.Hash...),
				indicator: ind.Indicator,
				typ:       ind.Type,
				feedID:    feedID,
				firstSeen: now,
				lastSeen:  now,
				severity:  ind.Severity,
				tags:      append([]string(nil), ind.Tags...),
			})
		} else {
			row := m.indicators[idx]
			row.indicator = ind.Indicator
			row.typ = ind.Type
			row.lastSeen = now
			if ind.Severity > row.severity {
				row.severity = ind.Severity
			}
			row.tags = append([]string(nil), ind.Tags...)
			m.indicators[idx] = row
		}
		n++
	}
	return n, nil
}

// LookupByHash returns matched indicators for the given hashes.
func (m *MemoryIntelStore) LookupByHash(_ context.Context, hashes [][]byte) ([]intel.MatchedIndicator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(hashes) == 0 {
		return nil, nil
	}
	out := make([]intel.MatchedIndicator, 0, len(hashes))
	for _, h := range hashes {
		for _, ind := range m.indicators {
			if bytes.Equal(h, ind.hash) {
				feedName := ""
				if f, ok := m.feeds[ind.feedID]; ok {
					feedName = f.Name
				}
				out = append(out, intel.MatchedIndicator{
					Hash:          append([]byte(nil), ind.hash...),
					Indicator:     ind.indicator,
					IndicatorType: ind.typ,
					FeedID:        ind.feedID,
					FeedName:      feedName,
					Severity:      ind.severity,
					Tags:          append([]string(nil), ind.tags...),
					LastSeen:      ind.lastSeen,
				})
			}
		}
	}
	return out, nil
}

// FindByIndicator canonicalises the input and looks up by hash.
// Tries each supported type and de-duplicates the resulting hashes
// — a value that canonicalises identically under two types (e.g.
// "1.2.3.4" parses as an IP but also lowercases as a "domain") must
// not produce a duplicate match per type.
func (m *MemoryIntelStore) FindByIndicator(ctx context.Context, indicator string) ([]intel.MatchedIndicator, error) {
	hashes := uniqueCandidateHashes(indicator)
	if len(hashes) == 0 {
		return nil, nil
	}
	return m.LookupByHash(ctx, hashes)
}

// uniqueCandidateHashes returns the set of distinct hashes that the
// supplied raw indicator would produce under any of the supported
// types. Reused by Postgres' FindByIndicator so both stores share
// the same de-dup semantics.
func uniqueCandidateHashes(raw string) [][]byte {
	types := []intel.IndicatorType{
		intel.IndicatorDomain, intel.IndicatorURL,
		intel.IndicatorIP, intel.IndicatorSHA256,
	}
	seen := make(map[string]struct{}, len(types))
	out := make([][]byte, 0, len(types))
	for _, t := range types {
		h, err := intel.HashIndicator(t, raw)
		if err != nil {
			continue
		}
		key := string(h)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, h)
	}
	return out
}

// GarbageCollect mirrors the PG implementation's semantics: delete
// rows with last_seen < cutoff that are NOT shadowed by a fresher
// row for the same hash on a different feed.
func (m *MemoryIntelStore) GarbageCollect(_ context.Context, cutoff time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// First, index "fresh" hashes (rows with last_seen >= cutoff)
	// so the deletion pass can do O(1) shadow checks.
	fresh := make(map[string]map[string]struct{}) // hash-hex → feedID set
	for _, ind := range m.indicators {
		if !ind.lastSeen.Before(cutoff) {
			key := string(ind.hash)
			if _, ok := fresh[key]; !ok {
				fresh[key] = make(map[string]struct{})
			}
			fresh[key][ind.feedID] = struct{}{}
		}
	}
	kept := make([]memoryIndicator, 0, len(m.indicators))
	deleted := 0
	for _, ind := range m.indicators {
		if ind.lastSeen.Before(cutoff) {
			// Does another feed have a fresh row for this hash?
			if peers, ok := fresh[string(ind.hash)]; ok {
				stillFresh := false
				for peerFeed := range peers {
					if peerFeed != ind.feedID {
						stillFresh = true
						break
					}
				}
				if stillFresh {
					kept = append(kept, ind)
					continue
				}
			}
			deleted++
			continue
		}
		kept = append(kept, ind)
	}
	m.indicators = kept
	return deleted, nil
}

// RecordStaleAlert records an in-memory alert. The in-memory store
// has no audit_logs table so the alert is held in a slice that
// tests can introspect via StaleAlerts().
func (m *MemoryIntelStore) RecordStaleAlert(_ context.Context, feedID, feedName string, failures int, lastError string, occurredAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staleAlerts = append(m.staleAlerts, MemoryStaleAlert{
		FeedID:     feedID,
		FeedName:   feedName,
		Failures:   failures,
		LastError:  lastError,
		OccurredAt: occurredAt,
	})
	return nil
}

// StaleAlerts returns a snapshot of recorded alerts. Returned slice
// is a copy so callers can range over it without holding the lock.
func (m *MemoryIntelStore) StaleAlerts() []MemoryStaleAlert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MemoryStaleAlert, len(m.staleAlerts))
	copy(out, m.staleAlerts)
	return out
}

func (m *MemoryIntelStore) findByHashAndFeed(hash []byte, feedID string) int {
	for i, ind := range m.indicators {
		if ind.feedID == feedID && bytes.Equal(ind.hash, hash) {
			return i
		}
	}
	return -1
}

// Statically assert that the in-memory store satisfies the
// IntelStore interface. The compiler-time check guarantees the
// interface stays in sync as new methods are added.
var _ intel.IntelStore = (*MemoryIntelStore)(nil)
