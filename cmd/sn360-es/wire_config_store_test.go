package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
)

// fakeScoreEngineRepo is a deterministic in-process implementation of
// repository.ScoreEngineRepository used to drive postgresConfigStore
// in isolation from a real Postgres pool. It mirrors the semantics
// of pgScoreEngines: UpdateWeights / UpdateThresholds return
// repository.ErrNotFound when no row exists for the tenant, so the
// caller's seed-then-upsert fallback path is exercised exactly as it
// would be against Postgres.
type fakeScoreEngineRepo struct {
	mu       sync.Mutex
	rows     map[string]repository.ScoreEngine
	getErr   error
	upErr    error
	updWErr  error
	updTErr  error
	getHits  int
	upHits   int
	updWHits int
	updTHits int
}

func newFakeScoreEngineRepo() *fakeScoreEngineRepo {
	return &fakeScoreEngineRepo{rows: map[string]repository.ScoreEngine{}}
}

func (f *fakeScoreEngineRepo) Get(_ context.Context, tenantID string) (*repository.ScoreEngine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getHits++
	if f.getErr != nil {
		return nil, f.getErr
	}
	s, ok := f.rows[tenantID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := s
	return &cp, nil
}

func (f *fakeScoreEngineRepo) Upsert(_ context.Context, s *repository.ScoreEngine) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upHits++
	if f.upErr != nil {
		return f.upErr
	}
	f.rows[s.TenantID] = *s
	return nil
}

func (f *fakeScoreEngineRepo) UpdateWeights(_ context.Context, tenantID string, w repository.ScoreWeightUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updWHits++
	if f.updWErr != nil {
		return f.updWErr
	}
	row, ok := f.rows[tenantID]
	if !ok {
		return repository.ErrNotFound
	}
	row.WeightAI = w.WeightAI
	row.WeightRspamd = w.WeightRspamd
	row.WeightAttachments = w.WeightAttachments
	row.WeightLinks = w.WeightLinks
	f.rows[tenantID] = row
	return nil
}

func (f *fakeScoreEngineRepo) UpdateThresholds(_ context.Context, tenantID string, t repository.ScoreThresholdUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updTHits++
	if f.updTErr != nil {
		return f.updTErr
	}
	row, ok := f.rows[tenantID]
	if !ok {
		return repository.ErrNotFound
	}
	row.ThresholdBlocked = t.Blocked
	row.ThresholdHigh = t.High
	row.ThresholdWarning = t.Warning
	row.ThresholdCaution = t.Caution
	row.ThresholdInfo = t.Info
	row.ThresholdTier1PassBelow = t.Tier1PassBelow
	row.ThresholdTier1FlagAbove = t.Tier1FlagAbove
	f.rows[tenantID] = row
	return nil
}

// TestPostgresConfigStore_UpdateWeights_SeedsThenUpserts asserts that
// the very first UpdateWeights call against a tenant whose row does
// not exist yet creates a fresh row populated with the schema
// defaults, overlays the supplied float weights as integer
// percentages, and upserts it back. The contract matters because the
// onboarding agent invokes UpdateWeights on first-onboard *before*
// any other writer has ever touched the score_engine row. The
// column-scoped UpdateWeights call must return ErrNotFound first so
// the seed-then-upsert fallback runs exactly once.
func TestPostgresConfigStore_UpdateWeights_SeedsThenUpserts(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	store := newPostgresConfigStore(repo, nil)

	err := store.UpdateWeights(context.Background(), "tenant-a", agent.ScoreWeights{
		AI:          0.5,
		Rspamd:      0.3,
		Attachments: 0.15,
		Links:       0.05,
	})
	if err != nil {
		t.Fatalf("UpdateWeights: %v", err)
	}

	if repo.updWHits != 1 {
		t.Fatalf("expected exactly 1 UpdateWeights attempt before fallback, got %d", repo.updWHits)
	}
	if repo.upHits != 1 {
		t.Fatalf("expected exactly 1 Upsert fallback, got %d", repo.upHits)
	}
	row, ok := repo.rows["tenant-a"]
	if !ok {
		t.Fatalf("expected row for tenant-a after upsert")
	}
	if got, want := row.WeightAI, 50; got != want {
		t.Errorf("WeightAI = %d, want %d", got, want)
	}
	if got, want := row.WeightRspamd, 30; got != want {
		t.Errorf("WeightRspamd = %d, want %d", got, want)
	}
	if got, want := row.WeightAttachments, 15; got != want {
		t.Errorf("WeightAttachments = %d, want %d", got, want)
	}
	// 0.05 * 100 + 0.5 = 5.5 -> 5
	if got, want := row.WeightLinks, 5; got != want {
		t.Errorf("WeightLinks = %d, want %d", got, want)
	}
	// Schema-default banner thresholds (from migration 0001) must
	// survive the seed-then-overlay path so the first UpdateWeights
	// call doesn't silently wipe Tier 1 / banner thresholds.
	if got, want := row.ThresholdBlocked, 85; got != want {
		t.Errorf("ThresholdBlocked (seeded default) = %d, want %d", got, want)
	}
	if got, want := row.ThresholdTier1PassBelow, 20; got != want {
		t.Errorf("ThresholdTier1PassBelow (seeded default) = %d, want %d", got, want)
	}
	if got, want := row.ThresholdTier1FlagAbove, 60; got != want {
		t.Errorf("ThresholdTier1FlagAbove (seeded default) = %d, want %d", got, want)
	}
}

// TestPostgresConfigStore_UpdateThresholds_PreservesWeights asserts
// that UpdateThresholds only touches the threshold columns: an
// existing row's weights survive the read-modify-write so the tuning
// agent can update thresholds without clobbering whatever weights the
// onboarding agent (or admin UI) already wrote.
func TestPostgresConfigStore_UpdateThresholds_PreservesWeights(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	repo.rows["tenant-b"] = repository.ScoreEngine{
		TenantID:          "tenant-b",
		ScoreBase:         100,
		WeightAI:          70,
		WeightRspamd:      20,
		WeightAttachments: 5,
		WeightLinks:       5,
		ThresholdBlocked:  85,
		ThresholdHigh:     70,
		ThresholdWarning:  50,
		ThresholdCaution:  30,
		ThresholdInfo:     15,
	}
	store := newPostgresConfigStore(repo, nil)

	err := store.UpdateThresholds(context.Background(), "tenant-b", agent.Thresholds{
		Tier1PassBelow: 25,
		Tier1FlagAbove: 65,
		BannerBlocked:  90,
		BannerHighRisk: 75,
		BannerWarning:  55,
		BannerCaution:  35,
		BannerInfo:     20,
	})
	if err != nil {
		t.Fatalf("UpdateThresholds: %v", err)
	}
	row := repo.rows["tenant-b"]
	if row.WeightAI != 70 || row.WeightRspamd != 20 || row.WeightAttachments != 5 || row.WeightLinks != 5 {
		t.Fatalf("weights were clobbered: %+v", row)
	}
	if row.ThresholdBlocked != 90 || row.ThresholdHigh != 75 || row.ThresholdWarning != 55 ||
		row.ThresholdCaution != 35 || row.ThresholdInfo != 20 {
		t.Fatalf("banner thresholds not persisted: %+v", row)
	}
	if row.ThresholdTier1PassBelow != 25 || row.ThresholdTier1FlagAbove != 65 {
		t.Fatalf("tier1 thresholds not persisted: %+v", row)
	}
	// The column-scoped update path must run (no fallback Upsert) when
	// the row already exists.
	if repo.updTHits != 1 {
		t.Fatalf("expected exactly 1 UpdateThresholds, got %d", repo.updTHits)
	}
	if repo.upHits != 0 {
		t.Fatalf("expected no Upsert fallback when row exists, got %d", repo.upHits)
	}
}

// TestPostgresConfigStore_UpdateWeights_NoUpsertWhenRowExists asserts
// that the column-scoped UpdateWeights path is taken (no full-row
// Upsert) when a tenant row already exists. This is the production
// race-free path; falling through to Upsert here would re-introduce
// the read-modify-write race against UpdateThresholds.
func TestPostgresConfigStore_UpdateWeights_NoUpsertWhenRowExists(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	repo.rows["tenant-d"] = repository.ScoreEngine{
		TenantID:                "tenant-d",
		WeightAI:                80,
		WeightRspamd:            20,
		ThresholdBlocked:        85,
		ThresholdHigh:           70,
		ThresholdWarning:        50,
		ThresholdCaution:        30,
		ThresholdInfo:           15,
		ThresholdTier1PassBelow: 20,
		ThresholdTier1FlagAbove: 60,
	}
	store := newPostgresConfigStore(repo, nil)

	if err := store.UpdateWeights(context.Background(), "tenant-d", agent.ScoreWeights{
		AI: 0.6, Rspamd: 0.4,
	}); err != nil {
		t.Fatalf("UpdateWeights: %v", err)
	}

	if repo.updWHits != 1 {
		t.Fatalf("expected 1 UpdateWeights, got %d", repo.updWHits)
	}
	if repo.upHits != 0 {
		t.Fatalf("expected no Upsert fallback when row exists, got %d", repo.upHits)
	}
	row := repo.rows["tenant-d"]
	// Threshold columns must be untouched by the column-scoped
	// UpdateWeights (this is precisely what kills the cross-column
	// race the old full-row Upsert had).
	if row.ThresholdBlocked != 85 || row.ThresholdTier1PassBelow != 20 {
		t.Fatalf("thresholds were clobbered by UpdateWeights: %+v", row)
	}
	if row.WeightAI != 60 || row.WeightRspamd != 40 {
		t.Fatalf("weights not persisted: %+v", row)
	}
}

// TestRoundTrip_CurrentWeightsPreservesScale wires
// tuningResultAdapter.CurrentWeights + postgresConfigStore.UpdateWeights
// in series — the same call sequence the tuning agent executes per
// tenant on every tuning pass. It pins the bug that the previous
// implementation hit: CurrentWeights cast the integer percent column
// to float64 without dividing by 100, so the [0, 1] contract that
// agent.clampWeights expects was violated, every weight clipped to
// 1.0, and the renormaliser then wrote 1/N back to the DB. After the
// scale fix in CurrentWeights, this round-trip must preserve the
// tenant's distribution.
func TestRoundTrip_CurrentWeightsPreservesScale(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	repo.rows["tenant-rt"] = repository.ScoreEngine{
		TenantID:                "tenant-rt",
		ScoreBase:               100,
		WeightAI:                80,
		WeightRspamd:            20,
		WeightAttachments:       0,
		WeightLinks:             0,
		ThresholdBlocked:        85,
		ThresholdHigh:           70,
		ThresholdWarning:        50,
		ThresholdCaution:        30,
		ThresholdInfo:           15,
		ThresholdTier1PassBelow: 20,
		ThresholdTier1FlagAbove: 60,
		SubjectTagEnabled:       false,
		SubjectTagPrefix:        "SN360",
	}

	repos := &repository.Registry{ScoreEngines: repo}
	reader := tuningResultAdapter{repos: repos}
	store := newPostgresConfigStore(repo, nil)

	// Step 1: read the seeded row. Must come back as [0, 1] floats,
	// NOT raw integers — anything > 1 here is the regression that
	// motivated this test.
	w, err := reader.CurrentWeights(context.Background(), "tenant-rt")
	if err != nil {
		t.Fatalf("CurrentWeights: %v", err)
	}
	if w.AI != 0.80 || w.Rspamd != 0.20 || w.Attachments != 0 || w.Links != 0 {
		t.Fatalf("CurrentWeights returned unscaled values: %+v (expected AI=0.80 Rspamd=0.20)", w)
	}
	for _, v := range []float64{w.AI, w.Rspamd, w.Attachments, w.Links} {
		if v < 0 || v > 1 {
			t.Fatalf("CurrentWeights produced out-of-range value %v (must be in [0, 1])", v)
		}
	}

	// Step 2: apply a small adjustment in the [0, 1] domain, the
	// way the tuning agent's Decide() would (renormalised float).
	wAdjusted := agent.ScoreWeights{
		AI:          0.75,
		Rspamd:      0.25,
		Attachments: 0,
		Links:       0,
	}
	if err := store.UpdateWeights(context.Background(), "tenant-rt", wAdjusted); err != nil {
		t.Fatalf("UpdateWeights: %v", err)
	}

	// Step 3: read again. The new values must reflect the adjustment
	// and still be in [0, 1] — NOT corrupted to 1/N by a missing
	// scale conversion.
	w2, err := reader.CurrentWeights(context.Background(), "tenant-rt")
	if err != nil {
		t.Fatalf("CurrentWeights (post-update): %v", err)
	}
	if w2.AI != 0.75 || w2.Rspamd != 0.25 || w2.Attachments != 0 || w2.Links != 0 {
		t.Fatalf("CurrentWeights post-update returned %+v, want AI=0.75 Rspamd=0.25", w2)
	}

	// And thresholds must be untouched by the weight write (the
	// column-scoped UPDATE contract).
	row := repo.rows["tenant-rt"]
	if row.ThresholdBlocked != 85 || row.ThresholdTier1PassBelow != 20 || row.ThresholdTier1FlagAbove != 60 {
		t.Fatalf("thresholds clobbered by UpdateWeights: %+v", row)
	}
}

// TestPostgresConfigStore_UpdateWeights_LoadError surfaces the
// failure mode that motivated this code: if the score-engine read
// fails, the agent must see an error (not a silent overwrite of
// whatever in-memory state existed) so it can NAK / retry the tuning
// decision against a degraded Postgres backend.
func TestPostgresConfigStore_UpdateWeights_LoadError(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	boom := errors.New("connection refused")
	repo.getErr = boom
	store := newPostgresConfigStore(repo, nil)

	err := store.UpdateWeights(context.Background(), "tenant-c", agent.ScoreWeights{AI: 1})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped %v, got %v", boom, err)
	}
	if repo.upHits != 0 {
		t.Fatalf("expected no Upsert after load error, got %d", repo.upHits)
	}
}

// TestClampWeightToPercent pins the float-to-int mapping used by
// postgresConfigStore. The agent's renormalised weights are in
// [0, 1]; the score_engine column type is INT (percent). The clamp
// floors negatives to 0 and caps overflows at 100 so a misbehaving
// tuning iteration cannot insert a row that violates the
// CHECK constraint.
func TestClampWeightToPercent(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   float64
		out  int
	}{
		{"zero", 0, 0},
		{"negative", -0.5, 0},
		{"one", 1, 100},
		{"overflow", 1.5, 100},
		{"midpoint", 0.5, 50},
		{"rounds-up", 0.005, 1},
		{"rounds-down", 0.004, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampWeightToPercent(tc.in); got != tc.out {
				t.Errorf("clampWeightToPercent(%v) = %d, want %d", tc.in, got, tc.out)
			}
		})
	}
}

// TestTenantScoringConfigAdapter_LoadReadsAndCachesScoreEngine asserts
// the evaluator-side adapter returns the persisted score_engine row
// translated into evaluate.TenantScoringConfig (integer percentages
// divided by 100 to land in [0, 1]) AND that a second Load call
// within the TTL window does not re-hit the repository. The cache
// behaviour is the operational contract that keeps verdict-path
// latency from being dragged onto every Postgres round-trip when
// the same tenant evaluates thousands of messages per second.
func TestTenantScoringConfigAdapter_LoadReadsAndCachesScoreEngine(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	repo.rows["tenant-x"] = repository.ScoreEngine{
		TenantID:                "tenant-x",
		WeightAI:                70,
		WeightRspamd:            20,
		WeightAttachments:       10,
		WeightLinks:             0,
		ThresholdTier1PassBelow: 25,
		ThresholdTier1FlagAbove: 65,
	}
	adapter := newTenantScoringConfigAdapter(repo, time.Minute)

	got, err := adapter.LoadTenantScoringConfig(context.Background(), "tenant-x")
	if err != nil {
		t.Fatalf("LoadTenantScoringConfig: %v", err)
	}
	wantWeights := evaluate.Weights{AI: 0.7, Rspamd: 0.2, Attachments: 0.1, Links: 0}
	if got.Weights != wantWeights {
		t.Fatalf("first load weights: got %+v want %+v", got.Weights, wantWeights)
	}
	if got.Tier1PassThreshold == nil || *got.Tier1PassThreshold != 25 {
		t.Fatalf("first load Tier1PassThreshold: got %v want 25", got.Tier1PassThreshold)
	}
	if got.Tier1FlagThreshold == nil || *got.Tier1FlagThreshold != 65 {
		t.Fatalf("first load Tier1FlagThreshold: got %v want 65", got.Tier1FlagThreshold)
	}
	if repo.getHits != 1 {
		t.Fatalf("expected 1 repo hit, got %d", repo.getHits)
	}

	if _, err := adapter.LoadTenantScoringConfig(context.Background(), "tenant-x"); err != nil {
		t.Fatalf("second LoadTenantScoringConfig: %v", err)
	}
	if repo.getHits != 1 {
		t.Fatalf("expected cache hit (still 1 repo hit), got %d", repo.getHits)
	}
}

// TestTenantScoringConfigAdapter_InvalidateForcesReread asserts the
// adapter re-reads from the repository after Invalidate is called.
// This is the cache-coherence contract postgresConfigStore relies on
// to make tuning writes visible to evaluation immediately, rather
// than after a 60s TTL expiry.
func TestTenantScoringConfigAdapter_InvalidateForcesReread(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	repo.rows["tenant-y"] = repository.ScoreEngine{
		TenantID:     "tenant-y",
		WeightAI:     50,
		WeightRspamd: 50,
	}
	adapter := newTenantScoringConfigAdapter(repo, time.Hour)

	if _, err := adapter.LoadTenantScoringConfig(context.Background(), "tenant-y"); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if repo.getHits != 1 {
		t.Fatalf("expected 1 repo hit, got %d", repo.getHits)
	}

	row := repo.rows["tenant-y"]
	row.WeightAI = 80
	row.WeightRspamd = 20
	repo.rows["tenant-y"] = row
	adapter.Invalidate("tenant-y")

	got, err := adapter.LoadTenantScoringConfig(context.Background(), "tenant-y")
	if err != nil {
		t.Fatalf("post-invalidate load: %v", err)
	}
	if got.Weights.AI != 0.8 || got.Weights.Rspamd != 0.2 {
		t.Fatalf("invalidated cache returned stale weights: %+v", got)
	}
	if repo.getHits != 2 {
		t.Fatalf("expected 2 repo hits after invalidate, got %d", repo.getHits)
	}
}

// TestTenantScoringConfigAdapter_NotFoundIsNotAnError asserts the
// adapter returns (zero TenantScoringConfig, nil) when no row exists
// for a tenant. This is the contract the evaluator's
// resolveTenantConfig depends on to fall through to its static
// defaults for un-tuned tenants without surfacing a noisy error.
func TestTenantScoringConfigAdapter_NotFoundIsNotAnError(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	adapter := newTenantScoringConfigAdapter(repo, time.Minute)
	got, err := adapter.LoadTenantScoringConfig(context.Background(), "no-such-tenant")
	if err != nil {
		t.Fatalf("LoadTenantScoringConfig: unexpected error %v", err)
	}
	if got != (evaluate.TenantScoringConfig{}) {
		t.Fatalf("expected zero TenantScoringConfig, got %+v", got)
	}
}

// TestPostgresConfigStore_UpdateInvalidatesCache asserts the
// production wire-up: postgresConfigStore notifies the adapter after
// every successful UpdateWeights / UpdateThresholds so the
// evaluator-side cache cannot return stale values across a tuning
// pass. The seed-then-upsert fallback path is exercised explicitly
// (no row exists for tenant-z at start) because it is the only
// branch that does NOT go through the column-scoped UPDATE.
func TestPostgresConfigStore_UpdateInvalidatesCache(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	adapter := newTenantScoringConfigAdapter(repo, time.Hour)
	store := newPostgresConfigStore(repo, adapter)

	if err := store.UpdateWeights(context.Background(), "tenant-z", agent.ScoreWeights{
		AI: 0.6, Rspamd: 0.4,
	}); err != nil {
		t.Fatalf("UpdateWeights (seed): %v", err)
	}
	tc, err := adapter.LoadTenantScoringConfig(context.Background(), "tenant-z")
	if err != nil {
		t.Fatalf("LoadTenantScoringConfig: %v", err)
	}
	if tc.Weights.AI != 0.6 || tc.Weights.Rspamd != 0.4 {
		t.Fatalf("after seed: got %+v want AI=0.6 Rspamd=0.4", tc.Weights)
	}
	hitsAfterSeed := repo.getHits

	if err := store.UpdateWeights(context.Background(), "tenant-z", agent.ScoreWeights{
		AI: 0.8, Rspamd: 0.2,
	}); err != nil {
		t.Fatalf("UpdateWeights (steady-state): %v", err)
	}
	tc, err = adapter.LoadTenantScoringConfig(context.Background(), "tenant-z")
	if err != nil {
		t.Fatalf("LoadTenantScoringConfig (post-update): %v", err)
	}
	if tc.Weights.AI != 0.8 || tc.Weights.Rspamd != 0.2 {
		t.Fatalf("cache returned stale weights after UpdateWeights: %+v", tc.Weights)
	}
	if repo.getHits != hitsAfterSeed+1 {
		t.Fatalf("expected exactly one additional repo hit after invalidation, got %d (was %d)", repo.getHits, hitsAfterSeed)
	}

	if err := store.UpdateThresholds(context.Background(), "tenant-z", agent.Thresholds{
		BannerBlocked:  90,
		BannerHighRisk: 70,
		BannerWarning:  50,
		BannerCaution:  30,
		BannerInfo:     15,
		Tier1PassBelow: 30,
		Tier1FlagAbove: 70,
	}); err != nil {
		t.Fatalf("UpdateThresholds: %v", err)
	}
	tc, err = adapter.LoadTenantScoringConfig(context.Background(), "tenant-z")
	if err != nil {
		t.Fatalf("LoadTenantScoringConfig (post-thresholds): %v", err)
	}
	if tc.Tier1PassThreshold == nil || *tc.Tier1PassThreshold != 30 {
		t.Fatalf("cache returned stale Tier1PassThreshold: got %v want 30", tc.Tier1PassThreshold)
	}
	if tc.Tier1FlagThreshold == nil || *tc.Tier1FlagThreshold != 70 {
		t.Fatalf("cache returned stale Tier1FlagThreshold: got %v want 70", tc.Tier1FlagThreshold)
	}
}

// TestTenantScoringConfigAdapter_SweepExpired pins the eviction
// invariant: entries past their expiresAt timestamp are removed and
// counted, fresh entries are preserved, and a nil receiver is safe
// (mirrors memoryLabelCache.sweepExpired). Without this sweep, a
// multi-tenant SaaS with churn would accumulate entries for
// deactivated tenants indefinitely — the cache map only ever grows
// because storeFull() overwrites the same slot it occupied before.
func TestTenantScoringConfigAdapter_SweepExpired(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	a := newTenantScoringConfigAdapter(repo, 100*time.Millisecond)

	// Seed three entries: two will expire, one is fresh.
	a.storeFull("tenant-old-1", evaluate.TenantScoringConfig{}, "")
	a.storeFull("tenant-old-2", evaluate.TenantScoringConfig{}, "")
	a.storeFull("tenant-fresh", evaluate.TenantScoringConfig{}, "")
	if got := len(a.cache); got != 3 {
		t.Fatalf("setup: cache has %d entries, want 3", got)
	}

	// Walk the clock forward past the TTL.
	now := time.Now().Add(200 * time.Millisecond)

	// Re-stamp the fresh entry so it survives the sweep — simulates
	// a recent LoadTenantScoringConfig call.
	a.mu.Lock()
	a.cache["tenant-fresh"] = tenantScoringConfigCacheEntry{
		value:     evaluate.TenantScoringConfig{},
		expiresAt: now.Add(60 * time.Second),
	}
	a.mu.Unlock()

	evicted := a.sweepExpired(now)
	if evicted != 2 {
		t.Fatalf("sweepExpired returned %d, want 2", evicted)
	}
	if got := len(a.cache); got != 1 {
		t.Fatalf("post-sweep: cache has %d entries, want 1", got)
	}
	if _, ok := a.cache["tenant-fresh"]; !ok {
		t.Fatalf("post-sweep: fresh entry was incorrectly evicted")
	}

	// Idempotency: a second sweep at the same wall-clock evicts nothing.
	if evicted := a.sweepExpired(now); evicted != 0 {
		t.Fatalf("second sweepExpired returned %d, want 0 (idempotent)", evicted)
	}

	// Nil-receiver safety: a panic here would be a regression of the
	// nil guard in sweepExpired (matches memoryLabelCache contract).
	var nilAdapter *tenantScoringConfigAdapter
	if got := nilAdapter.sweepExpired(now); got != 0 {
		t.Fatalf("nil receiver sweepExpired returned %d, want 0", got)
	}
}

// TestTenantScoringConfigAdapter_RunJanitor pins the background-loop
// contract: the janitor sweeps expired entries on the supplied
// interval and exits cleanly when the context is cancelled. This
// guards against two real regressions — (1) the janitor never
// actually evicting anything (e.g. ticker channel never read),
// and (2) the janitor leaking past ctx cancellation.
func TestTenantScoringConfigAdapter_RunJanitor(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	a := newTenantScoringConfigAdapter(repo, 10*time.Millisecond)

	// Plant an already-expired entry so the very first tick will
	// have something to remove.
	a.mu.Lock()
	a.cache["tenant-expired"] = tenantScoringConfigCacheEntry{
		value:     evaluate.TenantScoringConfig{},
		expiresAt: time.Now().Add(-time.Hour),
	}
	a.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.runJanitor(ctx, 5*time.Millisecond, nil)
		close(done)
	}()

	// Poll until the janitor has removed the expired entry, with a
	// generous overall deadline to avoid flake on loaded CI hosts.
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.mu.RLock()
		empty := len(a.cache) == 0
		a.mu.RUnlock()
		if empty {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("janitor did not evict expired entry within 2s")
		}
		time.Sleep(2 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
		// runJanitor returned, as required.
	case <-time.After(time.Second):
		t.Fatal("janitor did not exit within 1s of ctx cancellation")
	}

	// Nil-receiver safety: a janitor on a nil adapter must return
	// immediately without panicking or spinning.
	nilCtx, nilCancel := context.WithCancel(context.Background())
	defer nilCancel()
	nilDone := make(chan struct{})
	var nilAdapter *tenantScoringConfigAdapter
	go func() {
		nilAdapter.runJanitor(nilCtx, 5*time.Millisecond, nil)
		close(nilDone)
	}()
	select {
	case <-nilDone:
		// expected
	case <-time.After(time.Second):
		t.Fatal("nil-adapter runJanitor did not return promptly")
	}
}

// TestEnsureTenantScoringConfigAdapter_WiresAdapterBeforeBuildAgents
// pins the initialisation-ordering invariant that motivated the
// extraction of ensureTenantScoringConfigAdapter out of
// buildConfigStore: NewEvaluator + NewBatchOrchestrator capture
// app.tenantScoringConfig at construction time, but buildAgents
// (the only previous caller of buildConfigStore) ran AFTER the
// evaluator block in newApplication. Without the split, the
// evaluator captured nil and the entire per-tenant scoring config
// feature collapsed back onto static defaults.
//
// This test calls ensureTenantScoringConfigAdapter directly with a
// minimal application that has a ScoreEngines repo wired, and
// asserts the adapter is non-nil afterwards. A second call must
// be a no-op (preserve the same pointer) so concurrent or
// alternate-path callers don't overwrite the shared instance.
func TestEnsureTenantScoringConfigAdapter_WiresAdapterBeforeBuildAgents(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	app := &application{
		repos: &repository.Registry{ScoreEngines: repo},
	}

	if app.tenantScoringConfig != nil {
		t.Fatalf("setup: app.tenantScoringConfig already populated")
	}

	ensureTenantScoringConfigAdapter(app)
	if app.tenantScoringConfig == nil {
		t.Fatal("ensureTenantScoringConfigAdapter did not populate app.tenantScoringConfig — the evaluator would capture nil and the per-tenant scoring config feature would be silently disabled")
	}
	first := app.tenantScoringConfig

	// Idempotency: a second call must NOT swap the adapter, since
	// buildConfigStore (called later by buildAgents) reuses the
	// same instance for tuning-write invalidation. Replacing it
	// would break the cache-coherence contract between evaluator
	// reads and tuning agent writes.
	ensureTenantScoringConfigAdapter(app)
	if app.tenantScoringConfig != first {
		t.Fatal("ensureTenantScoringConfigAdapter is not idempotent — a second call replaced the existing adapter, which would break the evaluator-side cache <-> tuning-write invalidation contract")
	}

	// Verify the adapter actually reads from the wired repo by
	// seeding a row and loading through the cache. If the
	// adapter were nil or wired to a different repo, the loader
	// would return zero values and the test would fail.
	repo.rows["tenant-wire"] = repository.ScoreEngine{
		TenantID:                "tenant-wire",
		WeightAI:                70,
		WeightRspamd:            30,
		ThresholdTier1PassBelow: 25,
		ThresholdTier1FlagAbove: 75,
	}
	tc, err := app.tenantScoringConfig.LoadTenantScoringConfig(context.Background(), "tenant-wire")
	if err != nil {
		t.Fatalf("LoadTenantScoringConfig: %v", err)
	}
	if tc.Weights.AI != 0.70 || tc.Weights.Rspamd != 0.30 {
		t.Fatalf("adapter not wired to repo: weights = %+v (want AI=0.70 Rspamd=0.30)", tc.Weights)
	}
	if tc.Tier1PassThreshold == nil || *tc.Tier1PassThreshold != 25 {
		t.Fatalf("adapter not wired to repo: Tier1PassThreshold = %v (want 25)", tc.Tier1PassThreshold)
	}
}

// TestEnsureTenantScoringConfigAdapter_NoRepoIsNoOp pins the
// memory-fallback path: when ScoreEngines is nil (the operator has
// not set PG_HOST), ensureTenantScoringConfigAdapter must leave
// app.tenantScoringConfig nil so the evaluator falls through to
// static defaults instead of attempting to read from a nil repo.
func TestEnsureTenantScoringConfigAdapter_NoRepoIsNoOp(t *testing.T) {
	cases := []struct {
		name string
		app  *application
	}{
		{"nil app", nil},
		{"nil repos", &application{}},
		{"nil ScoreEngines", &application{repos: &repository.Registry{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ensureTenantScoringConfigAdapter(tc.app)
			if tc.app != nil && tc.app.tenantScoringConfig != nil {
				t.Fatalf("expected tenantScoringConfig to remain nil when ScoreEngines is unwired; got %v", tc.app.tenantScoringConfig)
			}
		})
	}
}
