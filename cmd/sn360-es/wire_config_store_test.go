package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// fakeScoreEngineRepo is a deterministic in-process implementation of
// repository.ScoreEngineRepository used to drive postgresConfigStore
// in isolation from a real Postgres pool.
type fakeScoreEngineRepo struct {
	mu      sync.Mutex
	rows    map[string]repository.ScoreEngine
	getErr  error
	upErr   error
	getHits int
	upHits  int
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

// TestPostgresConfigStore_UpdateWeights_SeedsThenUpserts asserts that
// the very first UpdateWeights call against a tenant whose row does
// not exist yet creates a fresh row populated with the schema
// defaults, overlays the supplied float weights as integer
// percentages, and upserts it back. The contract matters because the
// onboarding agent invokes UpdateWeights on first-onboard *before*
// any other writer has ever touched the score_engine row.
func TestPostgresConfigStore_UpdateWeights_SeedsThenUpserts(t *testing.T) {
	repo := newFakeScoreEngineRepo()
	store := newPostgresConfigStore(repo)

	err := store.UpdateWeights(context.Background(), "tenant-a", agent.ScoreWeights{
		AI:          0.5,
		Rspamd:      0.3,
		Attachments: 0.15,
		Links:       0.05,
	})
	if err != nil {
		t.Fatalf("UpdateWeights: %v", err)
	}

	if repo.upHits != 1 {
		t.Fatalf("expected exactly 1 Upsert, got %d", repo.upHits)
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
	store := newPostgresConfigStore(repo)

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
	store := newPostgresConfigStore(repo)

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
