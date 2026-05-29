package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/relationship"
)

// --- fakes ----------------------------------------------------------------

type fakeTenantLister struct {
	tenants []repository.Tenant
	err     error
}

func (f *fakeTenantLister) List(_ context.Context, _ int) ([]repository.Tenant, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tenants, nil
}

// IterateActive yields the fake's tenants in a single batch. Tests
// that need batch-boundary behaviour can override this with a fake
// that overrides IterateActive directly.
func (f *fakeTenantLister) IterateActive(_ context.Context, _ int, yield func([]repository.Tenant) error) error {
	if f.err != nil {
		return f.err
	}
	if len(f.tenants) == 0 {
		return nil
	}
	return yield(f.tenants)
}

type fakeCommunicationStore struct {
	rowsByTenant map[string][]repository.CommunicationHistory
	err          error
	// errByTenant, when set, overrides err on a per-tenant basis.
	// A tenant whose ID is a key here returns the mapped error from
	// ListByTenant; tenants not in the map fall through to the
	// rowsByTenant data path. Used by tests that need to exercise
	// "tenant A succeeds, tenant B fails" partial-outage paths.
	errByTenant map[string]error
	calls       []string
	mu          sync.Mutex
}

func (f *fakeCommunicationStore) ListByTenant(_ context.Context, tenantID string, _ time.Time, _ int) ([]repository.CommunicationHistory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, tenantID)
	if e, ok := f.errByTenant[tenantID]; ok {
		return nil, e
	}
	if f.err != nil {
		return nil, f.err
	}
	return append([]repository.CommunicationHistory(nil), f.rowsByTenant[tenantID]...), nil
}

// fakeCommUpserter captures the CAS writes issued by
// RelationshipJob.Run. The `accept` field controls whether the
// fake returns (true, nil) — simulating a CAS that landed — or
// (false, nil) — simulating ingestion winning the race between
// ListByTenant and the worker's UpdateCountsIfFresh call.
type fakeCommUpserter struct {
	mu      sync.Mutex
	upserts []repository.CommunicationHistory
	readAts []time.Time
	err     error
	accept  bool
}

func (f *fakeCommUpserter) UpdateCountsIfFresh(_ context.Context, h *repository.CommunicationHistory, readAt time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	f.upserts = append(f.upserts, *h)
	f.readAts = append(f.readAts, readAt)
	return f.accept, nil
}

type fakeVendorRepo struct {
	mu       sync.Mutex
	upserts  []repository.Vendor
	upsetErr error
}

func (f *fakeVendorRepo) GetByDomain(_ context.Context, _, _ string) (*repository.Vendor, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeVendorRepo) ListApproved(_ context.Context, _ string) ([]repository.Vendor, error) {
	return nil, nil
}
func (f *fakeVendorRepo) List(_ context.Context, _ string, _ int) ([]repository.Vendor, error) {
	return nil, nil
}
func (f *fakeVendorRepo) Delete(_ context.Context, _, _ string) error {
	return nil
}
func (f *fakeVendorRepo) Upsert(_ context.Context, v *repository.Vendor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upsetErr != nil {
		return f.upsetErr
	}
	f.upserts = append(f.upserts, *v)
	return nil
}

// --- tests ----------------------------------------------------------------

func TestNewRelationshipJob_Validates(t *testing.T) {
	if _, err := NewRelationshipJob(RelationshipJobConfig{}); err == nil {
		t.Fatal("interval required")
	}
	if _, err := NewRelationshipJob(RelationshipJobConfig{Interval: time.Hour}); err == nil {
		t.Fatal("tenants required")
	}
	if _, err := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: &fakeTenantLister{},
	}); err == nil {
		t.Fatal("communications required")
	}
	if _, err := NewRelationshipJob(RelationshipJobConfig{
		Interval:       time.Hour,
		Tenants:        &fakeTenantLister{},
		Communications: &fakeCommunicationStore{},
	}); err == nil {
		t.Fatal("upserter required")
	}
}

func TestRelationshipJob_Run_UpsertsEveryRow(t *testing.T) {
	now := time.Now().UTC()
	readAt := now.Add(-time.Minute)
	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}, {ID: "t-2"}}}
	cs := &fakeCommunicationStore{
		rowsByTenant: map[string][]repository.CommunicationHistory{
			"t-1": {
				{ID: "row-1", TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"), Count30d: 3, LastSeenAt: now, UpdatedAt: readAt},
				{ID: "row-2", TenantID: "t-1", SenderHash: []byte("c"), RecipientHash: []byte("d"), Count30d: 1, LastSeenAt: now, UpdatedAt: readAt},
			},
			"t-2": {
				{ID: "row-3", TenantID: "t-2", SenderHash: []byte("e"), RecipientHash: []byte("f"), Count30d: 5, LastSeenAt: now, UpdatedAt: readAt},
			},
		},
	}
	up := &fakeCommUpserter{accept: true}
	job, err := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(up.upserts) != 3 {
		t.Errorf("expected 3 CAS writes, got %d", len(up.upserts))
	}
	for i, r := range up.readAts {
		if !r.Equal(readAt) {
			t.Errorf("upsert %d readAt = %v, want %v (the snapshot UpdatedAt)", i, r, readAt)
		}
	}
}

// TestRelationshipJob_Run_CASRejection_TreatedAsSuccess verifies the
// optimistic-concurrency contract: when UpdateCountsIfFresh returns
// (false, nil) — the row was modified between ListByTenant and the
// worker's write — the worker treats the row as quietly skipped
// instead of erroring out. The ingestion-time write is canonical,
// so re-running decay against ingestion's fresher counts would
// just resurrect the same race on the next cycle.
func TestRelationshipJob_Run_CASRejection_TreatedAsSuccess(t *testing.T) {
	now := time.Now().UTC()
	readAt := now.Add(-time.Minute)
	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}}}
	cs := &fakeCommunicationStore{
		rowsByTenant: map[string][]repository.CommunicationHistory{
			"t-1": {
				{ID: "row-1", TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"), Count30d: 3, LastSeenAt: now, UpdatedAt: readAt},
			},
		},
	}
	up := &fakeCommUpserter{accept: false} // simulate ingestion winning the race
	job, _ := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
		Logger: discardLogger(),
	})
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("CAS rejection should not be returned as an error: %v", err)
	}
	if len(up.upserts) != 1 {
		t.Errorf("expected the CAS write attempt to still be issued, got %d", len(up.upserts))
	}
}

// TestRelationshipJob_Run_ZeroUpdatedAt_Skipped verifies the
// invariant-violation guard: rows loaded from the store with a
// zero UpdatedAt would cause the Postgres CAS to either match
// arbitrary zero-updated_at rows or surface a validation error, so
// the worker proactively skips them and logs the corruption.
func TestRelationshipJob_Run_ZeroUpdatedAt_Skipped(t *testing.T) {
	now := time.Now().UTC()
	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}}}
	cs := &fakeCommunicationStore{
		rowsByTenant: map[string][]repository.CommunicationHistory{
			"t-1": {
				// UpdatedAt deliberately zero — should be skipped.
				{ID: "row-zero", TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"), Count30d: 3, LastSeenAt: now},
			},
		},
	}
	up := &fakeCommUpserter{accept: true}
	job, _ := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
		Logger: discardLogger(),
	})
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(up.upserts) != 0 {
		t.Errorf("expected zero-UpdatedAt row to be skipped without a CAS attempt, got %d", len(up.upserts))
	}
}

func TestRelationshipJob_TenantListError_PropagatesAndStops(t *testing.T) {
	job, _ := NewRelationshipJob(RelationshipJobConfig{
		Interval:       time.Hour,
		Tenants:        &fakeTenantLister{err: errors.New("db down")},
		Communications: &fakeCommunicationStore{},
		Upserter:       &fakeCommUpserter{},
		Logger:         discardLogger(),
	})
	if err := job.Run(context.Background()); err == nil {
		t.Fatal("expected db error")
	}
}

func TestRelationshipJob_ListByTenantError_ContinuesOtherTenants(t *testing.T) {
	cs := &fakeCommunicationStore{err: errors.New("transient")}
	job, _ := NewRelationshipJob(RelationshipJobConfig{
		Interval:       time.Hour,
		Tenants:        &fakeTenantLister{tenants: []repository.Tenant{{ID: "a"}, {ID: "b"}}},
		Communications: cs, Upserter: &fakeCommUpserter{}, Logger: discardLogger(),
	})
	err := job.Run(context.Background())
	if err == nil {
		t.Error("expected first error to propagate")
	}
	if len(cs.calls) != 2 {
		t.Errorf("both tenants should be processed: %v", cs.calls)
	}
}

func TestVendorJob_Validates(t *testing.T) {
	if _, err := NewVendorJob(VendorJobConfig{}); err == nil {
		t.Fatal("interval required")
	}
	if _, err := NewVendorJob(VendorJobConfig{Interval: time.Hour}); err == nil {
		t.Fatal("tenants required")
	}
	if _, err := NewVendorJob(VendorJobConfig{
		Interval: time.Hour, Tenants: &fakeTenantLister{},
	}); err == nil {
		t.Fatal("communications required")
	}
	if _, err := NewVendorJob(VendorJobConfig{
		Interval:       time.Hour,
		Tenants:        &fakeTenantLister{},
		Communications: &fakeCommunicationStore{},
	}); err == nil {
		t.Fatal("discovery required")
	}
}

func TestVendorJob_Run_PersistsProposals(t *testing.T) {
	now := time.Now().UTC()
	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}}}
	cs := &fakeCommunicationStore{
		rowsByTenant: map[string][]repository.CommunicationHistory{
			"t-1": makeCommRows("vendor.example", 200, 80, now),
		},
	}
	disc := relationship.NewVendorDiscovery(relationship.DefaultVendorDiscoveryConfig(), nil)
	repo := &fakeVendorRepo{}
	job, err := NewVendorJob(VendorJobConfig{
		Interval:         time.Hour,
		Tenants:          tl,
		Communications:   cs,
		Discovery:        disc,
		VendorRepository: repo,
		Logger:           discardLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	// Vendor heuristic should propose at least one candidate from a
	// 200-message, 80-distinct-recipient sender domain.
	if len(repo.upserts) == 0 {
		t.Error("expected at least one vendor proposal to be persisted")
	}
}

func TestBuildSenderObservations_Aggregates(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	rows := []repository.CommunicationHistory{
		{SenderDomain: "d1.example", RecipientHash: []byte("r1"), Count30d: 4, FirstSeenAt: now, LastSeenAt: now.Add(time.Hour)},
		{SenderDomain: "d1.example", RecipientHash: []byte("r2"), Count30d: 1, FirstSeenAt: now.Add(-time.Hour), LastSeenAt: now},
		{SenderDomain: "d2.example", RecipientHash: []byte("r3"), Count30d: 2, FirstSeenAt: now, LastSeenAt: now},
		// Rows missing the plaintext SenderDomain must be skipped:
		// the legacy SenderDomainHash is binary and cannot be
		// turned into a meaningful domain identifier.
		{SenderDomainHash: []byte("\x01\x02\xff"), RecipientHash: []byte("r4"), Count30d: 99, FirstSeenAt: now, LastSeenAt: now},
	}
	obs := buildSenderObservations(rows)
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations (empty domain filtered), got %d", len(obs))
	}
	var d1 relationship.SenderObservation
	for _, o := range obs {
		if o.Domain == "d1.example" {
			d1 = o
		}
	}
	if d1.InboundCount != 5 {
		t.Errorf("d1 inbound: %d", d1.InboundCount)
	}
	if d1.DistinctRecipients != 2 {
		t.Errorf("d1 recipients: %d", d1.DistinctRecipients)
	}
	if !d1.FirstSeen.Equal(now.Add(-time.Hour)) {
		t.Errorf("d1 first_seen: %s", d1.FirstSeen)
	}
	if !d1.LastSeen.Equal(now.Add(time.Hour)) {
		t.Errorf("d1 last_seen: %s", d1.LastSeen)
	}
}

// fakeBaselineRepo is a deterministic in-process implementation of
// repository.UserBehavioralBaselineRepository used to exercise the
// accumulation behaviour of RelationshipJob without spinning up a
// real Postgres pool. It keyed on (tenant, user_hash, sender_hash)
// the same way the production pgBehavioralBaselines table is.
type fakeBaselineRepo struct {
	mu       sync.Mutex
	rows     map[string]repository.UserBehavioralBaseline
	getErr   error
	upErr    error
	upCalls  int
	getCalls int
}

func newFakeBaselineRepo() *fakeBaselineRepo {
	return &fakeBaselineRepo{rows: map[string]repository.UserBehavioralBaseline{}}
}

func (f *fakeBaselineRepo) baselineKey(tenantID string, userHash, senderHash []byte) string {
	return tenantID + ":" + string(userHash) + ":" + string(senderHash)
}

func (f *fakeBaselineRepo) Get(_ context.Context, tenantID string, userHash, senderDomainHash []byte) (*repository.UserBehavioralBaseline, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	b, ok := f.rows[f.baselineKey(tenantID, userHash, senderDomainHash)]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := b
	cp.TypicalSendHours = append([]int(nil), b.TypicalSendHours...)
	return &cp, nil
}

func (f *fakeBaselineRepo) Upsert(_ context.Context, b *repository.UserBehavioralBaseline) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upCalls++
	if f.upErr != nil {
		return f.upErr
	}
	stored := *b
	stored.TypicalSendHours = append([]int(nil), b.TypicalSendHours...)
	f.rows[f.baselineKey(b.TenantID, b.UserEmailHash, b.SenderDomainHash)] = stored
	return nil
}

// TestRelationshipJob_Run_AccumulatesBaselineHoursAndComputesModal
// verifies the 1B fix: across multiple cycles the worker appends to
// the existing TypicalSendHours distribution rather than overwriting
// it with a single-element slice, and it mirrors the modal hour of
// the accumulated distribution onto h.TypicalHour so the CAS write
// propagates it to communication_histories.typical_hour.
func TestRelationshipJob_Run_AccumulatesBaselineHoursAndComputesModal(t *testing.T) {
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	// Three "cycles", each observing the same (sender, recipient)
	// pair but at a different send hour. The third cycle's send
	// hour (14) appears twice across the run because the second
	// and third cycles both land at 14:00, so the modal hour
	// after cycle 3 must be 14.
	cycles := []struct {
		hour int
		row  repository.CommunicationHistory
	}{
		{9, repository.CommunicationHistory{ID: "row-1", TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"), SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 8, LastSeenAt: day.Add(9 * time.Hour), UpdatedAt: day}},
		{14, repository.CommunicationHistory{ID: "row-1", TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"), SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 8, LastSeenAt: day.Add(14 * time.Hour), UpdatedAt: day}},
		{14, repository.CommunicationHistory{ID: "row-1", TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"), SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 8, LastSeenAt: day.Add(14 * time.Hour), UpdatedAt: day}},
	}

	baselines := newFakeBaselineRepo()
	up := &fakeCommUpserter{accept: true}
	hasher := func(_, _ string) ([]byte, error) { return []byte("ok"), nil }

	for i, c := range cycles {
		tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}}}
		cs := &fakeCommunicationStore{rowsByTenant: map[string][]repository.CommunicationHistory{"t-1": {c.row}}}
		job, err := NewRelationshipJob(RelationshipJobConfig{
			Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
			Baselines: baselines, Hasher: hasher, Logger: discardLogger(),
		})
		if err != nil {
			t.Fatalf("cycle %d new: %v", i, err)
		}
		if err := job.Run(context.Background()); err != nil {
			t.Fatalf("cycle %d run: %v", i, err)
		}
	}

	// Baseline distribution must now contain three samples in the
	// order they were observed.
	b, err := baselines.Get(context.Background(), "t-1", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline get: %v", err)
	}
	wantHours := []int{9, 14, 14}
	if len(b.TypicalSendHours) != len(wantHours) {
		t.Fatalf("expected %d send hours after 3 cycles, got %v", len(wantHours), b.TypicalSendHours)
	}
	for i, h := range wantHours {
		if b.TypicalSendHours[i] != h {
			t.Errorf("send hour[%d] = %d, want %d", i, b.TypicalSendHours[i], h)
		}
	}

	// h.TypicalHour propagated to the third CAS write must be 14
	// (the modal hour of {9, 14, 14}).
	if len(up.upserts) != 3 {
		t.Fatalf("expected 3 CAS writes, got %d", len(up.upserts))
	}
	if got := up.upserts[2].TypicalHour; got != 14 {
		t.Errorf("CAS upsert[2].TypicalHour = %d, want 14 (modal hour of {9,14,14})", got)
	}
}

// TestRelationshipJob_Run_BaselineCappedAtMaxBaselineSendHours
// verifies the FIFO cap so the typical_send_hours array does not
// grow unbounded across years of cycles.
func TestRelationshipJob_Run_BaselineCappedAtMaxBaselineSendHours(t *testing.T) {
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	baselines := newFakeBaselineRepo()

	// Pre-seed the baseline with maxBaselineSendHours samples so
	// the very next observation triggers a trim.
	seedHours := make([]int, maxBaselineSendHours)
	for i := range seedHours {
		seedHours[i] = i % 24
	}
	_ = baselines.Upsert(context.Background(), &repository.UserBehavioralBaseline{
		TenantID:         "t-1",
		UserEmailHash:    []byte("b"),
		SenderDomainHash: []byte("d"),
		TypicalSendHours: seedHours,
	})

	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}}}
	cs := &fakeCommunicationStore{rowsByTenant: map[string][]repository.CommunicationHistory{
		"t-1": {{ID: "row-1", TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"),
			SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
			LastSeenAt: day.Add(7 * time.Hour), UpdatedAt: day}},
	}}
	up := &fakeCommUpserter{accept: true}
	hasher := func(_, _ string) ([]byte, error) { return []byte("ok"), nil }

	job, _ := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
		Baselines: baselines, Hasher: hasher, Logger: discardLogger(),
	})
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	b, err := baselines.Get(context.Background(), "t-1", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline get: %v", err)
	}
	if len(b.TypicalSendHours) != maxBaselineSendHours {
		t.Errorf("expected %d send hours (capped), got %d", maxBaselineSendHours, len(b.TypicalSendHours))
	}
	// FIFO eviction: the oldest entry (hour 0 at index 0 of the
	// seed) should be gone and the newest entry (hour 7) should
	// be the last element.
	if b.TypicalSendHours[len(b.TypicalSendHours)-1] != 7 {
		t.Errorf("expected newest send hour 7 at tail, got %d", b.TypicalSendHours[len(b.TypicalSendHours)-1])
	}
}

// TestRelationshipJob_Run_CASRejection_DoesNotPolluteBaseline
// verifies the split between prepareBaselineUpdate (pure compute)
// and persistBaselineUpdate (write-after-CAS): when the canonical
// communication-history CAS write loses the race against
// ingestion (UpdateCountsIfFresh returns (false, nil)), the
// baseline append from the stale snapshot must NOT be persisted.
// Otherwise a subsequent cycle would re-read the now-fresher row
// and append another sample, double-counting the same underlying
// message event in the histogram and skewing
// relationship.BaselineAnomalyCheck's timing-anomaly detection.
func TestRelationshipJob_Run_CASRejection_DoesNotPolluteBaseline(t *testing.T) {
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	baselines := newFakeBaselineRepo()
	// Seed an existing baseline so we can verify it stays
	// untouched after the worker's CAS-rejected cycle.
	_ = baselines.Upsert(context.Background(), &repository.UserBehavioralBaseline{
		TenantID:         "t-1",
		UserEmailHash:    []byte("b"),
		SenderDomainHash: []byte("d"),
		TypicalSendHours: []int{9, 14},
	})

	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}}}
	cs := &fakeCommunicationStore{rowsByTenant: map[string][]repository.CommunicationHistory{
		"t-1": {{
			ID: "row-1", TenantID: "t-1", SenderHash: []byte("a"),
			RecipientHash: []byte("b"), SenderDomainHash: []byte("d"),
			SenderDomain: "d.example", Count30d: 8,
			LastSeenAt: day.Add(11 * time.Hour), UpdatedAt: day,
		}},
	}}
	// accept: false simulates ingestion winning the CAS race
	// between ListByTenant and UpdateCountsIfFresh.
	up := &fakeCommUpserter{accept: false}
	hasher := func(_, _ string) ([]byte, error) { return []byte("ok"), nil }

	job, err := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
		Baselines: baselines, Hasher: hasher, Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Baseline must still hold the original seed {9, 14} — the
	// stale snapshot's hour 11 must not have been persisted
	// because the CAS write was rejected.
	b, err := baselines.Get(context.Background(), "t-1", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline get: %v", err)
	}
	want := []int{9, 14}
	if len(b.TypicalSendHours) != len(want) {
		t.Fatalf("baseline hours = %v, want %v (CAS-rejected snapshot must not pollute the histogram)",
			b.TypicalSendHours, want)
	}
	for i, h := range want {
		if b.TypicalSendHours[i] != h {
			t.Errorf("baseline hours[%d] = %d, want %d", i, b.TypicalSendHours[i], h)
		}
	}
}

// TestRelationshipJob_Run_BaselineCacheCollapsesNplus1Lookups
// verifies the per-cycle baselineCache eliminates the N+1 Get
// pattern when many communication_histories rows share the same
// (recipient, sender_domain) baseline key. Without the cache the
// worker would issue len(rows) Baselines.Get calls per cycle;
// with the cache it issues exactly one per unique key. The test
// also confirms the per-row hour samples are still aggregated
// into the persisted baseline so the histogram doesn't lose
// information.
func TestRelationshipJob_Run_BaselineCacheCollapsesNplus1Lookups(t *testing.T) {
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	baselines := newFakeBaselineRepo()

	// Five communication_histories rows: three share recipient
	// "b" + sender_domain "d" (one baseline), two share
	// recipient "b" + sender_domain "e" (second baseline). Total
	// unique baseline keys: 2, so post-cycle the cache should
	// have collapsed the Get count to exactly 2.
	rows := []repository.CommunicationHistory{
		{ID: "r1", TenantID: "t-1", SenderHash: []byte("a1"), RecipientHash: []byte("b"),
			SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
			LastSeenAt: day.Add(9 * time.Hour), UpdatedAt: day},
		{ID: "r2", TenantID: "t-1", SenderHash: []byte("a2"), RecipientHash: []byte("b"),
			SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
			LastSeenAt: day.Add(14 * time.Hour), UpdatedAt: day},
		{ID: "r3", TenantID: "t-1", SenderHash: []byte("a3"), RecipientHash: []byte("b"),
			SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
			LastSeenAt: day.Add(14 * time.Hour), UpdatedAt: day},
		{ID: "r4", TenantID: "t-1", SenderHash: []byte("a4"), RecipientHash: []byte("b"),
			SenderDomainHash: []byte("e"), SenderDomain: "e.example", Count30d: 4,
			LastSeenAt: day.Add(10 * time.Hour), UpdatedAt: day},
		{ID: "r5", TenantID: "t-1", SenderHash: []byte("a5"), RecipientHash: []byte("b"),
			SenderDomainHash: []byte("e"), SenderDomain: "e.example", Count30d: 4,
			LastSeenAt: day.Add(10 * time.Hour), UpdatedAt: day},
	}

	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}}}
	cs := &fakeCommunicationStore{rowsByTenant: map[string][]repository.CommunicationHistory{"t-1": rows}}
	up := &fakeCommUpserter{accept: true}
	hasher := func(_, _ string) ([]byte, error) { return []byte("ok"), nil }

	job, err := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
		Baselines: baselines, Hasher: hasher, Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Cache regression: exactly 2 Get calls for 5 rows. Without
	// caching this would be 5 (one per row).
	if baselines.getCalls != 2 {
		t.Fatalf("Baselines.Get call count = %d, want 2 (one per unique recipient+sender_domain pair); cache is not collapsing N+1 lookups",
			baselines.getCalls)
	}

	// Aggregation regression: even with caching, every row's
	// sendHour must still land in the persisted baseline. The
	// first baseline (recipient b, sender_domain d) accumulates
	// hours [9, 14, 14] from r1/r2/r3.
	bd, err := baselines.Get(context.Background(), "t-1", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline (b,d) get: %v", err)
	}
	wantBD := []int{9, 14, 14}
	if len(bd.TypicalSendHours) != len(wantBD) {
		t.Fatalf("baseline (b,d) hours = %v, want %v (cache must still aggregate every row's sample)",
			bd.TypicalSendHours, wantBD)
	}
	for i, want := range wantBD {
		if bd.TypicalSendHours[i] != want {
			t.Errorf("baseline (b,d) hours[%d] = %d, want %d", i, bd.TypicalSendHours[i], want)
		}
	}

	// The second baseline (recipient b, sender_domain e)
	// accumulates hours [10, 10] from r4/r5.
	be, err := baselines.Get(context.Background(), "t-1", []byte("b"), []byte("e"))
	if err != nil {
		t.Fatalf("baseline (b,e) get: %v", err)
	}
	wantBE := []int{10, 10}
	if len(be.TypicalSendHours) != len(wantBE) {
		t.Fatalf("baseline (b,e) hours = %v, want %v", be.TypicalSendHours, wantBE)
	}
	for i, want := range wantBE {
		if be.TypicalSendHours[i] != want {
			t.Errorf("baseline (b,e) hours[%d] = %d, want %d", i, be.TypicalSendHours[i], want)
		}
	}
}

// TestRelationshipJob_Run_BaselineWatermarkSkipsUnchangedRows
// locks in the lastCycleStartedAt watermark: a row whose
// LastSeenAt has not advanced since the previous Run must not
// contribute another histogram sample, otherwise the default
// Window=30d / Interval=4h pairing would re-sample the same
// underlying message ~180 times and saturate the 168-entry FIFO
// cap with stale duplicates of one pair's timestamp.
func TestRelationshipJob_Run_BaselineWatermarkSkipsUnchangedRows(t *testing.T) {
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	baselines := newFakeBaselineRepo()

	// Single row whose LastSeenAt never moves across two
	// invocations of Run on the SAME job instance.
	rows := []repository.CommunicationHistory{{
		ID: "r1", TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
		LastSeenAt: day.Add(9 * time.Hour), UpdatedAt: day,
	}}
	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}}}
	cs := &fakeCommunicationStore{rowsByTenant: map[string][]repository.CommunicationHistory{"t-1": rows}}
	up := &fakeCommUpserter{accept: true}
	hasher := func(_, _ string) ([]byte, error) { return []byte("ok"), nil }

	job, err := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
		Baselines: baselines, Hasher: hasher, Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// First Run: prevCycleStartedAt is the zero value, so the
	// row's LastSeenAt > zero and the bootstrap sample lands.
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	b, err := baselines.Get(context.Background(), "t-1", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline get after first run: %v", err)
	}
	if len(b.TypicalSendHours) != 1 || b.TypicalSendHours[0] != 9 {
		t.Fatalf("first run baseline = %v, want [9] (bootstrap sample)", b.TypicalSendHours)
	}

	// Second Run on the same job: prevCycleStartedAt is now the
	// first Run's start time, and the row's LastSeenAt has not
	// advanced past it. The watermark must skip the append.
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("second run: %v", err)
	}
	b, err = baselines.Get(context.Background(), "t-1", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline get after second run: %v", err)
	}
	if len(b.TypicalSendHours) != 1 || b.TypicalSendHours[0] != 9 {
		t.Fatalf("second run double-appended unchanged LastSeenAt: %v, want still [9]",
			b.TypicalSendHours)
	}

	// Third Run AFTER mutating the row's LastSeenAt to a fresh
	// timestamp: this simulates ingestion observing a new
	// message for the same pair. The watermark must let the new
	// hour through.
	cs.rowsByTenant["t-1"][0].LastSeenAt = time.Now().UTC().Add(time.Hour) // strictly > job.lastCycleStartedAt set just before this Run
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("third run: %v", err)
	}
	b, err = baselines.Get(context.Background(), "t-1", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline get after third run: %v", err)
	}
	if len(b.TypicalSendHours) != 2 {
		t.Fatalf("third run with advanced LastSeenAt did not append: %v, want 2 samples",
			b.TypicalSendHours)
	}
}

// TestRelationshipJob_Run_PartialFailurePreservesWatermark locks
// in the per-tenant watermark contract: when tenant A's row loop
// completes but tenant B's ListByTenant fails, only A's watermark
// advances. The next cycle must re-evaluate B's rows from the
// previous (still-empty) watermark so no histogram samples are
// dropped just because a peer tenant had a transient outage. The
// global-watermark predecessor of this code would have advanced a
// single field for both tenants, silently dropping every B row
// whose LastSeenAt fell into the failed window on the next cycle.
func TestRelationshipJob_Run_PartialFailurePreservesWatermark(t *testing.T) {
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	baselines := newFakeBaselineRepo()

	// Two tenants, one row each. Tenant A processes cleanly,
	// tenant B's ListByTenant fails on the first cycle.
	rowB := repository.CommunicationHistory{
		ID: "rB", TenantID: "t-B", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
		LastSeenAt: day.Add(9 * time.Hour), UpdatedAt: day,
	}
	rowA := repository.CommunicationHistory{
		ID: "rA", TenantID: "t-A", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
		LastSeenAt: day.Add(11 * time.Hour), UpdatedAt: day,
	}

	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-A"}, {ID: "t-B"}}}
	cs := &fakeCommunicationStore{
		rowsByTenant: map[string][]repository.CommunicationHistory{
			"t-A": {rowA},
			"t-B": {rowB},
		},
		errByTenant: map[string]error{"t-B": errors.New("transient B")},
	}
	up := &fakeCommUpserter{accept: true}
	hasher := func(_, _ string) ([]byte, error) { return []byte("ok"), nil }

	job, err := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
		Baselines: baselines, Hasher: hasher, Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// Cycle 1: A succeeds (1 sample), B's ListByTenant fails (0 samples).
	_ = job.Run(context.Background())
	bA, err := baselines.Get(context.Background(), "t-A", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline A get after cycle 1: %v", err)
	}
	if len(bA.TypicalSendHours) != 1 || bA.TypicalSendHours[0] != 11 {
		t.Fatalf("cycle 1 tenant A baseline = %v, want [11]", bA.TypicalSendHours)
	}
	if _, err := baselines.Get(context.Background(), "t-B", []byte("b"), []byte("d")); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cycle 1 tenant B should have no baseline; got err=%v", err)
	}

	// Cycle 2: clear B's error, both tenants' ListByTenant
	// succeeds. With LastSeenAt unchanged for both rows, A's
	// watermark has advanced past rowA.LastSeenAt so A is gated
	// out (correctly — already sampled). B's watermark stayed at
	// zero because cycle 1 failed for B, so B's row passes the
	// gate and lands its bootstrap sample.
	delete(cs.errByTenant, "t-B")
	_ = job.Run(context.Background())

	bA, err = baselines.Get(context.Background(), "t-A", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline A get after cycle 2: %v", err)
	}
	if len(bA.TypicalSendHours) != 1 || bA.TypicalSendHours[0] != 11 {
		t.Fatalf("cycle 2 tenant A re-sampled unchanged row: %v, want still [11]", bA.TypicalSendHours)
	}
	bB, err := baselines.Get(context.Background(), "t-B", []byte("b"), []byte("d"))
	if err != nil {
		t.Fatalf("baseline B get after cycle 2: %v", err)
	}
	if len(bB.TypicalSendHours) != 1 || bB.TypicalSendHours[0] != 9 {
		t.Fatalf("cycle 2 tenant B baseline = %v, want [9] (B's watermark must not have advanced during cycle 1)",
			bB.TypicalSendHours)
	}
}

// TestRelationshipJob_Run_PrunesDeletedTenantWatermarks locks in
// the active-tenant pruning at the bottom of Run. Without it, the
// lastCycleStartedAt map would accumulate entries for tenants that
// have been deleted/deactivated and no longer appear in
// Tenants.List, growing unbounded in a long-running worker
// processing tenant churn over years.
//
// The test cycles two tenants, removes one from the active tenant
// list between cycles, and asserts the next Run drops the removed
// tenant's entry from the in-process watermark map without touching
// the surviving tenant's entry.
func TestRelationshipJob_Run_PrunesDeletedTenantWatermarks(t *testing.T) {
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	baselines := newFakeBaselineRepo()

	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-A"}, {ID: "t-B"}, {ID: "t-C"}}}
	cs := &fakeCommunicationStore{rowsByTenant: map[string][]repository.CommunicationHistory{
		"t-A": {{ID: "rA", TenantID: "t-A", SenderHash: []byte("a"), RecipientHash: []byte("b"),
			SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
			LastSeenAt: day.Add(9 * time.Hour), UpdatedAt: day}},
		"t-B": {{ID: "rB", TenantID: "t-B", SenderHash: []byte("a"), RecipientHash: []byte("b"),
			SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
			LastSeenAt: day.Add(10 * time.Hour), UpdatedAt: day}},
		"t-C": {{ID: "rC", TenantID: "t-C", SenderHash: []byte("a"), RecipientHash: []byte("b"),
			SenderDomainHash: []byte("d"), SenderDomain: "d.example", Count30d: 4,
			LastSeenAt: day.Add(11 * time.Hour), UpdatedAt: day}},
	}}
	up := &fakeCommUpserter{accept: true}
	hasher := func(_, _ string) ([]byte, error) { return []byte("ok"), nil }

	job, err := NewRelationshipJob(RelationshipJobConfig{
		Interval: time.Hour, Tenants: tl, Communications: cs, Upserter: up,
		Baselines: baselines, Hasher: hasher, Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// Cycle 1: all three tenants process; each gets a watermark
	// entry populated at the end of its row loop.
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	if len(job.lastCycleStartedAt) != 3 {
		t.Fatalf("cycle 1 watermark map size = %d, want 3", len(job.lastCycleStartedAt))
	}
	for _, id := range []string{"t-A", "t-B", "t-C"} {
		if _, ok := job.lastCycleStartedAt[id]; !ok {
			t.Fatalf("cycle 1 watermark missing tenant %s", id)
		}
	}

	// Simulate tenant deletion: t-B and t-C disappear from the
	// canonical Tenants.List output. t-A remains.
	tl.tenants = []repository.Tenant{{ID: "t-A"}}
	delete(cs.rowsByTenant, "t-B")
	delete(cs.rowsByTenant, "t-C")

	// Cycle 2: only t-A processes. The bottom-of-Run pruning must
	// drop t-B and t-C from the watermark map without touching
	// t-A's entry (which advances in the row loop).
	prevA := job.lastCycleStartedAt["t-A"]
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	if len(job.lastCycleStartedAt) != 1 {
		t.Fatalf("cycle 2 watermark map size = %d after pruning, want 1; got keys %v",
			len(job.lastCycleStartedAt), watermarkKeys(job.lastCycleStartedAt))
	}
	if _, ok := job.lastCycleStartedAt["t-A"]; !ok {
		t.Fatal("cycle 2 dropped active tenant t-A from watermark map")
	}
	if got := job.lastCycleStartedAt["t-A"]; !got.After(prevA) {
		t.Fatalf("cycle 2 did not advance t-A's watermark: prev=%s now=%s", prevA, got)
	}

	// Defence-in-depth: when an empty tenants list comes back
	// (control-plane drain, accidental deactivation), all
	// watermarks are pruned.
	tl.tenants = nil
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("cycle 3: %v", err)
	}
	if len(job.lastCycleStartedAt) != 0 {
		t.Fatalf("cycle 3 with empty tenant list left %d zombie watermarks: %v",
			len(job.lastCycleStartedAt), watermarkKeys(job.lastCycleStartedAt))
	}
}

func watermarkKeys(m map[string]time.Time) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestBaselineCacheKey_InjectiveOverVariableWidthInputs locks in
// the length-prefix encoding for the per-cycle baseline cache key.
// The old `recipientHash + "\x00" + senderDomainHash` scheme was
// collision-free only because today's hashes are fixed-width
// BLAKE2 outputs — a future change to a variable-width hash whose
// payload contained a literal NUL byte would have silently
// collided two distinct (recipient, sender_domain) pairs onto the
// same cache entry, polluting the histogram.
//
// The cases below construct two DIFFERENT (recipientHash,
// senderDomainHash) pairs that the old separator-based encoding
// would have mapped to the same string — by leaking a NUL byte
// from the recipient into where the separator should have been —
// and assert the length-prefix encoding keeps them distinct.
func TestBaselineCacheKey_InjectiveOverVariableWidthInputs(t *testing.T) {
	tests := []struct {
		name    string
		aRecip  []byte
		aDomain []byte
		bRecip  []byte
		bDomain []byte
	}{
		{
			name:    "nul_byte_in_recipient_emulating_separator",
			aRecip:  []byte("ab"),
			aDomain: []byte("cd"),
			bRecip:  []byte("ab\x00cd"),
			bDomain: []byte(""),
		},
		{
			name:    "shifted_boundary_emulating_collision",
			aRecip:  []byte("x"),
			aDomain: []byte("yz"),
			bRecip:  []byte("x\x00yz"),
			bDomain: []byte(""),
		},
		{
			name:    "empty_vs_zero_length_payload",
			aRecip:  []byte(""),
			aDomain: []byte("\x00\x00"),
			bRecip:  []byte("\x00\x00"),
			bDomain: []byte(""),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ka := baselineCacheKey(tc.aRecip, tc.aDomain)
			kb := baselineCacheKey(tc.bRecip, tc.bDomain)
			if ka == kb {
				t.Errorf("baselineCacheKey collided: (%q,%q) and (%q,%q) both -> %q; length-prefix scheme failed",
					tc.aRecip, tc.aDomain, tc.bRecip, tc.bDomain, ka)
			}
		})
	}

	// Equality direction: identical inputs must produce identical
	// keys (sanity check on the determinism of the encoding).
	t.Run("deterministic_for_identical_inputs", func(t *testing.T) {
		k1 := baselineCacheKey([]byte("rec"), []byte("dom"))
		k2 := baselineCacheKey([]byte("rec"), []byte("dom"))
		if k1 != k2 {
			t.Errorf("baselineCacheKey not deterministic: %q vs %q", k1, k2)
		}
	})
}

// TestModalHourOf covers the helper used to derive the modal hour
// from an accumulated send-hour distribution.
func TestModalHourOf(t *testing.T) {
	tests := []struct {
		name string
		in   []int
		want int
	}{
		{"empty", nil, -1},
		{"out_of_range_only", []int{-1, 24, 99}, -1},
		{"single_in_range", []int{7}, 7},
		{"clear_modal", []int{9, 14, 14, 14, 9}, 14},
		{"tie_breaks_to_lowest_hour", []int{3, 3, 8, 8}, 3},
		{"mixed_with_invalid", []int{-5, 30, 11, 11, 4}, 11},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := modalHourOf(tc.in); got != tc.want {
				t.Errorf("modalHourOf(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// makeCommRows builds a synthetic batch of CommunicationHistory rows
// emulating a high-volume sender domain with the given inbound count
// and distinct-recipient cardinality.
func makeCommRows(domain string, total, distinct int, now time.Time) []repository.CommunicationHistory {
	rows := make([]repository.CommunicationHistory, 0, distinct)
	perRecipient := total / distinct
	if perRecipient == 0 {
		perRecipient = 1
	}
	for i := 0; i < distinct; i++ {
		rows = append(rows, repository.CommunicationHistory{
			SenderDomain:     domain,
			SenderDomainHash: []byte(domain),
			SenderHash:       []byte(domain),
			RecipientHash:    []byte{byte(i / 256), byte(i % 256)},
			Count30d:         perRecipient,
			FirstSeenAt:      now.Add(-30 * 24 * time.Hour),
			LastSeenAt:       now,
		})
	}
	return rows
}

// TestNewRelationshipJob_ClampsMaxPerTenantAboveRepoCap pins the
// internal-state clamp: when the operator configures MaxPerTenant
// above repository.CommHistoryListByTenantMaxLimit, the constructor
// must (1) emit a startup warning and (2) clamp the stored
// j.maxPerTenant down to the repository cap so any future code
// path that reads the field sees the effective value rather than
// the operator's over-large request. Without this clamp,
// j.maxPerTenant would drift out of sync with what ListByTenant
// actually returns and any later progress reporting / pagination
// decision keyed off j.maxPerTenant would be silently wrong.
func TestNewRelationshipJob_ClampsMaxPerTenantAboveRepoCap(t *testing.T) {
	job, err := NewRelationshipJob(RelationshipJobConfig{
		Interval:       time.Hour,
		Tenants:        &fakeTenantLister{},
		Communications: &fakeCommunicationStore{},
		Upserter:       &fakeCommUpserter{},
		MaxPerTenant:   repository.CommHistoryListByTenantMaxLimit + 5000,
		Logger:         discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewRelationshipJob: %v", err)
	}
	if got, want := job.maxPerTenant, repository.CommHistoryListByTenantMaxLimit; got != want {
		t.Errorf("maxPerTenant = %d, want clamped to %d", got, want)
	}
}

// TestNewRelationshipJob_PreservesMaxPerTenantBelowRepoCap pins the
// complementary positive path: configured values at or below the
// repository cap must be preserved verbatim, including the default
// fallback when MaxPerTenant is unset.
func TestNewRelationshipJob_PreservesMaxPerTenantBelowRepoCap(t *testing.T) {
	for _, configured := range []int{0, 1, 500, 1000, 9999, repository.CommHistoryListByTenantMaxLimit} {
		job, err := NewRelationshipJob(RelationshipJobConfig{
			Interval:       time.Hour,
			Tenants:        &fakeTenantLister{},
			Communications: &fakeCommunicationStore{},
			Upserter:       &fakeCommUpserter{},
			MaxPerTenant:   configured,
			Logger:         discardLogger(),
		})
		if err != nil {
			t.Fatalf("NewRelationshipJob(MaxPerTenant=%d): %v", configured, err)
		}
		want := configured
		if want <= 0 {
			want = 1000
		}
		if job.maxPerTenant != want {
			t.Errorf("MaxPerTenant=%d → stored %d, want %d", configured, job.maxPerTenant, want)
		}
	}
}
