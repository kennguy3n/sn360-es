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

type fakeCommunicationStore struct {
	rowsByTenant map[string][]repository.CommunicationHistory
	err          error
	calls        []string
	mu           sync.Mutex
}

func (f *fakeCommunicationStore) ListByTenant(_ context.Context, tenantID string, _ time.Time, _ int) ([]repository.CommunicationHistory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, tenantID)
	if f.err != nil {
		return nil, f.err
	}
	return append([]repository.CommunicationHistory(nil), f.rowsByTenant[tenantID]...), nil
}

type fakeCommUpserter struct {
	mu      sync.Mutex
	upserts []repository.CommunicationHistory
	err     error
}

func (f *fakeCommUpserter) Upsert(_ context.Context, h *repository.CommunicationHistory) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.upserts = append(f.upserts, *h)
	return nil
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
	tl := &fakeTenantLister{tenants: []repository.Tenant{{ID: "t-1"}, {ID: "t-2"}}}
	cs := &fakeCommunicationStore{
		rowsByTenant: map[string][]repository.CommunicationHistory{
			"t-1": {
				{TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"), Count30d: 3, LastSeenAt: now},
				{TenantID: "t-1", SenderHash: []byte("c"), RecipientHash: []byte("d"), Count30d: 1, LastSeenAt: now},
			},
			"t-2": {
				{TenantID: "t-2", SenderHash: []byte("e"), RecipientHash: []byte("f"), Count30d: 5, LastSeenAt: now},
			},
		},
	}
	up := &fakeCommUpserter{}
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
		t.Errorf("expected 3 upserts, got %d", len(up.upserts))
	}
	for _, u := range up.upserts {
		if u.UpdatedAt.IsZero() {
			t.Error("UpdatedAt should be refreshed")
		}
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
		{SenderDomainHash: []byte("d1"), RecipientHash: []byte("r1"), Count30d: 4, FirstSeenAt: now, LastSeenAt: now.Add(time.Hour)},
		{SenderDomainHash: []byte("d1"), RecipientHash: []byte("r2"), Count30d: 1, FirstSeenAt: now.Add(-time.Hour), LastSeenAt: now},
		{SenderDomainHash: []byte("d2"), RecipientHash: []byte("r3"), Count30d: 2, FirstSeenAt: now, LastSeenAt: now},
		{SenderDomainHash: nil, RecipientHash: []byte("r4"), Count30d: 99, FirstSeenAt: now, LastSeenAt: now},
	}
	obs := buildSenderObservations(rows)
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations (empty domain filtered), got %d", len(obs))
	}
	var d1 relationship.SenderObservation
	for _, o := range obs {
		if o.Domain == "d1" {
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
