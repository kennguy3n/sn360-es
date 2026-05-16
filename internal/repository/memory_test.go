package repository

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryTenants(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	tn := &Tenant{Name: "acme", DisplayName: "Acme Corp", Provider: "gws", PrimaryDomain: "acme.test", Region: "ap-southeast-1", KMSKeyARN: "arn", Status: "active"}
	if err := r.Tenants.Create(ctx, tn); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tn.ID == "" {
		t.Fatal("expected ID populated")
	}
	got, err := r.Tenants.GetByName(ctx, "acme")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.ID != tn.ID {
		t.Fatalf("ID mismatch: %v vs %v", got.ID, tn.ID)
	}
	if err := r.Tenants.UpdateStatus(ctx, tn.ID, "suspended"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, _ = r.Tenants.GetByID(ctx, tn.ID)
	if got.Status != "suspended" {
		t.Fatalf("status: %s", got.Status)
	}
	if err := r.Tenants.Create(ctx, &Tenant{Name: "acme"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestMemoryUsers(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	u := &User{TenantID: "tx", EmailHash: []byte{1, 2, 3}, Role: "user"}
	if err := r.Users.Upsert(ctx, u); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := r.Users.GetByHash(ctx, "tx", []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("ID mismatch")
	}
	if _, err := r.Users.GetByHash(ctx, "tx", []byte{9}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	list, _ := r.Users.List(ctx, "tx", 10)
	if len(list) != 1 {
		t.Fatalf("list len: %d", len(list))
	}
}

func TestMemoryScoreEngine(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	s := &ScoreEngine{
		TenantID: "tx", ScoreBase: 100, WeightAI: 80, WeightRspamd: 20,
		ThresholdBlocked: 85, ThresholdHigh: 70, ThresholdWarning: 50, ThresholdCaution: 30, ThresholdInfo: 15,
	}
	if err := r.ScoreEngines.Upsert(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err := r.ScoreEngines.Get(ctx, "tx")
	if err != nil {
		t.Fatal(err)
	}
	if got.ThresholdBlocked != 85 {
		t.Fatalf("threshold: %d", got.ThresholdBlocked)
	}
}

func TestMemoryEvaluationResults(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	er := &EvaluationResult{TenantID: "tx", MessageIDHash: []byte("h"), Score: 75, Tier: "HighRisk", Primary: "LIKELY_PHISHING"}
	if err := r.EvaluationResults.Create(ctx, er); err != nil {
		t.Fatal(err)
	}
	got, err := r.EvaluationResults.GetByMessageHash(ctx, "tx", []byte("h"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Tier != "HighRisk" {
		t.Fatalf("tier: %s", got.Tier)
	}
	if err := r.EvaluationResults.Create(ctx, er); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for duplicate, got %v", err)
	}
	recent, _ := r.EvaluationResults.ListRecent(ctx, "tx", 10)
	if len(recent) != 1 {
		t.Fatalf("recent: %d", len(recent))
	}
}

func TestMemoryVendors(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	v := &Vendor{TenantID: "tx", Domain: "stripe.com", Approved: true, Confidence: 0.9}
	if err := r.Vendors.Upsert(ctx, v); err != nil {
		t.Fatal(err)
	}
	got, err := r.Vendors.GetByDomain(ctx, "tx", "stripe.com")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Approved {
		t.Fatal("expected approved")
	}
	approved, _ := r.Vendors.ListApproved(ctx, "tx")
	if len(approved) != 1 {
		t.Fatalf("approved list: %d", len(approved))
	}
}

func TestMemoryCommHistory(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	h := &CommunicationHistory{TenantID: "tx", SenderHash: []byte("s"), RecipientHash: []byte("r"), SenderDomainHash: []byte("sd"), Count7d: 3, Relationship: "partner"}
	if err := r.CommunicationHistories.Upsert(ctx, h); err != nil {
		t.Fatal(err)
	}
	got, err := r.CommunicationHistories.Get(ctx, "tx", []byte("s"), []byte("r"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Relationship != "partner" {
		t.Fatalf("rel: %s", got.Relationship)
	}
}

func TestMemoryClassifications(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	e := &EmailClassification{Domain: "tempmail.io", Classification: "DISPOSABLE", Source: "manual"}
	if err := r.EmailClassifications.Upsert(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, _ := r.EmailClassifications.GetByDomain(ctx, "tempmail.io")
	if len(got) != 1 {
		t.Fatalf("got: %d", len(got))
	}
	if got[0].Classification != "DISPOSABLE" {
		t.Fatalf("classification: %s", got[0].Classification)
	}
}

func TestMemoryLabels(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	l := &Label{TenantID: "tx", Provider: "gws", Tier: "Warning", Category: "LIKELY_PHISHING", Name: "SN360/Warning"}
	if err := r.Labels.Upsert(ctx, l); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Labels.ListByTenant(ctx, "tx", "gws")
	if len(got) != 1 {
		t.Fatalf("got: %d", len(got))
	}
}

func TestMemoryGroups(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	g := &Group{TenantID: "tx", Name: "Finance", RiskClass: "finance"}
	if err := r.Groups.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := r.Groups.Create(ctx, &Group{TenantID: "tx", Name: "Finance"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	gs, _ := r.Groups.List(ctx, "tx")
	if len(gs) != 1 {
		t.Fatalf("groups: %d", len(gs))
	}
}
