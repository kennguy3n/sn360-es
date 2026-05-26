package repository

import (
	"context"
	"errors"
	"testing"
	"time"
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

// TestMemoryCommHistory_Upsert_DoesNotWriteTypicalHour locks in the
// Upsert contract: the ingestion-time write path MUST NOT propagate
// the caller's h.TypicalHour onto the persisted row, regardless of
// whether the caller passes the Go zero value 0 (midnight UTC), a
// valid in-range hour, or a sentinel. The worker's
// UpdateCountsIfFresh path is the sole writer of typical_hour, so
// ingestion cannot accidentally clobber the worker-computed modal
// hour even when struct literals omit the field. The Postgres
// implementation enforces this by excluding typical_hour from the
// Upsert SQL entirely; this test exercises the memory mirror.
func TestMemoryCommHistory_Upsert_DoesNotWriteTypicalHour(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()

	// First insert: caller passes Go zero (0 == midnight UTC) for
	// TypicalHour. Without the contract, this would persist as 0
	// and the Tier 0 ATO heuristic would treat 03:00 sends as 3h
	// off the "baseline" midnight. With the contract, the column
	// settles at TypicalHourUnset (-1) per migration 0007 default.
	first := &CommunicationHistory{
		TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), Count7d: 3, Relationship: "partner",
		// TypicalHour intentionally left at Go zero (0).
	}
	if err := r.CommunicationHistories.Upsert(ctx, first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	// The caller's struct must not be mutated by Upsert: this is
	// the contract memory shares with Postgres (which only writes
	// SQL, never the Go struct), so tests inspecting the pointer
	// after Upsert observe identical behaviour across backends.
	if first.TypicalHour != 0 {
		t.Fatalf("first upsert mutated caller's TypicalHour: got %d, want 0 (unchanged Go zero)",
			first.TypicalHour)
	}
	got, err := r.CommunicationHistories.Get(ctx, "t-1", []byte("a"), []byte("b"))
	if err != nil {
		t.Fatalf("get after first upsert: %v", err)
	}
	if got.TypicalHour != TypicalHourUnset {
		t.Fatalf("first insert: TypicalHour = %d, want TypicalHourUnset (%d)",
			got.TypicalHour, TypicalHourUnset)
	}

	// Simulate the worker writing a real modal hour by mutating
	// the in-memory row directly (this is what UpdateCountsIfFresh
	// effectively does after a CAS landing).
	if err := r.CommunicationHistories.(*memoryCommHistory).directSetTypicalHourForTest("t-1", []byte("a"), []byte("b"), 14); err != nil {
		t.Fatalf("seed worker-computed modal hour: %v", err)
	}

	// Second Upsert: caller again passes the Go zero. Without the
	// contract, this would silently rewind typical_hour from 14
	// (worker-computed) to 0 (midnight). With the contract, 14 is
	// preserved.
	second := &CommunicationHistory{
		TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), Count7d: 7, Relationship: "partner",
		// TypicalHour intentionally left at Go zero (0).
	}
	if err := r.CommunicationHistories.Upsert(ctx, second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	got, err = r.CommunicationHistories.Get(ctx, "t-1", []byte("a"), []byte("b"))
	if err != nil {
		t.Fatalf("get after second upsert: %v", err)
	}
	if got.TypicalHour != 14 {
		t.Fatalf("second upsert clobbered worker value: TypicalHour = %d, want 14",
			got.TypicalHour)
	}
	if got.Count7d != 7 {
		t.Fatalf("second upsert lost Count7d: got %d, want 7", got.Count7d)
	}

	// Third Upsert: even a valid in-range TypicalHour from the
	// ingestion-time path MUST NOT overwrite the worker's value.
	third := &CommunicationHistory{
		TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), Count7d: 9, Relationship: "partner",
		TypicalHour: 5,
	}
	if err := r.CommunicationHistories.Upsert(ctx, third); err != nil {
		t.Fatalf("third upsert: %v", err)
	}
	got, err = r.CommunicationHistories.Get(ctx, "t-1", []byte("a"), []byte("b"))
	if err != nil {
		t.Fatalf("get after third upsert: %v", err)
	}
	if got.TypicalHour != 14 {
		t.Fatalf("third upsert overwrote worker value with caller-supplied 5: got %d, want 14",
			got.TypicalHour)
	}
}

// TestMemoryCommHistory_Upsert_PreservesIDAndFirstSeen locks in
// the contract that the memory backend behaves identically to the
// Postgres ON CONFLICT clause for the two columns the SQL
// deliberately leaves out of DO UPDATE SET: id and first_seen_at.
// Without this guarantee, an ingestion-time Upsert against an
// existing row would clobber the original row id (breaking
// log-tailing keyed on id) and reset first_seen_at to "now"
// (breaking the Tier 0 FirstTimeExternal heuristic, which depends
// on first_seen_at being monotonic).
func TestMemoryCommHistory_Upsert_PreservesIDAndFirstSeen(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()

	firstSeen := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	first := &CommunicationHistory{
		ID:       "row-original-id",
		TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), Count7d: 3, Relationship: "partner",
		FirstSeenAt: firstSeen,
	}
	if err := r.CommunicationHistories.Upsert(ctx, first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// Conflict path: caller supplies a fresh ID and a later
	// FirstSeenAt. Postgres preserves the original via ON
	// CONFLICT; memory must mirror that.
	laterSeen := firstSeen.Add(72 * time.Hour)
	second := &CommunicationHistory{
		ID:       "row-new-id",
		TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), Count7d: 7, Relationship: "partner",
		FirstSeenAt: laterSeen,
	}
	if err := r.CommunicationHistories.Upsert(ctx, second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	got, err := r.CommunicationHistories.Get(ctx, "t-1", []byte("a"), []byte("b"))
	if err != nil {
		t.Fatalf("get after second upsert: %v", err)
	}
	if got.ID != "row-original-id" {
		t.Fatalf("conflict Upsert overwrote ID: got %q, want %q (Postgres parity)",
			got.ID, "row-original-id")
	}
	if !got.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("conflict Upsert advanced FirstSeenAt: got %s, want %s (rolling-window monotonicity)",
			got.FirstSeenAt, firstSeen)
	}
	if got.Count7d != 7 {
		t.Fatalf("conflict Upsert lost Count7d: got %d, want 7 (must still update mutable columns)",
			got.Count7d)
	}
}

// TestMemoryCommHistory_Upsert_DoesNotMutateCallerTimestamps locks
// in the contract that Upsert must not write back FirstSeenAt or
// UpdatedAt onto the caller's *CommunicationHistory struct. The
// Postgres backend uses SQL (`updated_at = NOW()`, and column
// DEFAULT NOW() for first_seen_at) so the caller's Go struct is
// never touched by those columns; memory must mirror that. The
// concrete failure mode without this contract is: a test (or any
// caller) that constructs an in-memory CommunicationHistory and
// inspects h.UpdatedAt or h.FirstSeenAt after Upsert observes
// behaviour the Postgres backend would never produce, hiding bugs
// in tests that production would surface.
func TestMemoryCommHistory_Upsert_DoesNotMutateCallerTimestamps(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()

	// New-row path: caller passes zero values for both timestamps.
	// Postgres would let column defaults populate the row server-
	// side without touching the Go struct; memory must do the same.
	first := &CommunicationHistory{
		TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), Count7d: 3, Relationship: "partner",
		// FirstSeenAt and UpdatedAt intentionally left at zero.
	}
	if err := r.CommunicationHistories.Upsert(ctx, first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !first.FirstSeenAt.IsZero() {
		t.Fatalf("new-row Upsert mutated caller's FirstSeenAt: got %s, want zero (Postgres parity)",
			first.FirstSeenAt)
	}
	if !first.UpdatedAt.IsZero() {
		t.Fatalf("new-row Upsert mutated caller's UpdatedAt: got %s, want zero (Postgres parity)",
			first.UpdatedAt)
	}
	// But the persisted row MUST carry non-zero timestamps so
	// downstream readers (ListByTenant, BaselineAnomalyCheck) see
	// the same shape as Postgres rows.
	stored, err := r.CommunicationHistories.Get(ctx, "t-1", []byte("a"), []byte("b"))
	if err != nil {
		t.Fatalf("get after new-row Upsert: %v", err)
	}
	if stored.FirstSeenAt.IsZero() {
		t.Fatal("persisted row missing FirstSeenAt: Postgres column DEFAULT NOW() must be mirrored")
	}
	if stored.UpdatedAt.IsZero() {
		t.Fatal("persisted row missing UpdatedAt: Postgres `updated_at = NOW()` SQL must be mirrored")
	}

	// Conflict path: caller passes an explicit FirstSeenAt and a
	// pre-existing UpdatedAt; both must remain untouched on the
	// caller's struct after Upsert. The persisted row preserves
	// the original FirstSeenAt (Postgres ON CONFLICT exclusion)
	// and stamps a fresh UpdatedAt server-side.
	callerFirstSeen := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	callerUpdated := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	second := &CommunicationHistory{
		TenantID: "t-1", SenderHash: []byte("a"), RecipientHash: []byte("b"),
		SenderDomainHash: []byte("d"), Count7d: 7, Relationship: "partner",
		FirstSeenAt: callerFirstSeen,
		UpdatedAt:   callerUpdated,
	}
	if err := r.CommunicationHistories.Upsert(ctx, second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if !second.FirstSeenAt.Equal(callerFirstSeen) {
		t.Fatalf("conflict Upsert mutated caller's FirstSeenAt: got %s, want %s",
			second.FirstSeenAt, callerFirstSeen)
	}
	if !second.UpdatedAt.Equal(callerUpdated) {
		t.Fatalf("conflict Upsert mutated caller's UpdatedAt: got %s, want %s",
			second.UpdatedAt, callerUpdated)
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

func TestMemoryFeedbackEvents(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	now := time.Now().UTC()
	rows := []*FeedbackEvent{
		{TenantID: "tx", PseudoMessageID: "m1", Action: "report_phishing", Tier: "HighRisk", OccurredAt: now.Add(-30 * time.Minute)},
		{TenantID: "tx", PseudoMessageID: "m2", Action: "report_phishing", Tier: "Warning", OccurredAt: now.Add(-15 * time.Minute)},
		{TenantID: "tx", PseudoMessageID: "m3", Action: "mark_safe", Tier: "Warning", OccurredAt: now.Add(-10 * time.Minute)},
		{TenantID: "tx", PseudoMessageID: "m4", Action: "trust_sender", Tier: "Caution", OccurredAt: now.Add(-5 * time.Minute)},
		// Outside the window — must be excluded.
		{TenantID: "tx", PseudoMessageID: "m5", Action: "report_phishing", Tier: "HighRisk", OccurredAt: now.Add(-90 * time.Minute)},
		// Different tenant — must be excluded.
		{TenantID: "ty", PseudoMessageID: "m6", Action: "report_phishing", OccurredAt: now.Add(-2 * time.Minute)},
	}
	for _, row := range rows {
		if err := r.FeedbackEvents.Create(ctx, row); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if row.ID == "" {
			t.Fatal("expected ID populated on Create")
		}
		if row.CreatedAt.IsZero() {
			t.Fatal("expected CreatedAt populated on Create")
		}
	}
	counts, err := r.FeedbackEvents.Counts(ctx, "tx", now.Add(-60*time.Minute), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if counts.ReportedPhishing != 2 {
		t.Fatalf("reported_phishing: got=%d want=2", counts.ReportedPhishing)
	}
	if counts.MarkedSafe != 1 {
		t.Fatalf("marked_safe: got=%d want=1", counts.MarkedSafe)
	}
	if counts.TrustedSender != 1 {
		t.Fatalf("trusted_sender: got=%d want=1", counts.TrustedSender)
	}
}

func TestMemoryFeedbackEvents_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	now := time.Now().UTC()
	if err := r.FeedbackEvents.Create(ctx, &FeedbackEvent{
		TenantID: "tenant-a", PseudoMessageID: "m", Action: "mark_safe", OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.FeedbackEvents.Create(ctx, &FeedbackEvent{
		TenantID: "tenant-b", PseudoMessageID: "m", Action: "report_phishing", OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := r.FeedbackEvents.Counts(ctx, "tenant-a", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.MarkedSafe != 1 || got.ReportedPhishing != 0 {
		t.Fatalf("tenant-a counts: %+v", got)
	}
	got, err = r.FeedbackEvents.Counts(ctx, "tenant-b", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.ReportedPhishing != 1 || got.MarkedSafe != 0 {
		t.Fatalf("tenant-b counts: %+v", got)
	}
}
