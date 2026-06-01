package investigation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// fixedClock is a tiny deterministic clock so the 30-day window
// arithmetic in SenderTrail aggregation is reproducible across CI
// runs (clock drift is not in scope of these tests).
func fixedClock(now time.Time) func() time.Time {
	return func() time.Time { return now }
}

// seedFixture stamps a deterministic-enough corpus across two
// tenants on the supplied registry so every test below shares the
// same shape: one (sender, recipient) pair under tenant t-1 with
// three verdicts at descending evaluated_at + a CommunicationHistory
// row to support the join; a second tenant (t-2) carrying a
// parallel set so cross-tenant isolation can be asserted.
func seedFixture(ctx context.Context, t *testing.T, r *repository.Registry, now time.Time) {
	t.Helper()
	type seed struct {
		tenant      string
		sender      []byte
		recipient   []byte
		evaluatedAt time.Time
		score       int
		tier        string
		messageID   string
	}
	seeds := []seed{
		{"t-1", []byte("s-A"), []byte("r-1"), now.Add(-1 * time.Hour), 90, "blocked", "msg-1"},
		{"t-1", []byte("s-A"), []byte("r-1"), now.Add(-2 * time.Hour), 55, "medium", "msg-2"},
		{"t-1", []byte("s-A"), []byte("r-2"), now.Add(-3 * time.Hour), 30, "low", "msg-3"},
		// Cross-tenant collision: same sender hash + same message ID,
		// different tenant. The service MUST NOT leak it across.
		{"t-2", []byte("s-A"), []byte("r-1"), now.Add(-1 * time.Hour), 80, "high", "msg-1"},
	}
	for _, s := range seeds {
		er := &repository.EvaluationResult{
			TenantID:      s.tenant,
			MessageIDHash: []byte(s.messageID),
			SenderHash:    s.sender,
			RecipientHash: s.recipient,
			Score:         s.score,
			Tier:          s.tier,
			EvaluatedAt:   s.evaluatedAt,
		}
		if err := r.EvaluationResults.Create(ctx, er); err != nil {
			t.Fatalf("seed eval %v: %v", s, err)
		}
	}
	// Recipient fan-out for tenant t-1 under sender s-A:
	// r-1 last seen 1h ago (in window), r-2 last seen 40d ago
	// (outside the default 30d window so the aggregate skips it).
	histories := []*repository.CommunicationHistory{
		{
			TenantID:      "t-1",
			SenderHash:    []byte("s-A"),
			RecipientHash: []byte("r-1"),
			Count7d:       2,
			Count30d:      12,
			FirstSeenAt:   now.Add(-30 * 24 * time.Hour),
			LastSeenAt:    now.Add(-1 * time.Hour),
		},
		{
			TenantID:      "t-1",
			SenderHash:    []byte("s-A"),
			RecipientHash: []byte("r-2"),
			Count7d:       0,
			Count30d:      4,
			FirstSeenAt:   now.Add(-60 * 24 * time.Hour),
			LastSeenAt:    now.Add(-40 * 24 * time.Hour),
		},
		{
			TenantID:      "t-2",
			SenderHash:    []byte("s-A"),
			RecipientHash: []byte("r-1"),
			Count7d:       9,
			Count30d:      40,
			FirstSeenAt:   now.Add(-10 * 24 * time.Hour),
			LastSeenAt:    now.Add(-30 * time.Minute),
		},
	}
	for _, h := range histories {
		if err := r.CommunicationHistories.Upsert(ctx, h); err != nil {
			t.Fatalf("seed comm history %v: %v", h, err)
		}
	}
}

func newServiceForTest(t *testing.T, now time.Time) (*Service, *repository.Registry) {
	t.Helper()
	r := repository.NewInMemoryRegistry()
	seedFixture(context.Background(), t, r, now)
	svc, err := NewService(ServiceConfig{
		EvaluationResults:      r.EvaluationResults,
		CommunicationHistories: r.CommunicationHistories,
		Clock:                  fixedClock(now),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, r
}

func TestNewService_RequiresRepositories(t *testing.T) {
	cases := []struct {
		name string
		cfg  ServiceConfig
	}{
		{"missing evaluation_results", ServiceConfig{
			CommunicationHistories: repository.NewInMemoryRegistry().CommunicationHistories,
		}},
		{"missing communication_histories", ServiceConfig{
			EvaluationResults: repository.NewInMemoryRegistry().EvaluationResults,
		}},
		{"both missing", ServiceConfig{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewService(tc.cfg); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestMessageTrail_HappyPath(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	svc, _ := newServiceForTest(t, now)
	trail, err := svc.MessageTrail(context.Background(), "t-1", "msg-1")
	if err != nil {
		t.Fatalf("MessageTrail: %v", err)
	}
	if trail.Result.TenantID != "t-1" {
		t.Errorf("tenant mismatch: got %q", trail.Result.TenantID)
	}
	if string(trail.Result.MessageIDHash) != "msg-1" {
		t.Errorf("message id mismatch: got %q", trail.Result.MessageIDHash)
	}
	if trail.Result.Score != 90 {
		t.Errorf("score mismatch: got %d", trail.Result.Score)
	}
	if trail.CommunicationHistory == nil {
		t.Fatalf("expected comm_history join; got nil")
	}
	if trail.CommunicationHistory.TenantID != "t-1" {
		t.Errorf("comm history tenant: got %q", trail.CommunicationHistory.TenantID)
	}
	if string(trail.CommunicationHistory.SenderHash) != "s-A" {
		t.Errorf("comm history sender: got %q", trail.CommunicationHistory.SenderHash)
	}
}

func TestMessageTrail_CrossTenantReturnsNotFound(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	svc, _ := newServiceForTest(t, now)
	// msg-1 exists for t-2 as well; tenant t-3 has nothing.
	// Both must return ErrNotFound — the handler maps this to a
	// 404 indistinguishable from genuine absence.
	if _, err := svc.MessageTrail(context.Background(), "t-3", "msg-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("non-existent tenant: got %v, want ErrNotFound", err)
	}
	// Tenant t-1 has msg-2 but t-2 doesn't — t-2 must NOT see it.
	if _, err := svc.MessageTrail(context.Background(), "t-2", "msg-2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-tenant probe: got %v, want ErrNotFound", err)
	}
}

func TestMessageTrail_Validation(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	svc, _ := newServiceForTest(t, now)
	if _, err := svc.MessageTrail(context.Background(), "", "msg-1"); !errors.Is(err, ErrTenantIDRequired) {
		t.Errorf("empty tenant: got %v, want ErrTenantIDRequired", err)
	}
	if _, err := svc.MessageTrail(context.Background(), "t-1", ""); !errors.Is(err, ErrMessageIDRequired) {
		t.Errorf("empty msg id: got %v, want ErrMessageIDRequired", err)
	}
}

func TestSenderTrail_HappyPath(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	svc, _ := newServiceForTest(t, now)
	trail, err := svc.SenderTrail(context.Background(), "t-1", []byte("s-A"), SenderTrailOptions{})
	if err != nil {
		t.Fatalf("SenderTrail: %v", err)
	}
	if len(trail.Verdicts) != 3 {
		t.Fatalf("verdict count: got %d, want 3", len(trail.Verdicts))
	}
	// Verdicts must be sorted by EvaluatedAt descending.
	for i := 1; i < len(trail.Verdicts); i++ {
		if trail.Verdicts[i].EvaluatedAt.After(trail.Verdicts[i-1].EvaluatedAt) {
			t.Fatalf("verdicts not sorted descending: index %d (%s) > %d (%s)",
				i, trail.Verdicts[i].EvaluatedAt, i-1, trail.Verdicts[i-1].EvaluatedAt)
		}
	}
	if len(trail.CommunicationHistories) != 2 {
		t.Fatalf("recipient count: got %d, want 2", len(trail.CommunicationHistories))
	}
	// Aggregate properties.
	agg := trail.Aggregate
	if agg.TotalVerdicts != 3 {
		t.Errorf("agg total verdicts: got %d, want 3", agg.TotalVerdicts)
	}
	// One verdict is "blocked" -> high-risk. The "medium" / "low"
	// tiers do NOT count.
	if agg.HighRiskVerdicts != 1 {
		t.Errorf("agg high-risk verdicts: got %d, want 1", agg.HighRiskVerdicts)
	}
	if agg.MaxScore != 90 {
		t.Errorf("agg max score: got %d, want 90", agg.MaxScore)
	}
	if !agg.LastVerdictAt.Equal(now.Add(-1 * time.Hour)) {
		t.Errorf("agg last verdict at: got %s, want %s", agg.LastVerdictAt, now.Add(-1*time.Hour))
	}
	// Only r-1 is within the 30d window; r-2 (40d ago) is excluded.
	if agg.DistinctRecipients != 1 {
		t.Errorf("agg distinct recipients: got %d, want 1", agg.DistinctRecipients)
	}
	if agg.TotalSightingsWindow != 12 {
		t.Errorf("agg total sightings: got %d, want 12", agg.TotalSightingsWindow)
	}
}

func TestSenderTrail_TenantIsolation(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	svc, _ := newServiceForTest(t, now)
	trail, err := svc.SenderTrail(context.Background(), "t-2", []byte("s-A"), SenderTrailOptions{})
	if err != nil {
		t.Fatalf("SenderTrail: %v", err)
	}
	// t-2 has exactly one seeded verdict for sender s-A; t-1 has
	// three. If isolation is broken the count would mix.
	if len(trail.Verdicts) != 1 {
		t.Fatalf("t-2 sees %d verdicts; expected 1 (cross-tenant leak)", len(trail.Verdicts))
	}
	if trail.Verdicts[0].TenantID != "t-2" {
		t.Errorf("verdict tenant: got %q, want t-2", trail.Verdicts[0].TenantID)
	}
	if len(trail.CommunicationHistories) != 1 {
		t.Fatalf("t-2 sees %d recipient rows; expected 1", len(trail.CommunicationHistories))
	}
	if trail.CommunicationHistories[0].TenantID != "t-2" {
		t.Errorf("comm history tenant: got %q, want t-2", trail.CommunicationHistories[0].TenantID)
	}
}

func TestSenderTrail_LimitClampedToDefault(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	svc, _ := newServiceForTest(t, now)
	// Limit=2 should return the two most recent verdicts.
	trail, err := svc.SenderTrail(context.Background(), "t-1", []byte("s-A"), SenderTrailOptions{Limit: 2})
	if err != nil {
		t.Fatalf("SenderTrail: %v", err)
	}
	if len(trail.Verdicts) != 2 {
		t.Fatalf("limit=2: got %d verdicts; want 2", len(trail.Verdicts))
	}
	// Aggregate's TotalVerdicts reflects the returned slice, not
	// the underlying row count — by-design (the caller paged).
	if trail.Aggregate.TotalVerdicts != 2 {
		t.Errorf("agg total verdicts: got %d, want 2", trail.Aggregate.TotalVerdicts)
	}
}

func TestSenderTrail_Validation(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	svc, _ := newServiceForTest(t, now)
	if _, err := svc.SenderTrail(context.Background(), "", []byte("s"), SenderTrailOptions{}); !errors.Is(err, ErrTenantIDRequired) {
		t.Errorf("empty tenant: got %v", err)
	}
	if _, err := svc.SenderTrail(context.Background(), "t-1", nil, SenderTrailOptions{}); !errors.Is(err, ErrSenderHashRequired) {
		t.Errorf("nil sender: got %v", err)
	}
	if _, err := svc.SenderTrail(context.Background(), "t-1", []byte{}, SenderTrailOptions{}); !errors.Is(err, ErrSenderHashRequired) {
		t.Errorf("empty sender: got %v", err)
	}
}

func TestAggregate_PureFunctionEmptyInput(t *testing.T) {
	// Direct invocation so the helper is exercised on the empty
	// branch without going through the seeded fixture.
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	agg := aggregate(nil, nil, now, senderTrailDefaultWindow)
	if agg.TotalVerdicts != 0 || agg.HighRiskVerdicts != 0 || agg.MaxScore != 0 {
		t.Errorf("empty input: got %+v, expected zero envelope", agg)
	}
	if !agg.LastVerdictAt.IsZero() {
		t.Errorf("empty input LastVerdictAt: got %s, want zero", agg.LastVerdictAt)
	}
	if agg.DistinctRecipients != 0 || agg.TotalSightingsWindow != 0 {
		t.Errorf("empty input recipients: got %+v", agg)
	}
}
