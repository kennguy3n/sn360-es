package education

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// stubInteractionStore mirrors the InteractionStore contract that
// MemoryInteractionStore and PostgresInteractionStore both honour:
// Append is idempotent per (CampaignID, UserHash, Action) so the
// tracker tests exercise the same semantics that production code sees.
type stubInteractionStore struct {
	mu     sync.Mutex
	items  []dto.UserInteraction
	seen   map[string]struct{}
	apErr  error
	lstErr error
}

func (s *stubInteractionStore) Append(_ context.Context, i dto.UserInteraction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.apErr != nil {
		return s.apErr
	}
	if s.seen == nil {
		s.seen = map[string]struct{}{}
	}
	key := i.CampaignID + "\x00" + i.UserHash + "\x00" + string(i.Action)
	if _, dup := s.seen[key]; dup {
		return nil
	}
	s.seen[key] = struct{}{}
	s.items = append(s.items, i)
	return nil
}

func (s *stubInteractionStore) ListByCampaign(_ context.Context, campaignID string) ([]dto.UserInteraction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lstErr != nil {
		return nil, s.lstErr
	}
	out := make([]dto.UserInteraction, 0, len(s.items))
	for _, i := range s.items {
		if i.CampaignID == campaignID {
			out = append(out, i)
		}
	}
	return out, nil
}

// stubEventService captures Publish calls but otherwise behaves like a no-op.
type stubEventService struct {
	mu       sync.Mutex
	subjects []string
	bodies   [][]byte
	err      error
}

func (s *stubEventService) Publish(_ context.Context, subject string, data []byte, _ ...events.PublishOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.subjects = append(s.subjects, subject)
	s.bodies = append(s.bodies, append([]byte(nil), data...))
	return nil
}

func (s *stubEventService) Subscribe(_ context.Context, _ string, _ events.MessageHandler, _ ...events.SubscribeOption) (events.Subscription, error) {
	return nil, errors.New("not implemented")
}

func (s *stubEventService) Health(_ context.Context) error { return nil }

func (s *stubEventService) Close() error { return nil }

func TestNewSimulationTracker_RequiresStore(t *testing.T) {
	if _, err := NewSimulationTracker(TrackerConfig{}); err == nil {
		t.Fatal("expected error when Store is nil")
	}
}

func TestNewSimulationTracker_AppliesClockDefault(t *testing.T) {
	tr, err := NewSimulationTracker(TrackerConfig{Store: &stubInteractionStore{}})
	if err != nil {
		t.Fatalf("NewSimulationTracker: %v", err)
	}
	if tr.now == nil {
		t.Fatal("clock default not applied")
	}
}

func TestRecordInteraction_RejectsInvalidInputs(t *testing.T) {
	tr, _ := NewSimulationTracker(TrackerConfig{Store: &stubInteractionStore{}})
	cases := []struct {
		name           string
		campaign, user string
		action         dto.UserInteractionType
	}{
		{"empty campaign", "", "u", dto.InteractionOpened},
		{"empty user", "c", "", dto.InteractionOpened},
		{"invalid action", "c", "u", "fly"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := tr.RecordInteraction(context.Background(), c.campaign, c.user, c.action); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRecordInteraction_PersistsAndPublishes(t *testing.T) {
	store := &stubInteractionStore{}
	pub := &stubEventService{}
	fixed := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	tr, _ := NewSimulationTracker(TrackerConfig{
		Store:     store,
		Publisher: pub,
		Clock:     func() time.Time { return fixed },
	})
	got, err := tr.RecordInteraction(context.Background(), "camp-1", "uhash", dto.InteractionClickedLink)
	if err != nil {
		t.Fatalf("RecordInteraction: %v", err)
	}
	if !got.OccurredAt.Equal(fixed) {
		t.Fatalf("OccurredAt: %v", got.OccurredAt)
	}
	if len(store.items) != 1 || store.items[0].Action != dto.InteractionClickedLink {
		t.Fatalf("stored: %+v", store.items)
	}
	if len(pub.subjects) != 1 || pub.subjects[0] != "es.education.simulation.result" {
		t.Fatalf("publish subjects: %+v", pub.subjects)
	}
}

func TestRecordInteraction_AppendErrorPropagates(t *testing.T) {
	tr, _ := NewSimulationTracker(TrackerConfig{
		Store: &stubInteractionStore{apErr: errors.New("store down")},
	})
	if _, err := tr.RecordInteraction(context.Background(), "c", "u", dto.InteractionOpened); err == nil {
		t.Fatal("expected append error")
	}
}

func TestRecordInteraction_PublishErrorIsNonFatal(t *testing.T) {
	tr, _ := NewSimulationTracker(TrackerConfig{
		Store:     &stubInteractionStore{},
		Publisher: &stubEventService{err: errors.New("bus down")},
	})
	if _, err := tr.RecordInteraction(context.Background(), "c", "u", dto.InteractionOpened); err != nil {
		t.Fatalf("publish error should be non-fatal: %v", err)
	}
}

func TestAggregate_CountsAllOutcomesWithReplay(t *testing.T) {
	store := &stubInteractionStore{}
	tr, _ := NewSimulationTracker(TrackerConfig{Store: store})
	ctx := context.Background()
	// Recording the same action twice for the same target simulates an
	// at-least-once redelivery of the simulation.result event. The
	// InteractionStore contract guarantees Append is idempotent per
	// (CampaignID, UserHash, Action), so Aggregate must NOT inflate
	// the campaign counters on replay — "did this target click?" is
	// a boolean, not a count.
	actions := []dto.UserInteractionType{
		dto.InteractionDelivered,
		dto.InteractionDelivered, // replay
		dto.InteractionOpened,
		dto.InteractionClickedLink,
		dto.InteractionClickedLink, // replay
		dto.InteractionSubmittedCredentials,
		dto.InteractionReportedPhishing,
		dto.InteractionIgnored,
	}
	for _, a := range actions {
		if _, err := tr.RecordInteraction(ctx, "camp-1", "u", a); err != nil {
			t.Fatalf("RecordInteraction(%q): %v", a, err)
		}
	}
	res, err := tr.Aggregate(ctx, "camp-1")
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	want := dto.SimulationResult{
		CampaignID:           "camp-1",
		Delivered:            1,
		Opened:               1,
		Clicked:              1,
		SubmittedCredentials: 1,
		Reported:             1,
		Ignored:              1,
	}
	if res != want {
		t.Fatalf("got=%+v want=%+v (replay must not double-count)", res, want)
	}
}

func TestAggregate_OnlyCountsRequestedCampaign(t *testing.T) {
	store := &stubInteractionStore{}
	tr, _ := NewSimulationTracker(TrackerConfig{Store: store})
	_, _ = tr.RecordInteraction(context.Background(), "camp-1", "u", dto.InteractionClickedLink)
	_, _ = tr.RecordInteraction(context.Background(), "camp-2", "u", dto.InteractionReportedPhishing)
	res, err := tr.Aggregate(context.Background(), "camp-1")
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if res.Clicked != 1 || res.Reported != 0 {
		t.Fatalf("bleed: %+v", res)
	}
}

func TestAggregate_RequiresCampaign(t *testing.T) {
	tr, _ := NewSimulationTracker(TrackerConfig{Store: &stubInteractionStore{}})
	if _, err := tr.Aggregate(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty campaign")
	}
}

func TestAggregate_StoreErrorPropagates(t *testing.T) {
	tr, _ := NewSimulationTracker(TrackerConfig{Store: &stubInteractionStore{lstErr: errors.New("read fail")}})
	if _, err := tr.Aggregate(context.Background(), "c"); err == nil {
		t.Fatal("expected list error")
	}
}

func TestMemoryInteractionStore_AppendListSeparation(t *testing.T) {
	s := NewMemoryInteractionStore()
	ctx := context.Background()
	_ = s.Append(ctx, dto.UserInteraction{CampaignID: "a", UserHash: "u1", Action: dto.InteractionOpened})
	_ = s.Append(ctx, dto.UserInteraction{CampaignID: "a", UserHash: "u2", Action: dto.InteractionClickedLink})
	_ = s.Append(ctx, dto.UserInteraction{CampaignID: "b", UserHash: "u3", Action: dto.InteractionReportedPhishing})

	a, _ := s.ListByCampaign(ctx, "a")
	b, _ := s.ListByCampaign(ctx, "b")
	if len(a) != 2 {
		t.Fatalf("a: %d", len(a))
	}
	if len(b) != 1 {
		t.Fatalf("b: %d", len(b))
	}

	// Mutating the returned slice must NOT mutate the store (defensive copy).
	a[0].UserHash = "tampered"
	again, _ := s.ListByCampaign(ctx, "a")
	if again[0].UserHash == "tampered" {
		t.Fatalf("store leaked mutable slice: %+v", again)
	}
}

// TestMemoryInteractionStore_IdempotentPerUserAction pins down the
// in-memory store's dedup behaviour: Append for the same
// (campaign, user, action) tuple is a no-op after the first call, and
// the first-observed OccurredAt is preserved on the listed entry.
// This is the same contract PostgresInteractionStore enforces via
// (campaign_id, user_hash) primary key + COALESCE-on-upsert, and is
// required so Aggregate counters are stable under at-least-once
// NATS redelivery of education.simulation.result events.
func TestMemoryInteractionStore_IdempotentPerUserAction(t *testing.T) {
	s := NewMemoryInteractionStore()
	ctx := context.Background()
	first := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	second := time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC)
	_ = s.Append(ctx, dto.UserInteraction{
		CampaignID: "c", UserHash: "u1", Action: dto.InteractionOpened, OccurredAt: first,
	})
	// Replay of the SAME (user, action) tuple — must be a no-op.
	_ = s.Append(ctx, dto.UserInteraction{
		CampaignID: "c", UserHash: "u1", Action: dto.InteractionOpened, OccurredAt: second,
	})
	// Different action for the same user must still be retained.
	_ = s.Append(ctx, dto.UserInteraction{
		CampaignID: "c", UserHash: "u1", Action: dto.InteractionClickedLink, OccurredAt: second,
	})
	// Same action for a DIFFERENT user must still be retained.
	_ = s.Append(ctx, dto.UserInteraction{
		CampaignID: "c", UserHash: "u2", Action: dto.InteractionOpened, OccurredAt: second,
	})
	items, _ := s.ListByCampaign(ctx, "c")
	if len(items) != 3 {
		t.Fatalf("expected 3 deduped entries, got %d: %+v", len(items), items)
	}
	for _, it := range items {
		if it.UserHash == "u1" && it.Action == dto.InteractionOpened && !it.OccurredAt.Equal(first) {
			t.Fatalf("replay overwrote first OccurredAt: got %v want %v", it.OccurredAt, first)
		}
	}
}
