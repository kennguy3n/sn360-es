package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

type fakeEscPub struct {
	mu       sync.Mutex
	subjects []string
}

func (f *fakeEscPub) Publish(_ context.Context, subject string, _ []byte, _ ...events.PublishOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subjects = append(f.subjects, subject)
	return nil
}

type fakeFeedbackSink struct {
	mu     sync.Mutex
	calls  int
	ticket dto.EscalationTicket
}

func (f *fakeFeedbackSink) RecordOutcome(_ context.Context, t dto.EscalationTicket) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.ticket = t
	return nil
}

func TestEscalation_Escalate_CreatesTicketAndPublishes(t *testing.T) {
	pub := &fakeEscPub{}
	svc, err := NewEscalationService(EscalationServiceConfig{
		Publisher: pub,
		Clock:     func() time.Time { return time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewEscalationService: %v", err)
	}
	ticket, err := svc.Escalate(context.Background(), "acme", dto.EscalationIncident{
		PseudoMessageID:   "pmid-1",
		Tier:              "blocked",
		Category:          "BEC_Suspect",
		Reason:            dto.EscalationReasonConfirmedBreach,
		Score:             95,
		AffectedUserCount: 12,
		AISummary:         "Likely BEC against finance team",
		Indicators:        []string{"lookalike_domain", "urgency_lexicon"},
	})
	if err != nil {
		t.Fatalf("Escalate: %v", err)
	}
	if !strings.HasPrefix(ticket.TicketID, "esc_") {
		t.Fatalf("ticket_id: %q", ticket.TicketID)
	}
	if ticket.Outcome != dto.OutcomePending {
		t.Fatalf("outcome: %q", ticket.Outcome)
	}
	if len(ticket.Timeline) != 1 || ticket.Timeline[0].Step != "created" {
		t.Fatalf("timeline: %+v", ticket.Timeline)
	}
	if len(pub.subjects) != 1 || pub.subjects[0] != "es.action.escalation.created" {
		t.Fatalf("subjects: %+v", pub.subjects)
	}
}

func TestEscalation_RejectsInvalid(t *testing.T) {
	svc, _ := NewEscalationService(EscalationServiceConfig{Publisher: &fakeEscPub{}})
	if _, err := svc.Escalate(context.Background(), "", dto.EscalationIncident{Reason: dto.EscalationReasonUserRequested}); err == nil {
		t.Fatal("expected error for empty tenant")
	}
	if _, err := svc.Escalate(context.Background(), "acme", dto.EscalationIncident{Reason: "garbage"}); err == nil {
		t.Fatal("expected error for invalid reason")
	}
}

func TestEscalation_ResolveRecordsOutcomeAndFeedsML(t *testing.T) {
	pub := &fakeEscPub{}
	sink := &fakeFeedbackSink{}
	svc, _ := NewEscalationService(EscalationServiceConfig{Publisher: pub, Feedback: sink})
	tk, err := svc.Escalate(context.Background(), "acme", dto.EscalationIncident{
		Reason: dto.EscalationReasonUserRequested,
	})
	if err != nil {
		t.Fatalf("Escalate: %v", err)
	}
	resolved, err := svc.ResolveEscalation(context.Background(), "acme", tk.TicketID, "soc-analyst-1",
		dto.OutcomeConfirmedPhishing, "Phishing confirmed; user notified.")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Outcome != dto.OutcomeConfirmedPhishing {
		t.Fatalf("outcome: %q", resolved.Outcome)
	}
	if resolved.ResolverHash != "soc-analyst-1" {
		t.Fatalf("resolver: %q", resolved.ResolverHash)
	}
	if sink.calls != 1 {
		t.Fatalf("feedback sink calls: %d", sink.calls)
	}
	if len(pub.subjects) != 2 || pub.subjects[1] != "es.action.escalation.resolved" {
		t.Fatalf("subjects: %+v", pub.subjects)
	}
}

func TestEscalation_DoubleResolveRejected(t *testing.T) {
	svc, _ := NewEscalationService(EscalationServiceConfig{Publisher: &fakeEscPub{}})
	tk, _ := svc.Escalate(context.Background(), "acme", dto.EscalationIncident{Reason: dto.EscalationReasonUserRequested})
	_, _ = svc.ResolveEscalation(context.Background(), "acme", tk.TicketID, "a", dto.OutcomeFalsePositive, "")
	if _, err := svc.ResolveEscalation(context.Background(), "acme", tk.TicketID, "b", dto.OutcomeConfirmedPhishing, ""); err == nil {
		t.Fatal("expected error for double-resolve")
	}
}

func TestEscalation_ResolveValidatesOutcome(t *testing.T) {
	svc, _ := NewEscalationService(EscalationServiceConfig{Publisher: &fakeEscPub{}})
	tk, _ := svc.Escalate(context.Background(), "acme", dto.EscalationIncident{Reason: dto.EscalationReasonUserRequested})
	if _, err := svc.ResolveEscalation(context.Background(), "acme", tk.TicketID, "a", "garbage", ""); err == nil {
		t.Fatal("expected error for invalid outcome")
	}
}

// TestMemoryTicketStore_RequiresTenantID locks in the defense-in-depth
// contract: every TicketStore method refuses an empty tenantID with
// ErrTicketTenantIDRequired. The service layer already validates
// tenantID before reaching the store, so this guards the case of a
// future caller that goes straight to the store interface — without
// the check, Save would write under a blank-tenant key that any
// caller passing tenantID="" could then read with Load.
func TestMemoryTicketStore_RequiresTenantID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTicketStore()

	if err := store.Save(ctx, dto.EscalationTicket{TicketID: "esc_x"}); !errors.Is(err, ErrTicketTenantIDRequired) {
		t.Fatalf("Save(empty tenant) = %v, want ErrTicketTenantIDRequired", err)
	}
	if _, _, err := store.Load(ctx, "", "esc_x"); !errors.Is(err, ErrTicketTenantIDRequired) {
		t.Fatalf("Load(empty tenant) = %v, want ErrTicketTenantIDRequired", err)
	}
	if _, err := store.Update(ctx, "", "esc_x", func(*dto.EscalationTicket) error { return nil }); !errors.Is(err, ErrTicketTenantIDRequired) {
		t.Fatalf("Update(empty tenant) = %v, want ErrTicketTenantIDRequired", err)
	}

	// And the cross-check: a valid tenantID still works after the
	// rejected calls (no state was mutated by the rejected Save).
	if err := store.Save(ctx, dto.EscalationTicket{TicketID: "esc_y", TenantID: "acme"}); err != nil {
		t.Fatalf("Save(valid tenant): %v", err)
	}
	if _, _, err := store.Load(ctx, "", "esc_y"); !errors.Is(err, ErrTicketTenantIDRequired) {
		t.Fatalf("Load with empty tenant must still reject after a successful Save, got %v", err)
	}
	got, ok, err := store.Load(ctx, "acme", "esc_y")
	if err != nil || !ok || got.TicketID != "esc_y" {
		t.Fatalf("Load(acme, esc_y) = (%+v, %v, %v); want ok=true", got, ok, err)
	}
}

// TestEscalation_ResolveRejectsCrossTenant complements the store-level
// check above with a service-level regression test: a caller from a
// foreign tenant must not be able to resolve someone else's ticket.
// The store filters by tenantID so the service Update returns
// not-found, which the handler maps to HTTP 404 (indistinguishable
// from a non-existent ticket — see PR #47 round 9).
func TestEscalation_ResolveRejectsCrossTenant(t *testing.T) {
	svc, _ := NewEscalationService(EscalationServiceConfig{Publisher: &fakeEscPub{}})
	tk, err := svc.Escalate(context.Background(), "acme", dto.EscalationIncident{Reason: dto.EscalationReasonUserRequested})
	if err != nil {
		t.Fatalf("Escalate: %v", err)
	}
	// Caller tenant="globex" attempts to resolve acme's ticket.
	if _, err := svc.ResolveEscalation(context.Background(), "globex", tk.TicketID, "soc-1", dto.OutcomeConfirmedPhishing, ""); err == nil {
		t.Fatal("expected cross-tenant resolve to fail, got nil")
	}
	// Ticket must still be Pending — cross-tenant attempt must not
	// have mutated state.
	loaded, ok, err := svc.Load(context.Background(), "acme", tk.TicketID)
	if err != nil || !ok {
		t.Fatalf("Load after rejected resolve: ok=%v err=%v", ok, err)
	}
	if loaded.Outcome != dto.OutcomePending {
		t.Fatalf("outcome must remain Pending, got %q", loaded.Outcome)
	}
}

func TestEscalation_ResolveRequiresTenantID(t *testing.T) {
	svc, _ := NewEscalationService(EscalationServiceConfig{Publisher: &fakeEscPub{}})
	tk, _ := svc.Escalate(context.Background(), "acme", dto.EscalationIncident{Reason: dto.EscalationReasonUserRequested})
	if _, err := svc.ResolveEscalation(context.Background(), "", tk.TicketID, "a", dto.OutcomeFalsePositive, ""); err == nil {
		t.Fatal("expected error for empty tenant_id")
	}
}

