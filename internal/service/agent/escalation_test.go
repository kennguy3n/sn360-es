package agent

import (
	"context"
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
