package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// EscalationPublisher is the minimal contract the escalation service
// needs from the event bus.
type EscalationPublisher interface {
	Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error
}

// TicketStore persists escalation tickets. The default in-memory
// implementation is sufficient for tests; production wires Postgres
// via the management service.
type TicketStore interface {
	Save(ctx context.Context, t dto.EscalationTicket) error
	Load(ctx context.Context, ticketID string) (dto.EscalationTicket, bool, error)
	Update(ctx context.Context, ticketID string, mutate func(*dto.EscalationTicket) error) (dto.EscalationTicket, error)
}

// FeedbackSink receives the resolution outcome so it can be fed back
// into the ML training pipeline.
type FeedbackSink interface {
	RecordOutcome(ctx context.Context, t dto.EscalationTicket) error
}

// EscalationServiceConfig wires the service.
type EscalationServiceConfig struct {
	Publisher EscalationPublisher
	Store     TicketStore
	Feedback  FeedbackSink
	Logger    *slog.Logger
	Clock     func() time.Time
}

// EscalationService creates structured tickets for SecOps and records
// the resolution outcome (PROPOSAL.md §4).
type EscalationService struct {
	pub      EscalationPublisher
	store    TicketStore
	feedback FeedbackSink
	log      *slog.Logger
	now      func() time.Time
}

// NewEscalationService constructs the service.
func NewEscalationService(cfg EscalationServiceConfig) (*EscalationService, error) {
	if cfg.Publisher == nil {
		return nil, errors.New("escalation: publisher is required")
	}
	if cfg.Store == nil {
		cfg.Store = NewMemoryTicketStore()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &EscalationService{
		pub:      cfg.Publisher,
		store:    cfg.Store,
		feedback: cfg.Feedback,
		log:      cfg.Logger,
		now:      cfg.Clock,
	}, nil
}

// Escalate creates a ticket for the supplied incident, persists it,
// and publishes `es.action.escalation.created` on the bus.
func (s *EscalationService) Escalate(ctx context.Context, tenantID string, incident dto.EscalationIncident) (dto.EscalationTicket, error) {
	if tenantID == "" {
		return dto.EscalationTicket{}, errors.New("escalation: tenant_id is required")
	}
	if !incident.Reason.Valid() {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: invalid reason %q", incident.Reason)
	}
	id, err := newTicketID()
	if err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: ticket id: %w", err)
	}
	now := s.now()
	if incident.DetectedAt.IsZero() {
		incident.DetectedAt = now
	}
	ticket := dto.EscalationTicket{
		TicketID:  id,
		TenantID:  tenantID,
		CreatedAt: now,
		Reason:    incident.Reason,
		Incident:  scrubIncident(incident),
		Timeline: []dto.EscalationStep{{
			OccurredAt: now,
			Step:       "created",
			Detail:     "Incident detected and escalation ticket opened.",
		}},
	}
	if err := s.store.Save(ctx, ticket); err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: store: %w", err)
	}
	payload, err := json.Marshal(ticket)
	if err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: marshal: %w", err)
	}
	if err := s.pub.Publish(ctx, "es.action.escalation.created", payload,
		events.WithEventType("action.escalation.created"),
		events.WithTenantID(tenantID),
		events.WithMessageID(ticket.TicketID),
	); err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: publish: %w", err)
	}
	s.log.InfoContext(ctx, "escalation.created",
		slog.String("tenant_id", tenantID),
		slog.String("ticket_id", id),
		slog.String("reason", string(ticket.Reason)),
	)
	return ticket, nil
}

// ResolveEscalation records the SecOps outcome and feeds it into the
// training pipeline.
func (s *EscalationService) ResolveEscalation(ctx context.Context, ticketID string, resolverHash string, outcome dto.EscalationOutcome, notes string) (dto.EscalationTicket, error) {
	if ticketID == "" {
		return dto.EscalationTicket{}, errors.New("escalation: ticket_id is required")
	}
	if !outcome.Valid() {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: invalid outcome %q", outcome)
	}
	updated, err := s.store.Update(ctx, ticketID, func(t *dto.EscalationTicket) error {
		if t.Outcome != dto.OutcomePending {
			return fmt.Errorf("escalation: already resolved as %q", t.Outcome)
		}
		t.Outcome = outcome
		t.ResolvedAt = s.now()
		t.ResolverHash = resolverHash
		t.ResolutionNotes = notes
		t.Timeline = append(t.Timeline, dto.EscalationStep{
			OccurredAt: t.ResolvedAt,
			Step:       "resolved",
			Detail:     string(outcome),
		})
		return nil
	})
	if err != nil {
		return dto.EscalationTicket{}, err
	}
	if s.feedback != nil {
		if err := s.feedback.RecordOutcome(ctx, updated); err != nil {
			s.log.WarnContext(ctx, "escalation: feedback sink failed",
				slog.String("ticket_id", ticketID),
				slog.Any("error", err),
			)
		}
	}
	payload, err := json.Marshal(updated)
	if err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: marshal: %w", err)
	}
	if err := s.pub.Publish(ctx, "es.action.escalation.resolved", payload,
		events.WithEventType("action.escalation.resolved"),
		events.WithTenantID(updated.TenantID),
		events.WithMessageID(ticketID),
	); err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: publish: %w", err)
	}
	return updated, nil
}

// Load returns the persisted ticket with the given ID.
func (s *EscalationService) Load(ctx context.Context, ticketID string) (dto.EscalationTicket, bool, error) {
	return s.store.Load(ctx, ticketID)
}

// scrubIncident strips any caller-supplied PII fields that managed to
// sneak past the public DTO. We intentionally only echo the fields we
// expect.
func scrubIncident(in dto.EscalationIncident) dto.EscalationIncident {
	return dto.EscalationIncident{
		PseudoMessageID:   in.PseudoMessageID,
		Tier:              in.Tier,
		Category:          in.Category,
		Reason:            in.Reason,
		Score:             in.Score,
		AffectedUserCount: in.AffectedUserCount,
		AISummary:         in.AISummary,
		Indicators:        append([]string(nil), in.Indicators...),
		DetectedAt:        in.DetectedAt,
	}
}

func newTicketID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "esc_" + hex.EncodeToString(b[:]), nil
}

// --- In-memory ticket store ---

// MemoryTicketStore is a goroutine-safe in-memory TicketStore.
type MemoryTicketStore struct {
	mu      sync.RWMutex
	tickets map[string]dto.EscalationTicket
}

// NewMemoryTicketStore returns an empty store.
func NewMemoryTicketStore() *MemoryTicketStore {
	return &MemoryTicketStore{tickets: map[string]dto.EscalationTicket{}}
}

// Save implements TicketStore.
func (m *MemoryTicketStore) Save(_ context.Context, t dto.EscalationTicket) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tickets[t.TicketID] = t
	return nil
}

// Load implements TicketStore.
func (m *MemoryTicketStore) Load(_ context.Context, ticketID string) (dto.EscalationTicket, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tickets[ticketID]
	return t, ok, nil
}

// Update implements TicketStore.
func (m *MemoryTicketStore) Update(_ context.Context, ticketID string, mutate func(*dto.EscalationTicket) error) (dto.EscalationTicket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tickets[ticketID]
	if !ok {
		return dto.EscalationTicket{}, errors.New("escalation: ticket not found")
	}
	if err := mutate(&t); err != nil {
		return dto.EscalationTicket{}, err
	}
	m.tickets[ticketID] = t
	return t, nil
}
