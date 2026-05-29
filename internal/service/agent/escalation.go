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

// ErrTicketTenantIDRequired is returned whenever a TicketStore method
// is invoked with an empty tenant ID. Every ticket is hard-scoped to a
// tenant — see the TicketStore interface comment for rationale — so a
// missing tenantID is an unrecoverable contract violation. Exported as
// a sentinel so callers (and tests) can `errors.Is(err, …)` instead of
// matching the message string.
//
// Validation is duplicated at both the service layer (Escalate /
// ResolveEscalation / Load) and the store layer (Save / Load / Update)
// as defense in depth: a future caller that bypasses the service and
// calls the store directly cannot accidentally write a ticket under a
// blank-tenant key — which would otherwise be readable by any caller
// passing a blank tenantID.
var ErrTicketTenantIDRequired = errors.New("escalation: tenant_id is required")

// EscalationPublisher is the minimal contract the escalation service
// needs from the event bus.
type EscalationPublisher interface {
	Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error
}

// TicketStore persists escalation tickets. The default in-memory
// implementation is sufficient for tests; production wires Postgres
// via the management service.
//
// Every Load / Update operation MUST be scoped to a tenant. ticketID
// alone is not sufficient: tickets are identified by a short opaque
// number that is unique within a tenant but could collide across
// tenants, and even when it doesn't, looking up another tenant's
// ticket would be a cross-tenant data leak. The interface therefore
// takes tenantID as a first-class argument and implementations must
// include it in their WHERE / map-lookup clauses.
type TicketStore interface {
	Save(ctx context.Context, t dto.EscalationTicket) error
	Load(ctx context.Context, tenantID, ticketID string) (dto.EscalationTicket, bool, error)
	Update(ctx context.Context, tenantID, ticketID string, mutate func(*dto.EscalationTicket) error) (dto.EscalationTicket, error)
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
		return dto.EscalationTicket{}, ErrTicketTenantIDRequired
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

// ErrTicketNotFound is returned by the TicketStore implementations
// (Memory + Postgres) when a Load/Update targets a ticket ID that
// either does not exist OR belongs to a different tenant — both
// failure modes collapse to the same sentinel because the store's
// (tenant_id, ticket_id) compound lookup cannot distinguish them.
// That collapse is the security contract: the handler MUST map this
// to HTTP 404 with a generic body so an authenticated caller from
// tenant B cannot fingerprint which ticket IDs belong to tenant A by
// probing the resolve / get endpoints (a distinguishable 403 vs 404
// would leak the existence of a cross-tenant ticket).
//
// Callers should use errors.Is(err, ErrTicketNotFound) rather than
// string-matching the error message.
var ErrTicketNotFound = errors.New("escalation: ticket not found")

// ResolveEscalation records the SecOps outcome and feeds it into the
// training pipeline. tenantID is the authenticated caller's tenant
// and must match the ticket's TenantID — the store filters on it so a
// cross-tenant ticketID guess returns "not found" rather than
// resolving someone else's ticket.
func (s *EscalationService) ResolveEscalation(ctx context.Context, tenantID, ticketID string, resolverHash string, outcome dto.EscalationOutcome, notes string) (dto.EscalationTicket, error) {
	if tenantID == "" {
		return dto.EscalationTicket{}, ErrTicketTenantIDRequired
	}
	if ticketID == "" {
		return dto.EscalationTicket{}, errors.New("escalation: ticket_id is required")
	}
	if !outcome.Valid() {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: invalid outcome %q", outcome)
	}
	updated, err := s.store.Update(ctx, tenantID, ticketID, func(t *dto.EscalationTicket) error {
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

// Load returns the persisted ticket with the given ID, scoped to the
// caller's tenant. A ticket with a matching ID but a different
// tenantID returns (zero, false, nil) — same as a missing ticket — so
// the caller cannot distinguish "does not exist" from "belongs to
// another tenant" (avoids the timing / response-shape oracle).
func (s *EscalationService) Load(ctx context.Context, tenantID, ticketID string) (dto.EscalationTicket, bool, error) {
	if tenantID == "" {
		return dto.EscalationTicket{}, false, ErrTicketTenantIDRequired
	}
	return s.store.Load(ctx, tenantID, ticketID)
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

// MemoryTicketStore is a goroutine-safe in-memory TicketStore keyed by
// (tenantID, ticketID) so tickets are hard-isolated per tenant — see
// memoryTicketKey for rationale.
type MemoryTicketStore struct {
	mu      sync.RWMutex
	tickets map[memoryTicketKey]dto.EscalationTicket
}

// NewMemoryTicketStore returns an empty store.
func NewMemoryTicketStore() *MemoryTicketStore {
	return &MemoryTicketStore{tickets: map[memoryTicketKey]dto.EscalationTicket{}}
}

// memoryTicketKey is the composite (tenantID, ticketID) lookup key for
// the in-memory store. Embedding tenantID in the map key gives the
// in-memory implementation the same hard isolation as the Postgres
// implementation's WHERE-tenant_id-AND-ticket_number predicate.
type memoryTicketKey struct {
	tenantID string
	ticketID string
}

// Save implements TicketStore. Refuses to persist a ticket with an
// empty TenantID — otherwise the entry would land under a
// no-tenant key that any caller passing a blank tenantID could read.
// The service layer already validates Escalate's tenantID before
// constructing the ticket, but the store enforces the same invariant
// so a direct caller cannot bypass it.
func (m *MemoryTicketStore) Save(_ context.Context, t dto.EscalationTicket) error {
	if t.TenantID == "" {
		return ErrTicketTenantIDRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tickets[memoryTicketKey{tenantID: t.TenantID, ticketID: t.TicketID}] = t
	return nil
}

// Load implements TicketStore. Refuses an empty tenantID for the
// same defense-in-depth reason as Save.
func (m *MemoryTicketStore) Load(_ context.Context, tenantID, ticketID string) (dto.EscalationTicket, bool, error) {
	if tenantID == "" {
		return dto.EscalationTicket{}, false, ErrTicketTenantIDRequired
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tickets[memoryTicketKey{tenantID: tenantID, ticketID: ticketID}]
	return t, ok, nil
}

// Update implements TicketStore. Refuses an empty tenantID for the
// same defense-in-depth reason as Save.
func (m *MemoryTicketStore) Update(_ context.Context, tenantID, ticketID string, mutate func(*dto.EscalationTicket) error) (dto.EscalationTicket, error) {
	if tenantID == "" {
		return dto.EscalationTicket{}, ErrTicketTenantIDRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memoryTicketKey{tenantID: tenantID, ticketID: ticketID}
	t, ok := m.tickets[key]
	if !ok {
		return dto.EscalationTicket{}, ErrTicketNotFound
	}
	if err := mutate(&t); err != nil {
		return dto.EscalationTicket{}, err
	}
	m.tickets[key] = t
	return t, nil
}
