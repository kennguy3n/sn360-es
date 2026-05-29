package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// PostgresTicketStore persists escalation tickets to the
// escalation_tickets table (migration 0001_init.up.sql, extended by
// 0003_escalation_resolution_code.up.sql which adds the structured
// resolution_code column the dashboard FalseRates query depends on).
//
// The DTO carries richer state than the discrete columns offer
// (timeline, incident metadata), so we round-trip the full ticket
// through the `context` JSONB column. The columns that the dashboard
// aggregates against — tenant_id, resolved_at, resolution_code — are
// written through dedicated columns so SQL aggregates can index them.
type PostgresTicketStore struct {
	db *postgres.DB
}

// NewPostgresTicketStore wires the store against a Postgres
// connection. The caller is responsible for ensuring migration 0003
// has been applied; the SQL below references the resolution_code
// column unconditionally.
func NewPostgresTicketStore(db *postgres.DB) *PostgresTicketStore {
	return &PostgresTicketStore{db: db}
}

// ticketContext is the JSONB payload we store in escalation_tickets.context.
// Keeping the full DTO round-trippable through this column means the
// in-memory store's behaviour (Load returns the same ticket Save was
// called with) carries over to the Postgres path without any lossy
// projection.
type ticketContext struct {
	Incident dto.EscalationIncident `json:"incident"`
	Timeline []dto.EscalationStep   `json:"timeline,omitempty"`
}

// Save implements TicketStore. Refuses to persist a ticket with an
// empty TenantID — the schema's tenant_id column is NOT NULL and the
// INSERT would fail at the database, but failing fast in Go gives a
// clearer error and skips the round-trip. Same defense-in-depth
// rationale as MemoryTicketStore.Save.
func (s *PostgresTicketStore) Save(ctx context.Context, t dto.EscalationTicket) error {
	if t.TenantID == "" {
		return ErrTicketTenantIDRequired
	}
	payload, err := json.Marshal(ticketContext{Incident: t.Incident, Timeline: t.Timeline})
	if err != nil {
		return fmt.Errorf("escalation: marshal context: %w", err)
	}
	resolutionCode := outcomeToCode(t.Outcome)
	var (
		resolvedAt     any
		assignedTo     any
		resolutionText any
	)
	if !t.ResolvedAt.IsZero() {
		resolvedAt = t.ResolvedAt.UTC()
	}
	if t.ResolverHash != "" {
		assignedTo = t.ResolverHash
	}
	if t.ResolutionNotes != "" {
		resolutionText = t.ResolutionNotes
	}
	priority, status := derivePriorityAndStatus(t)
	const q = `
        INSERT INTO escalation_tickets (
            tenant_id, ticket_number, trigger_reason, priority, status,
            message_id_hash, correlation_id, context,
            assigned_to, resolved_at, resolution, resolution_code,
            created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (ticket_number) DO UPDATE SET
            trigger_reason  = EXCLUDED.trigger_reason,
            priority        = EXCLUDED.priority,
            status          = EXCLUDED.status,
            context         = EXCLUDED.context,
            assigned_to     = EXCLUDED.assigned_to,
            resolved_at     = EXCLUDED.resolved_at,
            resolution      = EXCLUDED.resolution,
            resolution_code = EXCLUDED.resolution_code,
            updated_at      = NOW()
    `
	if _, err := s.db.ExecContext(ctx, q,
		t.TenantID, t.TicketID, string(t.Reason), priority, status,
		nullableHash(t.Incident.PseudoMessageID), nullableString(t.Incident.PseudoMessageID),
		payload, assignedTo, resolvedAt, resolutionText, resolutionCode,
		t.CreatedAt.UTC(), time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("escalation: postgres save: %w", err)
	}
	return nil
}

// Load implements TicketStore. The (tenant_id, ticket_number) pair is
// the logical primary key from the caller's perspective: ticket_number
// alone is unique-within-tenant but the query MUST also filter by
// tenant_id so a caller cannot fetch another tenant's ticket by
// guessing or by being passed a ticket_number from logs.
func (s *PostgresTicketStore) Load(ctx context.Context, tenantID, ticketID string) (dto.EscalationTicket, bool, error) {
	if tenantID == "" {
		return dto.EscalationTicket{}, false, ErrTicketTenantIDRequired
	}
	const q = `
        SELECT tenant_id, ticket_number, trigger_reason, context,
               assigned_to, resolved_at, resolution, resolution_code,
               created_at
          FROM escalation_tickets
         WHERE tenant_id = $1 AND ticket_number = $2
    `
	var (
		loadedTenantID, ticketNumber, triggerReason string
		contextPayload                              []byte
		assignedTo, resolution, resolutionCd        sql.NullString
		resolvedAt                                  sql.NullTime
		createdAt                                   time.Time
	)
	err := s.db.QueryRowContext(ctx, q, tenantID, ticketID).Scan(
		&loadedTenantID, &ticketNumber, &triggerReason, &contextPayload,
		&assignedTo, &resolvedAt, &resolution, &resolutionCd,
		&createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return dto.EscalationTicket{}, false, nil
	}
	if err != nil {
		return dto.EscalationTicket{}, false, fmt.Errorf("escalation: postgres load: %w", err)
	}
	var payload ticketContext
	if len(contextPayload) > 0 {
		if err := json.Unmarshal(contextPayload, &payload); err != nil {
			return dto.EscalationTicket{}, false, fmt.Errorf("escalation: unmarshal context: %w", err)
		}
	}
	ticket := dto.EscalationTicket{
		TicketID:        ticketNumber,
		TenantID:        loadedTenantID,
		CreatedAt:       createdAt,
		Reason:          dto.EscalationReason(triggerReason),
		Incident:        payload.Incident,
		Timeline:        payload.Timeline,
		Outcome:         codeToOutcome(resolutionCd.String),
		ResolverHash:    assignedTo.String,
		ResolutionNotes: resolution.String,
	}
	if resolvedAt.Valid {
		ticket.ResolvedAt = resolvedAt.Time
	}
	return ticket, true, nil
}

// Update implements TicketStore. It performs the mutation under a
// single SELECT-FOR-UPDATE so concurrent ResolveEscalation calls do
// not race on the same ticket. Like Load, the (tenant_id, ticket_number)
// pair is required to scope the SELECT FOR UPDATE.
func (s *PostgresTicketStore) Update(ctx context.Context, tenantID, ticketID string, mutate func(*dto.EscalationTicket) error) (dto.EscalationTicket, error) {
	if tenantID == "" {
		return dto.EscalationTicket{}, ErrTicketTenantIDRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: postgres update: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const selectQ = `
        SELECT tenant_id, ticket_number, trigger_reason, context,
               assigned_to, resolved_at, resolution, resolution_code,
               created_at
          FROM escalation_tickets
         WHERE tenant_id = $1 AND ticket_number = $2
         FOR UPDATE
    `
	var (
		loadedTenantID, ticketNumber, triggerReason string
		contextPayload                              []byte
		assignedTo, resolution, resolutionCd        sql.NullString
		resolvedAt                                  sql.NullTime
		createdAt                                   time.Time
	)
	if err := tx.QueryRowContext(ctx, selectQ, tenantID, ticketID).Scan(
		&loadedTenantID, &ticketNumber, &triggerReason, &contextPayload,
		&assignedTo, &resolvedAt, &resolution, &resolutionCd,
		&createdAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return dto.EscalationTicket{}, errors.New("escalation: ticket not found")
		}
		return dto.EscalationTicket{}, fmt.Errorf("escalation: postgres update select: %w", err)
	}
	var payload ticketContext
	if len(contextPayload) > 0 {
		if err := json.Unmarshal(contextPayload, &payload); err != nil {
			return dto.EscalationTicket{}, fmt.Errorf("escalation: unmarshal context: %w", err)
		}
	}
	ticket := dto.EscalationTicket{
		TicketID:        ticketNumber,
		TenantID:        loadedTenantID,
		CreatedAt:       createdAt,
		Reason:          dto.EscalationReason(triggerReason),
		Incident:        payload.Incident,
		Timeline:        payload.Timeline,
		Outcome:         codeToOutcome(resolutionCd.String),
		ResolverHash:    assignedTo.String,
		ResolutionNotes: resolution.String,
	}
	if resolvedAt.Valid {
		ticket.ResolvedAt = resolvedAt.Time
	}
	if err := mutate(&ticket); err != nil {
		return dto.EscalationTicket{}, err
	}
	newPayload, err := json.Marshal(ticketContext{Incident: ticket.Incident, Timeline: ticket.Timeline})
	if err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: marshal context: %w", err)
	}
	resolutionCode := outcomeToCode(ticket.Outcome)
	priority, status := derivePriorityAndStatus(ticket)
	var (
		newResolvedAt   any
		newAssignedTo   any
		newResolutionTx any
	)
	if !ticket.ResolvedAt.IsZero() {
		newResolvedAt = ticket.ResolvedAt.UTC()
	}
	if ticket.ResolverHash != "" {
		newAssignedTo = ticket.ResolverHash
	}
	if ticket.ResolutionNotes != "" {
		newResolutionTx = ticket.ResolutionNotes
	}
	const updateQ = `
        UPDATE escalation_tickets
           SET trigger_reason  = $1,
               priority        = $2,
               status          = $3,
               context         = $4::jsonb,
               assigned_to     = $5,
               resolved_at     = $6,
               resolution      = $7,
               resolution_code = $8,
               updated_at      = NOW()
         WHERE tenant_id       = $9
           AND ticket_number   = $10
    `
	if _, err := tx.ExecContext(ctx, updateQ,
		string(ticket.Reason), priority, status, newPayload,
		newAssignedTo, newResolvedAt, newResolutionTx, resolutionCode,
		tenantID, ticketID,
	); err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: postgres update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return dto.EscalationTicket{}, fmt.Errorf("escalation: postgres commit: %w", err)
	}
	return ticket, nil
}

// outcomeToCode maps the DTO outcome enum to the structured
// resolution_code column value. OutcomePending writes NULL so the
// CHECK constraint allows it (the column is NULL when a ticket has
// not been resolved yet).
func outcomeToCode(o dto.EscalationOutcome) any {
	switch o {
	case dto.OutcomeConfirmedPhishing,
		dto.OutcomeFalsePositive,
		dto.OutcomeRequiresHunting,
		dto.OutcomeClosedNoAction:
		return string(o)
	}
	return nil
}

// codeToOutcome is the inverse mapping used when loading rows.
func codeToOutcome(code string) dto.EscalationOutcome {
	switch dto.EscalationOutcome(code) {
	case dto.OutcomeConfirmedPhishing,
		dto.OutcomeFalsePositive,
		dto.OutcomeRequiresHunting,
		dto.OutcomeClosedNoAction:
		return dto.EscalationOutcome(code)
	}
	return dto.OutcomePending
}

// derivePriorityAndStatus projects the DTO onto the legacy v1
// priority/status columns. The escalation service does not track
// priority explicitly, so we surface it via the trigger reason: the
// confirmed_breach / account_compromise reasons map to 'critical',
// everything else stays at the schema default 'normal'. Status is a
// straight function of whether a resolved_at timestamp is present.
func derivePriorityAndStatus(t dto.EscalationTicket) (priority string, status string) {
	priority = "normal"
	switch t.Reason {
	case dto.EscalationReasonConfirmedBreach, dto.EscalationReasonAccountCompromise:
		priority = "critical"
	case dto.EscalationReasonZeroDayAttachment:
		priority = "high"
	}
	status = "open"
	if !t.ResolvedAt.IsZero() {
		status = "resolved"
	}
	return priority, status
}

// nullableHash returns a BYTEA-suitable value or nil. The schema
// stores message ids as raw bytes; we treat the pseudo id (already
// privacy-safe) as the canonical identifier.
func nullableHash(s string) any {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
