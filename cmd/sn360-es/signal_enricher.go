package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
)

// commHistorySignalEnricher implements evaluate.SignalEnricher by
// reading the per-(tenant, sender, recipient) row from
// communication_histories and folding its persisted fields onto
// the base RiskSignals the normalizer produced.
//
// Field ownership (which side wins when both base and the row
// disagree):
//
//   - CurrentHourUTC: ENRICHER-OWNED. Unconditionally derived from
//     req.ReceivedAt; any producer-supplied value on base is
//     dropped. The ATO heuristic must compare against actual
//     arrival time, not publish-time wall-clock.
//   - TypicalSendHour: ENRICHER-OWNED. Cleared on entry; only
//     populated from a valid (0..23) DB row. A stale or future
//     producer-supplied value on base cannot survive enrichment.
//   - CommunicationFrequency: ENRICHER-OWNED when a row exists.
//     Set to the row's Count30d; unmodified when the row lookup
//     short-circuits or errors transiently.
//   - IsFirstContact: ENRICHER-OWNED. Set to true only on
//     ErrNotFound; transient repo failures degrade to base so a
//     Postgres blip cannot force every in-flight message into
//     Tier 2.
//   - RelationshipCategory: BASE-WINS when the producer already
//     classified the pair. Both sides are repo-driven, so the most-
//     recently-observed classification (the producer's, if it has
//     one) wins; the enricher only fills in when base is Unknown.
//   - SenderDomain and other producer-only fields: BASE-PRESERVED.
//     The enricher does not touch them.
//
// The enricher hashes the sender and recipient with the same PII
// hasher the directory/relationship workers use so the key
// matches communication_histories' (sender_hash, recipient_hash)
// primary key derivation byte-for-byte.
//
// Producer-side contract for whoever wires the ingestion-time
// writer (currently no production writer exists — see the
// pre-existing gap noted in relationship_worker.go's CommunicationUpserter
// comment): any code path that writes communication_histories.sender_hash
// or recipient_hash MUST derive the column from
//
//	HashPII(tenantID, strings.TrimSpace(strings.ToLower(address)))
//
// — the same trim + lower + tenant-keyed BLAKE2 derivation this
// enricher applies on the read side. Asymmetric normalisation
// (e.g. ingestion hashes raw "Alice@Example.COM" while the
// enricher hashes "alice@example.com") will make every message
// look like first-contact regardless of how many prior messages
// the pair exchanged.
//
// The enricher does NOT mutate base; it returns a copy with the
// enrichment fields populated.
type commHistorySignalEnricher struct {
	histories repository.CommunicationHistoryRepository
	hasher    agent.PIIHasher
	logger    *slog.Logger
	now       func() time.Time
}

// newCommHistorySignalEnricher constructs an enricher. Returns nil
// when either dependency is missing — the composition root should
// substitute evaluate.NoopEnricher in that case so the consumer
// call site never has to nil-check.
func newCommHistorySignalEnricher(
	histories repository.CommunicationHistoryRepository,
	hasher agent.PIIHasher,
	logger *slog.Logger,
) *commHistorySignalEnricher {
	if histories == nil || hasher == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &commHistorySignalEnricher{
		histories: histories,
		hasher:    hasher,
		logger:    logger,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

// Enrich folds the per-relationship signals onto base. Safe to call
// concurrently; the repository implementations and the PII hasher
// are required to be goroutine-safe.
func (e *commHistorySignalEnricher) Enrich(ctx context.Context, req dto.EvaluateRequest, base dto.RiskSignals) dto.RiskSignals {
	out := base

	// CurrentHourUTC and TypicalSendHour are both enricher-owned
	// (see the field-ownership table on commHistorySignalEnricher).
	// Clear/overwrite them up front so a future producer that
	// accidentally sets either field cannot leak a stale value past
	// the enricher — the ATO heuristic must compare against the
	// actual arrival hour, and a non-nil TypicalSendHour past this
	// point must come from a row whose typical_hour column was
	// validated in 0..23 (below).
	out.CurrentHourUTC = e.deriveCurrentHourUTC(req)
	out.TypicalSendHour = nil

	tenantID := strings.TrimSpace(req.TenantID)
	sender := strings.TrimSpace(strings.ToLower(req.Sender))
	recipient := strings.TrimSpace(strings.ToLower(primaryRecipient(req)))
	if tenantID == "" || sender == "" || recipient == "" {
		// Without a (tenant, sender, recipient) triple there is
		// nothing to look up. Leave the per-relationship fields
		// at their base values (typically zero / nil) so the ATO
		// heuristic short-circuits cleanly.
		return out
	}

	senderHash := []byte(e.hasher.HashPII(tenantID, sender))
	recipientHash := []byte(e.hasher.HashPII(tenantID, recipient))
	if len(senderHash) == 0 || len(recipientHash) == 0 {
		return out
	}

	row, err := e.histories.Get(ctx, tenantID, senderHash, recipientHash)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		// No history at all: a true first-contact pair. Leave
		// TypicalSendHour and CommunicationFrequency at their
		// zero values (nil / 0) so the ATO heuristic short-
		// circuits, and signal first-contact for the categoriser /
		// Tier 0 escalation gate.
		out.IsFirstContact = true
		return out
	case err != nil:
		// Transient repository failure: do NOT synthesise a
		// first-contact flag (it would force every in-flight
		// message into Tier 2 during a Postgres blip). Leave the
		// per-relationship fields (CommunicationFrequency,
		// IsFirstContact, RelationshipCategory) at their base
		// values and rely on the heuristic's graceful no-baseline
		// degradation. CurrentHourUTC and TypicalSendHour have
		// already been stamped/cleared up front per the enricher-
		// owned contract; they are intentionally NOT rolled back
		// here because a Postgres blip cannot un-do the fact that
		// this message arrived at the time it arrived.
		e.logger.Warn("signal enricher: communication_histories.Get failed; degrading to base signals",
			slog.String("tenant_id", tenantID), slog.Any("error", err))
		return out
	}

	// Existing row: populate the per-relationship signals.
	out.IsFirstContact = false
	out.CommunicationFrequency = row.Count30d
	if h := row.TypicalHour; h >= 0 && h < 24 {
		hour := h
		out.TypicalSendHour = &hour
	}
	// If the row's persisted Relationship label is one of the
	// classifier-recognised categories AND base did not already
	// carry a category, surface it so Tier 0 / threshold
	// adjustment use the worker-maintained view instead of a
	// stale producer-supplied value.
	if out.RelationshipCategory == dto.RelationshipUnknown {
		if cat := dto.RelationshipCategory(row.Relationship); cat.Valid() && cat != dto.RelationshipUnknown {
			out.RelationshipCategory = cat
		}
	}
	return out
}

// SightingFor derives the WS-4a CommHistoryUpdate event for a
// request, sharing exactly the same TrimSpace + ToLower
// normalisation Enrich applies on the read side. Keeping both
// derivations on the same type means a future change to the
// normalisation rule (e.g. NFKC unicode folding for IDNA-equivalent
// domains, or stripping plus-suffixes from local parts) lands in
// one place and stays symmetric between the consumer that updates
// communication_histories and every other code path that looks
// the same row up.
//
// Returned bool is false when any component of the
// (tenant, sender, recipient) triple is empty after normalisation,
// or when the PII hasher returns an empty digest. The handler
// skips the publish in that case so the bus never carries an
// envelope the consumer would reject in Validate().
//
// SentAt is sourced from req.ReceivedAt — the bridge stamps it at
// ingestion time, so two redeliveries of the same envelope produce
// the same SentAt. This determinism is what makes the
// (tenant, sender, recipient, message_id)-keyed JetStream dedup
// window collapse redeliveries at the broker instead of double-
// counting at the consumer. Falling back to e.now() on an unset
// ReceivedAt would break that property; the bridge guarantees
// ReceivedAt is non-zero on every envelope, but the fallback is
// retained because returning a zero SentAt would otherwise force
// the consumer to NAK every envelope from a misconfigured
// publisher and silently kill the WS-4a hot path. The fallback
// trades determinism for liveness in the broken-publisher case.
func (e *commHistorySignalEnricher) SightingFor(_ context.Context, req dto.EvaluateRequest) (dto.CommHistoryUpdate, bool) {
	tenantID := strings.TrimSpace(req.TenantID)
	sender := strings.TrimSpace(strings.ToLower(req.Sender))
	recipient := strings.TrimSpace(strings.ToLower(primaryRecipient(req)))
	if tenantID == "" || sender == "" || recipient == "" {
		return dto.CommHistoryUpdate{}, false
	}
	if req.MessageID == "" {
		// A sighting without a message id has no usable dedup
		// key; publishing it would either collide with another
		// envelope's dedup id (broker drops the second one) or
		// receive a derived id that re-collides on every
		// redelivery — either way the consumer either undercounts
		// or double-counts. Refuse to publish.
		return dto.CommHistoryUpdate{}, false
	}
	senderHash := []byte(e.hasher.HashPII(tenantID, sender))
	recipientHash := []byte(e.hasher.HashPII(tenantID, recipient))
	if len(senderHash) == 0 || len(recipientHash) == 0 {
		return dto.CommHistoryUpdate{}, false
	}
	// SenderDomain is best-effort: the producer may have left it
	// blank (e.g. malformed `From:`). The consumer treats an
	// empty domain as "do not overwrite the persisted value", so
	// emitting a blank here is safe and triggers the one-way
	// backfill on the read side.
	senderDomain := strings.TrimSpace(strings.ToLower(req.Signals.SenderDomain))
	var senderDomainHash []byte
	if senderDomain != "" {
		senderDomainHash = []byte(e.hasher.HashPII(tenantID, senderDomain))
	}
	sentAt := req.ReceivedAt
	if sentAt.IsZero() {
		// Liveness fallback documented above. The consumer's
		// LastSeenAt is GREATEST(persisted, sighting), so a
		// non-deterministic wall-clock value here can only
		// advance LastSeenAt forward — it cannot corrupt a
		// stable baseline.
		sentAt = e.now()
	}
	return dto.CommHistoryUpdate{
		TenantID:         tenantID,
		MessageID:        req.MessageID,
		SenderHash:       senderHash,
		RecipientHash:    recipientHash,
		SenderDomainHash: senderDomainHash,
		SenderDomain:     senderDomain,
		SentAt:           sentAt.UTC(),
	}, true
}

// deriveCurrentHourUTC prefers req.ReceivedAt (the arrival time
// stamped by the ingestion pipeline) over wall-clock so the ATO
// heuristic compares against the actual message hour rather than
// the moment the evaluator dequeues the request from the bus.
func (e *commHistorySignalEnricher) deriveCurrentHourUTC(req dto.EvaluateRequest) int {
	if !req.ReceivedAt.IsZero() {
		return req.ReceivedAt.UTC().Hour()
	}
	return e.now().Hour()
}

// primaryRecipient returns the recipient address the
// communication_histories aggregate is keyed on. The normalizer
// populates EvaluateRequest.Recipient with the authoritative
// recipient mailbox (the inbox the message landed in); CC
// addresses are kept separately and are not the aggregate key.
func primaryRecipient(req dto.EvaluateRequest) string {
	return req.Recipient
}

// Ensure commHistorySignalEnricher satisfies the interface.
var _ evaluate.SignalEnricher = (*commHistorySignalEnricher)(nil)
