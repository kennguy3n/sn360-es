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
// Responsibilities:
//
//   - Translate communication_histories.typical_hour (int, -1
//     sentinel, 0..23 valid) into dto.RiskSignals.TypicalSendHour
//     (*int, nil = no baseline). Out-of-range values are mapped to
//     nil so a stale producer can never feed garbage into the ATO
//     heuristic's hourDistance.
//   - Populate dto.RiskSignals.CommunicationFrequency from the row's
//     30-day rolling count (Count30d). That window matches the
//     classifier's lookback so the same view of "recent activity"
//     drives both relationship categorisation and the ATO
//     frequency guard.
//   - Set dto.RiskSignals.IsFirstContact = true iff the repository
//     returns ErrNotFound for the (tenant, sender, recipient)
//     triple. Any other error degrades to "leave fields as base"
//     so a Postgres blip cannot synthesise a spurious first-contact
//     signal and force every in-flight message through Tier 2.
//   - Stamp dto.RiskSignals.CurrentHourUTC from req.ReceivedAt
//     (falling back to the enricher's clock when the request lacks
//     a received timestamp) so the ATO heuristic always compares
//     against the actual arrival hour rather than the upstream
//     wall-clock at publish time.
//
// The enricher hashes the sender and recipient with the same PII
// hasher the directory/relationship workers use so the key
// matches communication_histories' (sender_hash, recipient_hash)
// primary key derivation byte-for-byte.
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

	// CurrentHourUTC is derived from the request itself; populate it
	// even when the repository lookup short-circuits below so the
	// ATO heuristic always has the arrival hour available.
	//
	// This unconditionally overwrites any producer-supplied
	// CurrentHourUTC on base, by design: the heuristic must compare
	// against the actual arrival time, not the publish-time
	// wall-clock from a normalizer that ran minutes earlier on a
	// different node. RelationshipCategory is the opposite — it is
	// preserved when the producer already classified the pair (see
	// below) because classification is repo-driven and the
	// normalizer-supplied value is also repo-driven, so the most
	// recently-observed one wins. The asymmetry is intentional.
	out.CurrentHourUTC = e.deriveCurrentHourUTC(req)

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
		// fields at their base values and rely on the heuristic's
		// graceful no-baseline degradation.
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
