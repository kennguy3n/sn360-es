package evaluate

import (
	"context"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// SignalEnricher folds per-relationship state (typical send hour,
// communication frequency, first-contact flag, current-hour
// reference) onto the base RiskSignals the normalizer derived from
// raw headers.
//
// The normalizer is a pure header-and-body transform; it has no
// access to the persistent communication_histories aggregate that
// the relationship worker maintains. The Tier 0 ATO heuristic,
// however, depends on those fields (TypicalSendHour,
// CommunicationFrequency, IsFirstContact, CurrentHourUTC) to fire
// at all. The SignalEnricher closes that loop at the consumer-side
// boundary, AFTER the request has been dequeued from the bus and
// BEFORE it is handed to Evaluator.Evaluate.
//
// Placing enrichment at the consumer rather than the producer is
// deliberate:
//
//   - Producer-side enrichment would couple every ingestion path
//     (poller, push manager, perf-harness, future batch publishers)
//     to the repository + PII hasher dependencies. The producer is
//     otherwise a pure normalize + publish transform.
//   - The relationship state and the wall-clock CurrentHourUTC are
//     time-sensitive. A request that sits on the bus for minutes
//     before being consumed should be enriched against the state
//     observed at evaluation time, not at publish time, so the ATO
//     heuristic compares against the freshest baseline.
//   - Both the per-message handler and the batch orchestrator
//     converge on Evaluator.Evaluate(ctx, req, signals) and can
//     therefore share a single enricher injected at the composition
//     root.
//
// Implementations MUST be safe for concurrent use.
type SignalEnricher interface {
	Enrich(ctx context.Context, req dto.EvaluateRequest, base dto.RiskSignals) dto.RiskSignals

	// SightingFor derives the per-message CommHistoryUpdate event
	// the WS-4a hot-path publishes onto
	// es.management.comm_history.update after Enrich completes.
	// The returned event encodes the same (tenant, sender,
	// recipient) triple Enrich keys its repository lookup on, so
	// the publisher cannot accidentally drift from the read-side
	// normalisation (TrimSpace + ToLower + tenant-keyed BLAKE2)
	// and break the symmetry that makes communication_histories
	// rows match across reads and writes.
	//
	// The boolean is false when the triple is incomplete — the
	// same short-circuit Enrich applies when tenant, sender, or
	// recipient is empty after normalisation. NoopEnricher always
	// returns false because a deployment without the repository or
	// the PII hasher has nowhere to write the sighting; the
	// caller is expected to skip the publish entirely in that
	// case so the bus never carries an unpersisted event.
	//
	// The returned CommHistoryUpdate is the wire shape, not the
	// repository Sighting shape. The consumer reconstructs the
	// Sighting from the event and feeds it into
	// CommunicationHistoryRepository.RecordSighting.
	SightingFor(ctx context.Context, req dto.EvaluateRequest) (dto.CommHistoryUpdate, bool)
}

// NoopEnricher is the SignalEnricher the composition root
// substitutes when its dependencies (repository.CommunicationHistories,
// agent.PIIHasher) are not wired. Call sites can therefore unconditionally
// invoke Enrich without nil-checking; a partially-wired deployment
// degrades to the pre-enricher behaviour where Tier 0's timing
// anomaly check sees no baseline and short-circuits to 0.
type NoopEnricher struct{}

// Enrich returns base unchanged. NoopEnricher satisfies SignalEnricher.
func (NoopEnricher) Enrich(_ context.Context, _ dto.EvaluateRequest, base dto.RiskSignals) dto.RiskSignals {
	return base
}

// SightingFor returns (zero, false) so the publisher skips the
// WS-4a hot-path publish entirely when the deployment is missing
// the repository or the PII hasher (the same conditions that cause
// the composition root to substitute NoopEnricher for the real
// enricher). Without a repository to persist into, every produced
// sighting would just queue up and time out at the broker.
func (NoopEnricher) SightingFor(_ context.Context, _ dto.EvaluateRequest) (dto.CommHistoryUpdate, bool) {
	return dto.CommHistoryUpdate{}, false
}
