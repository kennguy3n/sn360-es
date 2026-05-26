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
