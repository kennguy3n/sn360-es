package evaluate

// This file holds the WS-4a publisher helper shared by the per-message
// handler (cmd/sn360-es/consumers_evaluate.go) and the batch
// orchestrator (batch.go). Both code paths derive a per-message
// sighting from the same SignalEnricher (so the normalisation cascade
// stays symmetric with the read path) and publish it onto
// dto.CommHistoryUpdateSubject with the deterministic dedup id.
//
// The function lives here, not in the cmd/ package, because the batch
// orchestrator is library code that cannot import the cmd/ package
// without creating an import cycle. Both call sites pass in the same
// Sink (`*natsbus.Service` / `events.EventService`) and the same
// `SignalEnricher`, so the helper takes them as parameters and lives
// alongside BatchOrchestrator.

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// PublishCommHistoryUpdate is the WS-4a producer-side helper. It
// derives the per-message sighting via SignalEnricher.SightingFor
// (which shares the read-side normalisation cascade so the
// (tenant, sender, recipient) triple matches the row keys the
// read-side Get() targets), marshals it, and publishes onto
// dto.CommHistoryUpdateSubject with the deterministic dedup id bound
// to (tenant, sender_hash, recipient_hash, message_id).
//
// The function intentionally swallows all errors: failure to produce
// a sighting must NEVER block the caller, because the caller is on
// the hot path of either the per-message evaluator (where blocking
// would NAK the upstream evaluate.request envelope and produce a
// duplicate evaluate.result on the next redelivery) or the batch
// orchestrator (where blocking would NAK the entire fetched batch
// for one transient bus blip). The relationship_worker's 4-hour
// recomputation cycle recovers any dropped sighting from the
// persisted communication_histories rows, so the worst case here
// is a 4-hour staleness window on the incremental counters.
//
// Both arguments are tolerated nil: a partially-wired deployment
// (no enricher, no bus) is a no-op rather than a panic.
func PublishCommHistoryUpdate(
	ctx context.Context,
	sink Sink,
	enricher SignalEnricher,
	logger *slog.Logger,
	req dto.EvaluateRequest,
) {
	if enricher == nil || sink == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	upd, ok := enricher.SightingFor(ctx, req)
	if !ok {
		// SightingFor returns false on the same short-circuits
		// Enrich applies (empty tenant / sender / recipient /
		// message-id, or a NoopEnricher deployment). No need
		// to log; the read path will have already
		// short-circuited in Enrich with the same triple, and
		// a per-message warning would spam the log for every
		// Tier-0 reject.
		return
	}
	if err := upd.Validate(); err != nil {
		logger.WarnContext(ctx, "evaluate: comm_history.update derived but failed validate",
			slog.String("tenant_id", upd.TenantID),
			slog.String("message_id", upd.MessageID),
			slog.Any("error", err))
		return
	}
	payload, err := json.Marshal(upd)
	if err != nil {
		logger.WarnContext(ctx, "evaluate: comm_history.update marshal failed",
			slog.String("tenant_id", upd.TenantID),
			slog.String("message_id", upd.MessageID),
			slog.Any("error", err))
		return
	}
	if err := sink.Publish(ctx, dto.CommHistoryUpdateSubject, payload,
		events.WithMessageID(upd.DedupID()),
		events.WithCorrelationID(req.CorrelationID),
		events.WithTenantID(upd.TenantID),
		events.WithEventType("management.comm_history.update"),
		events.WithTraceContext(ctx),
	); err != nil {
		logger.WarnContext(ctx, "evaluate: publish comm_history.update failed",
			slog.String("tenant_id", upd.TenantID),
			slog.String("message_id", upd.MessageID),
			slog.Any("error", err))
	}
}
