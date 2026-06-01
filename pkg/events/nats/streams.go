package nats

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// Well-known SN360-ES streams. The names are uppercased per JetStream
// convention.
const (
	// StreamEvaluate is the work-queue stream that carries
	// es.evaluate.request[.>] — one worker handles each request.
	StreamEvaluate = "ES_EVALUATE"
	// StreamEvaluateResult is the fan-out stream that carries
	// es.evaluate.result[.>]. The architecture requires three
	// independent consumers (management-persist, education-trigger,
	// ingestion-action) to each see every result message, which is
	// incompatible with the work-queue retention policy on
	// StreamEvaluate (NATS rejects filtered consumers with
	// overlapping subject filters on work-queue streams with
	// err_code=10100 "filtered consumer not unique on workqueue
	// stream"). The fan-out path uses an interest stream instead so
	// every consumer group receives every result and the message is
	// freed only after all groups have acked.
	StreamEvaluateResult = "ES_EVALUATE_RESULT"
	StreamOnboarding     = "ES_ONBOARDING"
	StreamEducation      = "ES_EDUCATION"
	StreamAction         = "ES_ACTION"
	// StreamManagement is the work-queue stream that carries
	// per-message updates into the management Postgres layer
	// (es.management.*). The first consumer is WS-4a's
	// comm-history-update, which records ingestion-time sightings
	// of (tenant, sender, recipient) so the next message from the
	// same sender sees an up-to-date `communication_histories`
	// baseline without waiting for the 4-hour relationship_worker
	// cycle. Work-queue retention is intentional: each sighting
	// has exactly one writer (the in-process repository) and
	// every other consumer of management state reads from
	// Postgres, not from this stream. The dedup window pins
	// idempotency on the Nats-Msg-Id (a deterministic
	// per-(tenant, sender, recipient, message-id) hash assembled
	// by the publisher) so a JetStream redelivery within the
	// window is dropped at the broker rather than producing a
	// double-count at the consumer.
	StreamManagement = "ES_MANAGEMENT"
	StreamDLQ        = "ES_DLQ"
	// StreamPlatform owns the cross-repo `soc.>` namespace. The
	// producer side lives in kennguy3n/sn360-security-platform
	// services/soc-triage, which declares the same name + dedup
	// window in deploy/nats/streams.json — both sides converge on
	// the identical JetStream config via EnsureStream's
	// update-in-place semantic.
	//
	// WS-5A.6 subscribes the durable consumer
	// "ws5a6-escalation-sync" (see
	// cmd/sn360-es/consumers_soc_resolution.go's
	// socResolutionDurable const) to soc.incident.resolved on
	// this stream. Future cross-repo SOC envelopes
	// (soc.incident.created, soc.incident.assigned, ...) can land
	// here without provisioning another stream and tripping
	// JetStream's "subjects overlap with an existing stream" guard.
	// The 600s duplicate window matches the producer's FU-B
	// convention; the consumer-side INSERT-ON-CONFLICT on
	// email_verdict_audit (tenant_id, dedup_id) UNIQUE provides
	// defence-in-depth beyond the broker window.
	StreamPlatform = "sn360-platform"
	// StreamWebhookDLQ owns the `sn360.dlq.webhook.>` namespace
	// used by WS-5B.2 — per-tenant standalone-deployment webhook
	// sinks. Failed customer-endpoint POSTs (5xx / 408 / 429 /
	// network / timeout) are republished onto
	// `sn360.dlq.webhook.<tenant>.<sink>` with a DLQEnvelope
	// (pkg/sinks/webhook). The durable consumer in
	// cmd/sn360-es/consumers_webhook_dlq.go retries with an
	// explicit exponential schedule (1s, 5s, 30s, 5m, 1h) up to
	// 5 deliveries; the WorkQueuePolicy retention is correct
	// here because we want a single retrier (not a fan-out) and
	// successful Acks must free the message immediately.
	//
	// Subject lives under `sn360.*` rather than `es.dlq.*` so it
	// does NOT collide with the existing DLQProcessor's
	// `es.dlq.>` namespace (which serves a different decide-and-
	// republish semantic — see internal/service/dlq_processor.go).
	StreamWebhookDLQ = "SN360_WEBHOOK_DLQ"
)

// StreamSpec describes a JetStream stream that SN360-ES requires.
type StreamSpec struct {
	Name        string
	Subjects    []string
	Retention   jetstream.RetentionPolicy
	Storage     jetstream.StorageType
	MaxAge      time.Duration
	MaxMsgSize  int32
	DedupWindow time.Duration
	Replicas    int
	Discard     jetstream.DiscardPolicy
	Description string
}

// DefaultStreamSpecs returns the canonical set of streams the platform needs.
//
// The proposal in PROPOSAL.md Section 1 defines these. Tests assert on the
// exact configuration produced.
func DefaultStreamSpecs(cfg Config) []StreamSpec {
	storage := jetstream.FileStorage
	if strings.EqualFold(cfg.Storage, "memory") {
		storage = jetstream.MemoryStorage
	}
	replicas := cfg.Replicas
	if replicas <= 0 {
		replicas = 1
	}
	return []StreamSpec{
		{
			Name: StreamEvaluate,
			// Narrowed to request-only subjects so the work-queue
			// retention policy can coexist with the multi-consumer
			// fan-out on es.evaluate.result (which lives on
			// StreamEvaluateResult). Subjects must NOT overlap
			// es.evaluate.result[.>] or NATS will reject
			// StreamEvaluateResult creation with subject-overlap.
			Subjects:    []string{"es.evaluate.request", "es.evaluate.request.>"},
			Retention:   jetstream.WorkQueuePolicy,
			Storage:     storage,
			MaxAge:      24 * time.Hour,
			MaxMsgSize:  10 * 1024 * 1024,
			DedupWindow: orDefault(cfg.DedupWindow, 2*time.Minute),
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES evaluation request pipeline (work-queue, one worker per request)",
		},
		{
			Name: StreamEvaluateResult,
			// Result fan-out. Interest retention means each consumer
			// group receives the message independently, and the
			// message is freed once every interested consumer has
			// acked. This is the canonical NATS pattern for the
			// "par Fan-out" block in the message-flow diagram
			// (ingestion-action || management-persist ||
			// education-trigger).
			Subjects:    []string{"es.evaluate.result", "es.evaluate.result.>"},
			Retention:   jetstream.InterestPolicy,
			Storage:     storage,
			MaxAge:      24 * time.Hour,
			MaxMsgSize:  10 * 1024 * 1024,
			DedupWindow: orDefault(cfg.DedupWindow, 2*time.Minute),
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES evaluation result fan-out (interest, multi-consumer)",
		},
		{
			Name:        StreamOnboarding,
			Subjects:    []string{"es.onboarding.>"},
			Retention:   jetstream.WorkQueuePolicy,
			Storage:     storage,
			MaxAge:      72 * time.Hour,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES tenant / user / group lifecycle events",
		},
		{
			Name:        StreamEducation,
			Subjects:    []string{"es.education.>"},
			Retention:   jetstream.LimitsPolicy,
			Storage:     storage,
			MaxAge:      90 * 24 * time.Hour,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES education / phishing simulation events",
		},
		{
			Name:        StreamAction,
			Subjects:    []string{"es.action.>"},
			Retention:   jetstream.WorkQueuePolicy,
			Storage:     storage,
			MaxAge:      48 * time.Hour,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES post-evaluation action events",
		},
		{
			Name:      StreamManagement,
			Subjects:  []string{"es.management.>"},
			Retention: jetstream.WorkQueuePolicy,
			Storage:   storage,
			// 24h is plenty for an incremental sighting to be
			// re-delivered to the consumer; messages older than
			// the worker's cycle (4h) are redundant anyway because
			// the next relationship_worker pass will recompute
			// authoritative counts from the persisted rows.
			MaxAge:      24 * time.Hour,
			MaxMsgSize:  64 * 1024,
			DedupWindow: orDefault(cfg.DedupWindow, 2*time.Minute),
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES management plane writes (work-queue, per-message)",
		},
		{
			Name: StreamDLQ,
			// Dead-letter subjects live under a separate top-level
			// namespace so they do NOT overlap with the wildcard
			// subjects of the primary streams (es.evaluate.request[.>],
			// es.evaluate.result[.>], es.action.>, etc.). NATS
			// rejects subject overlap between streams.
			Subjects:    []string{"es.dlq.>"},
			Retention:   jetstream.LimitsPolicy,
			Storage:     storage,
			MaxAge:      30 * 24 * time.Hour,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES dead-letter queue (failed events)",
		},
		{
			Name:      StreamWebhookDLQ,
			Subjects:  []string{"sn360.dlq.webhook.>"},
			Retention: jetstream.WorkQueuePolicy,
			Storage:   storage,
			// 7 days easily covers the longest valid retry path
			// (5 deliveries with backoff 1s, 5s, 30s, 5m, 1h ≈ 1h6m
			// wall-clock to final-fail). Keeping a week gives ops
			// time to inspect dead messages before they age out.
			MaxAge:      7 * 24 * time.Hour,
			MaxMsgSize:  10 * 1024 * 1024,
			DedupWindow: orDefault(cfg.DedupWindow, 2*time.Minute),
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360-ES per-tenant standalone webhook DLQ (WS-5B.2; consumer retries with 1s/5s/30s/5m/1h backoff)",
		},
		{
			Name: StreamPlatform,
			// Cross-repo `soc.>` namespace. The producer side
			// (kennguy3n/sn360-security-platform) declares the
			// identical stream in deploy/nats/streams.json; both
			// sides converge on the same JetStream config via
			// EnsureStream's update-in-place semantic. The
			// wildcard root accommodates future cross-repo SOC
			// envelopes without provisioning another stream and
			// tripping JetStream's subject-overlap guard.
			Subjects:  []string{"soc.>"},
			Retention: jetstream.LimitsPolicy,
			Storage:   storage,
			// 24h matches the producer-side stream config.
			MaxAge: 24 * time.Hour,
			// WS-5A.6: 600s duplicate window mirrors FU-B's
			// sn360-events convention on the producer side. The
			// producer stamps Nats-Msg-Id with a length-prefixed
			// sha256(incident_id|resolved_at_unix_nano), so a
			// re-emit within this window is dropped at the
			// broker.
			DedupWindow: orDefault(cfg.DedupWindow, 600*time.Second),
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SN360 cross-repo SOC platform events (e.g. soc.incident.resolved from sn360-security-platform soc-triage)",
		},
	}
}

// EnsureStream creates the stream if it does not exist or updates it in place.
// It is idempotent and safe to call on every startup.
func EnsureStream(ctx context.Context, js jetstream.JetStream, spec StreamSpec) (jetstream.Stream, error) {
	cfg := jetstream.StreamConfig{
		Name:        spec.Name,
		Subjects:    spec.Subjects,
		Retention:   spec.Retention,
		Storage:     spec.Storage,
		MaxAge:      spec.MaxAge,
		MaxMsgSize:  spec.MaxMsgSize,
		Duplicates:  spec.DedupWindow,
		Replicas:    spec.Replicas,
		Discard:     spec.Discard,
		Description: spec.Description,
	}

	_, err := js.Stream(ctx, spec.Name)
	if err == nil {
		updated, uErr := js.UpdateStream(ctx, cfg)
		if uErr != nil {
			// If update is impossible (e.g. subject overlap), surface the error
			// rather than silently using the stale stream.
			return nil, fmt.Errorf("nats: update stream %s: %w", spec.Name, uErr)
		}
		return updated, nil
	}
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return nil, fmt.Errorf("nats: lookup stream %s: %w", spec.Name, err)
	}

	created, cErr := js.CreateStream(ctx, cfg)
	if cErr != nil {
		return nil, fmt.Errorf("nats: create stream %s: %w", spec.Name, cErr)
	}
	return created, nil
}

// EnsureAllStreams ensures every stream in specs exists. Errors aggregate so
// that one bad stream does not prevent inspecting failures in the others.
func EnsureAllStreams(ctx context.Context, js jetstream.JetStream, specs []StreamSpec) error {
	var errs []error
	for _, spec := range specs {
		if _, err := EnsureStream(ctx, js, spec); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// pruneOrphanResultConsumers removes durables on the legacy ES_EVALUATE
// stream that were originally created to consume es.evaluate.result*.
// Before the request / result split those durables were perfectly valid
// — the stream covered es.evaluate.> — but after the split they sit
// idle on the request work-queue stream while the new equivalents take
// delivery from ES_EVALUATE_RESULT. Leaving the old definitions in
// place is harmless functionally (the work-queue stream no longer
// matches the result subjects) but confusing for operators inspecting
// `nats consumer ls`.
//
// The function is best-effort: a missing stream, a consumer with a
// non-result filter subject, or a server that doesn't list consumers
// is left alone. Only durables whose filter is exactly the result
// subject get deleted.
func pruneOrphanResultConsumers(ctx context.Context, js jetstream.JetStream, logger *slog.Logger) error {
	stream, err := js.Stream(ctx, StreamEvaluate)
	if err != nil {
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			return nil
		}
		return fmt.Errorf("lookup %s: %w", StreamEvaluate, err)
	}
	lister := stream.ListConsumers(ctx)
	var orphans []string
	for info := range lister.Info() {
		if info == nil {
			continue
		}
		// Mark for deletion ONLY when EVERY filter subject on the
		// consumer is a result-side subject. The legacy code only
		// ever created single-filter consumers (FilterSubject set,
		// FilterSubjects empty), so the common path is the first
		// branch below. The multi-filter branch defends against a
		// hypothetical future where someone hand-crafts a mixed
		// consumer like FilterSubjects: ["es.evaluate.request",
		// "es.evaluate.result"] — that consumer still serves the
		// request side and must NOT be deleted just because one of
		// its filters happens to be a result subject.
		if info.Config.FilterSubject != "" {
			if isResultFilter(info.Config.FilterSubject) {
				orphans = append(orphans, info.Name)
			}
			continue
		}
		if len(info.Config.FilterSubjects) == 0 {
			continue
		}
		allResult := true
		for _, f := range info.Config.FilterSubjects {
			if !isResultFilter(f) {
				allResult = false
				break
			}
		}
		if allResult {
			orphans = append(orphans, info.Name)
		}
	}
	if err := lister.Err(); err != nil {
		return fmt.Errorf("list consumers on %s: %w", StreamEvaluate, err)
	}
	for _, name := range orphans {
		if err := stream.DeleteConsumer(ctx, name); err != nil {
			if errors.Is(err, jetstream.ErrConsumerNotFound) {
				continue
			}
			logger.WarnContext(ctx, "nats: delete orphan consumer",
				slog.String("stream", StreamEvaluate),
				slog.String("consumer", name),
				slog.Any("error", err))
			continue
		}
		logger.InfoContext(ctx, "nats: removed orphan result consumer",
			slog.String("stream", StreamEvaluate),
			slog.String("consumer", name))
	}
	return nil
}

func isResultFilter(subj string) bool {
	return subj == "es.evaluate.result" || strings.HasPrefix(subj, "es.evaluate.result.")
}

// StreamForSubject returns the stream name that should hold a published
// subject, or "" if none of the known streams cover it. This is used to
// route DLQ publishes back to the correct stream.
//
// Mapping (must stay in sync with DefaultStreamSpecs):
//   - es.dlq.>                       → StreamDLQ
//   - es.evaluate.result | result.>  → StreamEvaluateResult (interest fan-out)
//   - es.evaluate.request | req.>    → StreamEvaluate (work-queue)
//   - es.onboarding.>                → StreamOnboarding
//   - es.education.>                 → StreamEducation
//   - es.action.>                    → StreamAction
//   - es.management.>                → StreamManagement (WS-4a + future
//     management-domain work queues)
//   - soc.>                          → StreamPlatform (cross-repo SOC
//     envelopes from sn360-security-platform, e.g. WS-5A.6 IncidentResolved)
//   - sn360.dlq.webhook.>            → StreamWebhookDLQ (WS-5B.2
//     per-tenant standalone webhook DLQ; the consumer in
//     cmd/sn360-es/consumers_webhook_dlq.go drains with exp backoff)
//
// Any other es.evaluate.* subject (e.g. a hypothetical
// es.evaluate.status) is treated as unrouted and returns "" rather
// than being silently steered to ES_EVALUATE — that would be a stale
// hint now that the stream covers only request[.>], and DLQ re-publish
// would land on a stream that doesn't accept the subject.
func StreamForSubject(subject string) string {
	switch {
	case strings.HasPrefix(subject, "es.dlq."):
		return StreamDLQ
	case subject == "es.evaluate.result" || strings.HasPrefix(subject, "es.evaluate.result."):
		return StreamEvaluateResult
	case subject == "es.evaluate.request" || strings.HasPrefix(subject, "es.evaluate.request."):
		return StreamEvaluate
	case strings.HasPrefix(subject, "es.onboarding."):
		return StreamOnboarding
	case strings.HasPrefix(subject, "es.education."):
		return StreamEducation
	case strings.HasPrefix(subject, "es.action."):
		return StreamAction
	case strings.HasPrefix(subject, "es.management."):
		return StreamManagement
	case subject == "soc" || strings.HasPrefix(subject, "soc."):
		return StreamPlatform
	case strings.HasPrefix(subject, "sn360.dlq.webhook."):
		return StreamWebhookDLQ
	default:
		return ""
	}
}
