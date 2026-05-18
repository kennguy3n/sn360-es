package evaluate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
	"github.com/kennguy3n/sn360-es/pkg/events"
	natsevents "github.com/kennguy3n/sn360-es/pkg/events/nats"
)

// BatchTier1Client is the surface area BatchOrchestrator needs from the
// Tier 1 client. The concrete tier1.Client satisfies it.
type BatchTier1Client interface {
	PredictBatch(ctx context.Context, items []tier1.PredictRequest) ([]tier1.PredictResponse, error)
	MaxBatchSize() int
}

// Tier0BatchGate is the (optional) Tier 0 stage applied per-message
// inside the batch. The concrete tier0.Gate satisfies it.
type Tier0BatchGate interface {
	Apply(req dto.EvaluateRequest, signals dto.RiskSignals) (dto.EvaluateResult, bool)
}

// MessageEvaluator is the slow path used when Tier 0 doesn't short
// circuit a message. The evaluate.Evaluator satisfies it.
type MessageEvaluator interface {
	Evaluate(ctx context.Context, req dto.EvaluateRequest, signals dto.RiskSignals) (dto.EvaluateResult, error)
}

// Sink is where the batch orchestrator publishes verdicts (typically
// back onto an `es.action.*` subject). EventService satisfies it.
type Sink interface {
	Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error
}

// BatchOrchestratorConfig configures the orchestrator.
type BatchOrchestratorConfig struct {
	// JS is the JetStream context used to fetch batches. Required.
	JS *natsevents.Client
	// Stream is the JetStream stream name to consume from (default ES_EVALUATE).
	Stream string
	// Consumer is the durable consumer name (default es-evaluate-batch).
	Consumer string
	// Subject filters messages to a single subject (default es.evaluate.request).
	Subject string

	// BatchSize is the upper bound on messages fetched per cycle (default
	// 50). Always capped at the Tier 1 client's MaxBatchSize.
	BatchSize int
	// MaxWait is the per-fetch wait (default 500ms).
	MaxWait time.Duration
	// Tier0 is the optional Tier 0 short-circuit gate. When non-nil,
	// each message is run through it first; bypassed messages skip
	// Tier 1 entirely.
	Tier0 Tier0BatchGate
	// Tier1 is the Tier 1 client. Required.
	Tier1 BatchTier1Client
	// Thresholds maps Tier 1 raw scores to verdicts. Defaulted via
	// tier1.DefaultThresholds() if empty.
	Thresholds tier1.Thresholds
	// Fallback is the slow-path evaluator. When non-nil, the orchestrator
	// invokes it for messages whose Tier 1 verdict is "escalate" so the
	// full multi-tier pipeline (Tier 2 / Rspamd) can run. When nil, the
	// orchestrator simply emits the Tier 1 verdict.
	Fallback MessageEvaluator
	// Categorizer assigns a primary/secondary category + reason codes to
	// the Tier 1-only pass/flag results that don't go through Fallback,
	// mirroring the per-message evaluator.Evaluate aggregation step. Nil
	// is tolerated — the result then carries an empty Primary, which the
	// ingestion-action consumer treats as "no category-driven action".
	Categorizer Categorizer
	// TierDecider maps (score, primary, signals) to the final tier
	// label on Tier 1-only pass/flag results that don't go through
	// Fallback. Required when ResultSubject points at
	// `es.evaluate.result`: downstream consumers
	// (handleIngestionAction at cmd/sn360-es/main.go:1112) skip every
	// banner / label / quarantine action when res.Tier is empty, so
	// batch-path flag verdicts (clear threats, score ≥ flag threshold)
	// would otherwise silently bypass all security actions. Nil is
	// permitted only when the orchestrator emits to a subject the
	// action layer does not consume (e.g. an out-of-process action
	// service that re-derives tier itself).
	TierDecider TierDecider
	// Weights mirrors evaluator.Config.Weights and is applied in
	// aggregateLightweight so a batch-emitted verdict's res.Score is
	// the same weighted aggregate the per-message path would have
	// produced for an identical Tier 1 outcome. Without it, the
	// batch path published `res.Score = tier1Score`, while the
	// per-message path published `res.Score = tier1Score *
	// AI_weight / total_weight` (typically 0.8x), causing the same
	// message to land in a different TierDecider band depending on
	// which consumer happened to handle it. Defaults to
	// DefaultWeights() when zero.
	Weights Weights
	// Sink is where verdicts are emitted. The default ResultSubject
	// is `es.evaluate.result` (mirroring the per-message
	// handleEvaluateRequest path), so the sink only needs to support
	// publishing on that subject; alternative subjects can be set via
	// ResultSubject.
	Sink Sink
	// ResultSubject overrides the default result subject.
	// The orchestrator default is "es.evaluate.result", aligned with
	// the per-message handleEvaluateRequest path so the downstream
	// fan-out (management-persist, education-trigger,
	// ingestion-action) sees batch verdicts on the same subject. Set
	// this explicitly only when routing somewhere else (e.g. a
	// dedicated batch action service).
	ResultSubject string

	// Logger is the structured logger (default slog.Default()).
	Logger *slog.Logger
}

// BatchMessage is the canonical event payload consumed by the batch
// orchestrator. Producers (ingestion-svc, perf-harness) publish this on
// `es.evaluate.request`.
type BatchMessage struct {
	Request dto.EvaluateRequest `json:"request"`
	Signals dto.RiskSignals     `json:"signals"`
}

// BatchOrchestrator pulls messages from JetStream in batches, runs the
// Tier 0 gate, packs surviving messages into a single Tier 1 batch HTTP
// call, applies threshold logic, optionally fans out to the slow-path
// evaluator for escalations, and publishes verdicts to the action sink.
// It is safe for concurrent use but is normally run as a single
// long-lived goroutine per node.
type BatchOrchestrator struct {
	cfg BatchOrchestratorConfig
	log *slog.Logger

	startOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
}

// NewBatchOrchestrator validates cfg and returns a ready orchestrator.
func NewBatchOrchestrator(cfg BatchOrchestratorConfig) (*BatchOrchestrator, error) {
	if cfg.JS == nil {
		return nil, errors.New("evaluate: BatchOrchestrator JS is required")
	}
	if cfg.Tier1 == nil {
		return nil, errors.New("evaluate: BatchOrchestrator Tier1 is required")
	}
	if cfg.Sink == nil {
		// Without a Sink the orchestrator would ack messages and
		// silently drop every verdict — a quiet outage that
		// dashboards / consumers cannot distinguish from "no
		// traffic". Make it a wiring error so the misconfiguration
		// surfaces at startup rather than at the first batch.
		return nil, errors.New("evaluate: BatchOrchestrator Sink is required")
	}
	if cfg.Stream == "" {
		cfg.Stream = "ES_EVALUATE"
	}
	if cfg.Consumer == "" {
		cfg.Consumer = "es-evaluate-batch"
	}
	if cfg.Subject == "" {
		cfg.Subject = "es.evaluate.request"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if maxBatch := cfg.Tier1.MaxBatchSize(); maxBatch > 0 && cfg.BatchSize > maxBatch {
		cfg.BatchSize = maxBatch
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = 500 * time.Millisecond
	}
	if cfg.ResultSubject == "" {
		// Match the single-message handleEvaluateRequest publish
		// target so the downstream consumer fan-out (management-
		// persist, education-trigger, ingestion-action) sees batch
		// verdicts on the same subject as per-message verdicts.
		cfg.ResultSubject = "es.evaluate.result"
	}
	if (cfg.Thresholds == tier1.Thresholds{}) {
		cfg.Thresholds = tier1.DefaultThresholds()
	}
	if (cfg.Weights == Weights{}) {
		// Mirror the per-message evaluator default so a caller who
		// leaves Weights unset (or a future test that constructs the
		// orchestrator with only the required fields) still gets the
		// weighted aggregate documented in the field comment. Without
		// this default, Score()'s zero-weight fallback returned the
		// raw AI score and aggregateLightweight published a tier
		// landed against a different scale than the per-message path.
		cfg.Weights = DefaultWeights()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &BatchOrchestrator{cfg: cfg, log: cfg.Logger, stop: make(chan struct{}), done: make(chan struct{})}, nil
}

// Start launches the orchestrator goroutine. Subsequent calls are
// no-ops.
func (o *BatchOrchestrator) Start(ctx context.Context) {
	o.startOnce.Do(func() {
		go o.run(ctx)
	})
}

// Stop signals the orchestrator to drain and exit. It blocks until the
// loop terminates or ctx fires.
func (o *BatchOrchestrator) Stop(ctx context.Context) error {
	close(o.stop)
	select {
	case <-o.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run is the orchestrator loop. It pulls a batch, processes it, then
// repeats until Stop is called or the context is cancelled.
func (o *BatchOrchestrator) run(ctx context.Context) {
	defer close(o.done)
	for {
		select {
		case <-o.stop:
			return
		case <-ctx.Done():
			return
		default:
		}
		if err := o.processOnce(ctx); err != nil {
			o.log.Error("evaluate: batch cycle failed", slog.String("err", err.Error()))
			// Backoff briefly so we don't tight-loop on a broken downstream.
			select {
			case <-o.stop:
				return
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

// processOnce fetches a single batch and processes it end-to-end.
func (o *BatchOrchestrator) processOnce(ctx context.Context) error {
	msgs, err := o.cfg.JS.FetchBatch(ctx, o.cfg.Stream, o.cfg.Consumer, o.cfg.Subject, o.cfg.BatchSize, o.cfg.MaxWait)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	if len(msgs) == 0 {
		return nil
	}
	o.log.Debug("evaluate: batch received", slog.Int("count", len(msgs)))

	// Decode each message; classify each one through Tier 0; collect
	// the ones that need Tier 1.
	type pending struct {
		msg   events.Message
		req   dto.EvaluateRequest
		sig   dto.RiskSignals
		tier0 dto.EvaluateResult
		hit0  bool
	}
	pendings := make([]pending, 0, len(msgs))
	for _, m := range msgs {
		var bm BatchMessage
		if err := json.Unmarshal(m.Data(), &bm); err != nil {
			o.log.Warn("evaluate: decode failed; nak",
				slog.String("subject", m.Subject()),
				slog.String("err", err.Error()))
			_ = m.Nak(5 * time.Second)
			continue
		}
		p := pending{msg: m, req: bm.Request, sig: bm.Signals}
		if o.cfg.Tier0 != nil {
			if res, hit := o.cfg.Tier0.Apply(bm.Request, bm.Signals); hit {
				p.tier0 = res
				p.hit0 = true
			}
		}
		pendings = append(pendings, p)
	}

	// Build Tier 1 batch from messages that survived Tier 0.
	tier1Inputs := make([]tier1.PredictRequest, 0, len(pendings))
	tier1Indices := make([]int, 0, len(pendings))
	for i, p := range pendings {
		if p.hit0 {
			continue
		}
		tier1Inputs = append(tier1Inputs, tier1.PredictRequest{
			Subject:      p.req.Subject,
			Body:         p.req.Body,
			SenderDomain: p.sig.SenderDomain,
			MessageID:    p.req.MessageID,
		})
		tier1Indices = append(tier1Indices, i)
	}

	var tier1Out []tier1.PredictResponse
	if len(tier1Inputs) > 0 {
		tier1Out, err = o.cfg.Tier1.PredictBatch(ctx, tier1Inputs)
		if err != nil {
			o.log.Error("evaluate: tier1 batch failed",
				slog.Int("count", len(tier1Inputs)),
				slog.String("err", err.Error()))
			// Nak the entire tier 1 group with delay; Tier 0 hits still get
			// acked and published below so we don't waste their work.
			for _, idx := range tier1Indices {
				_ = pendings[idx].msg.Nak(5 * time.Second)
			}
			tier1Out = nil
			// Continue with Tier 0 hits only.
			tier1Indices = nil
		}
	}

	// Apply Tier 1 thresholds, escalate when needed, publish, ack.
	for j, idx := range tier1Indices {
		resp := tier1Out[j]
		t := o.cfg.Thresholds.AdjustForRelationship(pendings[idx].sig.RelationshipCategory)
		verdict := t.Decision(resp.Score)
		res := dto.EvaluateResult{
			TenantID:      pendings[idx].req.TenantID,
			MessageID:     pendings[idx].req.MessageID,
			CorrelationID: pendings[idx].req.CorrelationID,
			EvaluatedAt:   time.Now().UTC(),
			Score:         resp.Score,
			ReasonCodes:   append([]string(nil), resp.ReasonCodes...),
			Tier1: &dto.Tier1Outcome{
				Score:      resp.Score,
				Confidence: resp.Confidence,
				Language:   resp.Language,
				ModelName:  resp.ModelTag,
				Pass:       verdict == tier1.VerdictPass,
				Flag:       verdict == tier1.VerdictFlag,
				Escalate:   verdict == tier1.VerdictEscalate,
			},
		}
		// fallbackRan tracks whether the slow-path evaluator actually
		// replaced `res`. The previous structure used a plain
		// else-branch for the "no Fallback" path, which silently
		// skipped aggregateLightweight when Fallback was wired but
		// returned an error — the exact degraded-mode scenario where
		// downstream consumers still need a fully-formed verdict.
		fallbackRan := false
		if verdict == tier1.VerdictEscalate && o.cfg.Fallback != nil {
			full, err := o.cfg.Fallback.Evaluate(ctx, pendings[idx].req, pendings[idx].sig)
			if err == nil {
				res = full
				fallbackRan = true
			} else {
				o.log.Warn("evaluate: fallback failed",
					slog.String("err", err.Error()),
					slog.String("message_id", pendings[idx].req.MessageID))
			}
		}
		if !fallbackRan {
			// Pass + flag verdicts (and any escalate verdict whose
			// Fallback returned an error or was nil) skip the full
			// evaluator, so we have to populate Score + Primary +
			// Tier ourselves. Without this, downstream consumers
			// like handleIngestionAction reject the result because
			// res.Tier.Valid() is false (zero value) and silently
			// drop every banner / label / URL-rewrite / quarantine
			// action — including the failed-fallback case which is
			// exactly the degraded-mode scenario where the safety
			// net matters most. Mirrors the aggregation step in
			// evaluator.Evaluate (evaluator.go:278-288).
			o.aggregateLightweight(&res, pendings[idx].sig)
		}
		dto.BackfillRoutingFields(&res, pendings[idx].req)
		if err := o.publishResult(ctx, res); err != nil {
			o.log.Error("evaluate: publish result failed", slog.String("err", err.Error()))
			_ = pendings[idx].msg.Nak(5 * time.Second)
			continue
		}
		_ = pendings[idx].msg.Ack()
	}

	// Publish + ack the Tier 0 hits.
	for _, p := range pendings {
		if !p.hit0 {
			continue
		}
		t0 := p.tier0
		dto.BackfillRoutingFields(&t0, p.req)
		if err := o.publishResult(ctx, t0); err != nil {
			o.log.Error("evaluate: publish tier0 result failed", slog.String("err", err.Error()))
			_ = p.msg.Nak(5 * time.Second)
			continue
		}
		_ = p.msg.Ack()
	}
	return nil
}

// aggregateLightweight populates res.Score, res.Primary, res.Secondary,
// res.ReasonCodes, and res.Tier from the Weights, Categorizer, and
// TierDecider when the slow-path Fallback evaluator did not run. It is
// the minimal subset of evaluator.Evaluate's aggregation step
// (evaluator.go:278-288) that batch-only pass / flag verdicts need so
// downstream `es.evaluate.result` consumers see a fully-formed result
// scored on the same scale as per-message verdicts.
//
// Both Categorizer and TierDecider are optional: a nil Categorizer
// leaves Primary empty (downstream gracefully handles the empty
// category); a nil TierDecider leaves Tier as the zero value, which
// is the behaviour callers using a non-`es.evaluate.result` sink may
// deliberately want.
func (o *BatchOrchestrator) aggregateLightweight(res *dto.EvaluateResult, sig dto.RiskSignals) {
	// Recompute the aggregate score with the configured weights so
	// the batch path and per-message path agree on res.Score for an
	// identical Tier 1 outcome. Without this, batch verdicts would
	// publish the raw Tier 1 score (~0-100) while per-message
	// verdicts published the weighted score (~0-80 for Tier 1-only
	// outcomes under DefaultWeights), and any TierDecider band
	// straddling that ratio would classify the same message
	// differently depending on which consumer handled it.
	res.Score = Score(FromResult(res), o.cfg.Weights)
	if o.cfg.Categorizer != nil {
		primary, secondary, reasons := o.cfg.Categorizer.Categorise(*res, sig)
		res.Primary = primary
		res.Secondary = secondary
		if len(reasons) > 0 {
			res.ReasonCodes = append(res.ReasonCodes, reasons...)
		}
	}
	if o.cfg.TierDecider != nil {
		res.Tier = o.cfg.TierDecider.Decide(res.Score, res.Primary, sig)
	}
}

func (o *BatchOrchestrator) publishResult(ctx context.Context, res dto.EvaluateResult) error {
	// Sink is guaranteed non-nil by NewBatchOrchestrator; the early
	// return that used to live here turned a wiring bug (forgetting
	// to set Sink) into a silent verdict drop. The constructor now
	// rejects that case so the runtime path can dereference Sink
	// directly.
	blob, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	// Use the canonical tenant/correlation helpers (not raw
	// WithHeader("tenant_id", …)) so batch verdicts carry the same
	// well-known header keys as the per-message handleEvaluateRequest
	// path — `tenant-id` / `correlation-id` (RFC-style hyphenation),
	// not the underscore form. Downstream consumers
	// (handleEvaluateResult, handleEducationTrigger, handleIngestionAction)
	// read `events.HeaderTenantID` / `events.HeaderCorrelationID`, so a
	// mismatched key would silently fall through to the JSON body
	// lookup and break any bus middleware that operates on canonical
	// headers (e.g. tenant rewriting, tracing exporters, audit logging).
	return o.cfg.Sink.Publish(ctx, o.cfg.ResultSubject, blob,
		events.WithMessageID(res.MessageID),
		events.WithTenantID(res.TenantID),
		events.WithCorrelationID(res.CorrelationID),
		// Mirror the per-message handleEvaluateRequest publish so
		// downstream bus middleware that routes / counts by
		// event-type sees the same `evaluate.result` value on
		// batch-emitted verdicts as on single-message ones.
		events.WithEventType("evaluate.result"),
	)
}
