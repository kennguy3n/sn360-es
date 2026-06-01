// Package webhooksink implements the WS-5B.2 per-tenant standalone
// webhook fan-out: it takes a finalised evaluation verdict, looks
// up the customer-configured sinks for the tenant, applies any
// per-sink event-filter (min tier, primary category), formats the
// payload in the sink's chosen wire format (ECS / CEF), HMAC-signs
// it with the sink's secret, POSTs it via the publisher, and on a
// retriable failure routes a request envelope to the
// `sn360.dlq.webhook.<tenant>.<sink>` JetStream subject for the
// durable retry consumer.
//
// The Dispatcher is best-effort: a sink that errors out, gets rate-
// limited, or 4xx's never fails the originating evaluation. That
// mirrors the SOC-bridge contract on the WS-5A.1 path.
package webhooksink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/sinks/webhook"
)

// SecretEncryptor is the subset of privacy.Encryptor the dispatcher
// needs. Narrowing the dependency lets the dispatcher accept either
// the full envelope-encryption Encryptor or the URL-rewriter's
// action.URLEncryptor (Encrypt + Decrypt only), which is the same
// concrete kmsEncryptor under both names.
type SecretEncryptor interface {
	Encrypt(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, tenantID string, ciphertext []byte) ([]byte, error)
}

// DefaultRatePerMinute is the per-sink rate limit the dispatcher
// applies when the sink's event_filters does not override it. The
// task scope documents 100 req/min as the default.
const DefaultRatePerMinute = 100

// DefaultPublishTimeout is the per-sink budget. 5 seconds is also
// the webhook.HTTPPublisher default; setting it here too keeps the
// dispatcher independent of the publisher's default.
const DefaultPublishTimeout = 5 * time.Second

// MetricRecorder is the thin interface the dispatcher uses to
// emit per-outcome counts without tying itself to a specific
// metrics package. The application wires it through
// internal/telemetry.
type MetricRecorder interface {
	WebhookDispatched(tenantID, sinkID, outcome string)
}

// noopMetrics is used when the wiring code provides no recorder
// (tests, in-memory dev runs).
type noopMetrics struct{}

func (noopMetrics) WebhookDispatched(string, string, string) {}

// RateLimiter is the rate-limiting interface the dispatcher
// consumes. The production implementation is
// *redis.RateBucketStore; tests use a memory or unlimited
// implementation. Returning (true, 0, nil) is the "allow"
// outcome; (false, retry, nil) is "throttled".
type RateLimiter interface {
	Take(ctx context.Context, clientKey string, rate float64, burst int) (bool, time.Duration, error)
}

// unlimitedLimiter never throttles. Used when the dispatcher is
// wired without a Redis-backed rate limiter (tests, dev runs).
type unlimitedLimiter struct{}

func (unlimitedLimiter) Take(context.Context, string, float64, int) (bool, time.Duration, error) {
	return true, 0, nil
}

// Dispatcher fans evaluation verdicts to per-tenant webhook sinks.
type Dispatcher struct {
	repo           repository.WebhookSinkRepository
	encryptor      SecretEncryptor
	publisher      webhook.Publisher
	bus            events.EventService
	limiter        RateLimiter
	metrics        MetricRecorder
	logger         *slog.Logger
	publishTimeout time.Duration
	now            func() time.Time
}

// Config wires a Dispatcher. Repo, Encryptor, Publisher and Bus
// are required — passing nil for any of them is a programming
// error and the constructor returns an error so the wiring path
// fails fast instead of silently no-opping at runtime.
type Config struct {
	Repo      repository.WebhookSinkRepository
	Encryptor SecretEncryptor
	Publisher webhook.Publisher
	// Bus is the JetStream producer the dispatcher uses to
	// republish retriable failures onto
	// sn360.dlq.webhook.<tenant>.<sink>.
	Bus events.EventService
	// Limiter throttles per-(tenant, sink). nil => unlimited.
	Limiter RateLimiter
	// Metrics records per-outcome counts. nil => noop.
	Metrics MetricRecorder
	// Logger is required.
	Logger *slog.Logger
	// PublishTimeout is the per-sink HTTP budget. <= 0 => default
	// 5 seconds.
	PublishTimeout time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

// New builds a Dispatcher.
func New(cfg Config) (*Dispatcher, error) {
	if cfg.Repo == nil {
		return nil, errors.New("webhooksink: Repo is required")
	}
	if cfg.Encryptor == nil {
		return nil, errors.New("webhooksink: Encryptor is required")
	}
	if cfg.Publisher == nil {
		return nil, errors.New("webhooksink: Publisher is required")
	}
	if cfg.Bus == nil {
		return nil, errors.New("webhooksink: Bus is required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("webhooksink: Logger is required")
	}
	limiter := cfg.Limiter
	if limiter == nil {
		limiter = unlimitedLimiter{}
	}
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = noopMetrics{}
	}
	timeout := cfg.PublishTimeout
	if timeout <= 0 {
		timeout = DefaultPublishTimeout
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Dispatcher{
		repo:           cfg.Repo,
		encryptor:      cfg.Encryptor,
		publisher:      cfg.Publisher,
		bus:            cfg.Bus,
		limiter:        limiter,
		metrics:        metrics,
		logger:         cfg.Logger,
		publishTimeout: timeout,
		now:            now,
	}, nil
}

// DispatchVerdict fans res out to every enabled sink for the tenant.
// Returns nil unless the dispatcher couldn't list sinks (which is the
// only failure mode the caller cares about — every per-sink error is
// logged and either dropped (permanent) or republished to the DLQ
// (retriable), so individual sink failures must never propagate).
func (d *Dispatcher) DispatchVerdict(ctx context.Context, res *dto.EvaluateResult) error {
	if res == nil {
		return nil
	}
	if res.TenantID == "" {
		return nil
	}
	sinks, err := d.repo.ListEnabled(ctx, res.TenantID)
	if err != nil {
		return fmt.Errorf("webhooksink: list enabled: %w", err)
	}
	if len(sinks) == 0 {
		return nil
	}
	event := webhook.EventFromEvaluateResult(res)
	if event == nil {
		return nil
	}
	d.dispatchToSinks(ctx, sinks, event, false /* test */)
	return nil
}

// DispatchTestEvent fires a synthetic event against the named sink.
// Used by the POST /v1/tenants/{tid}/webhook-sinks/{id}/test handler
// for end-to-end customer-endpoint verification.
//
// Unlike the verdict path, this method DOES surface per-sink failures
// to the caller — the test endpoint's whole purpose is to tell the
// customer whether their endpoint is reachable + correctly signed.
func (d *Dispatcher) DispatchTestEvent(ctx context.Context, sink *repository.WebhookSink) (webhook.PublishResult, error) {
	if sink == nil {
		return webhook.PublishResult{}, errors.New("webhooksink: sink is required")
	}
	event := d.buildSyntheticEvent(sink.TenantID)
	body, signature, err := d.formatAndSign(ctx, sink, event)
	if err != nil {
		return webhook.PublishResult{}, err
	}
	pubCtx, cancel := context.WithTimeout(ctx, d.publishTimeout)
	defer cancel()
	req := &webhook.Request{
		SinkID:     sink.ID,
		TenantID:   sink.TenantID,
		SinkName:   sink.Name,
		URL:        sink.URL,
		Format:     sink.Format,
		Body:       body,
		Signature:  signature,
		EventType:  webhook.EventTypeEmailEvaluation,
		EventID:    event.EventID,
		OccurredAt: event.OccurredAt,
		Attempt:    1,
	}
	result, perr := d.publisher.Publish(pubCtx, req)
	if perr != nil {
		return result, perr
	}
	d.metrics.WebhookDispatched(sink.TenantID, sink.ID, result.Outcome.String())
	return result, nil
}

// dispatchToSinks is the common fan-out loop used by both the
// verdict and the manual-test paths. The bool toggles the
// per-sink rate-limit gate: synthetic test events skip it because
// the operator deliberately wants to verify the endpoint
// regardless of the production rate budget.
func (d *Dispatcher) dispatchToSinks(ctx context.Context, sinks []repository.WebhookSink, event *webhook.Event, isTest bool) {
	for i := range sinks {
		sink := &sinks[i]
		if d.skipBySinkFilter(sink, event) {
			d.metrics.WebhookDispatched(sink.TenantID, sink.ID, "filtered")
			continue
		}
		if !isTest && !d.takeRateBudget(ctx, sink) {
			d.metrics.WebhookDispatched(sink.TenantID, sink.ID, "rate_limited")
			d.logger.WarnContext(ctx, "webhooksink: rate-limited",
				slog.String("tenant_id", sink.TenantID),
				slog.String("sink_id", sink.ID),
				slog.String("sink_name", sink.Name))
			continue
		}
		d.dispatchOne(ctx, sink, event)
	}
}

// skipBySinkFilter applies the per-sink event_filters JSON: min_tier
// + categories. Returns true if the sink should NOT receive this
// event.
func (d *Dispatcher) skipBySinkFilter(sink *repository.WebhookSink, event *webhook.Event) bool {
	f := sink.EventFilters
	if f.MinTier != "" {
		minTier := constant.Tier(f.MinTier)
		if !minTier.Valid() {
			// Stale / invalid min_tier — log once at debug and
			// drop the filter (fail-open). The CRUD layer
			// validates min_tier on write so this can only
			// happen if a row was edited out-of-band.
			d.logger.Debug("webhooksink: sink has invalid min_tier; ignoring",
				slog.String("sink_id", sink.ID),
				slog.String("min_tier", f.MinTier))
		} else if event.Tier.Severity() < minTier.Severity() {
			return true
		}
	}
	if len(f.Categories) > 0 {
		want := string(event.Primary)
		match := false
		for _, c := range f.Categories {
			if c == want {
				match = true
				break
			}
		}
		if !match {
			return true
		}
	}
	return false
}

// takeRateBudget applies the per-sink rate limiter. Returns true
// on allow, false on throttle.
func (d *Dispatcher) takeRateBudget(ctx context.Context, sink *repository.WebhookSink) bool {
	rpm := sink.EventFilters.RateLimitPerMinute
	if rpm <= 0 {
		rpm = DefaultRatePerMinute
	}
	rate := float64(rpm) / 60.0
	// The bucket key is unique per (tenant, sink) so two sinks for
	// the same tenant share no budget. Tests assert this isolation.
	key := "webhook:" + sink.TenantID + ":" + sink.ID
	allowed, _, err := d.limiter.Take(ctx, key, rate, rpm)
	if err != nil {
		// Rate-limiter error: fail-open so a Redis blip doesn't
		// take the whole webhook surface down. The metric carves
		// these into their own bucket so ops can spot them.
		d.metrics.WebhookDispatched(sink.TenantID, sink.ID, "limiter_error")
		d.logger.WarnContext(ctx, "webhooksink: limiter error; failing open",
			slog.String("sink_id", sink.ID),
			slog.Any("error", err))
		return true
	}
	return allowed
}

// dispatchOne formats, signs and POSTs one event to one sink.
// Routes retriable failures to the DLQ; permanent failures to an
// audit row + metric.
func (d *Dispatcher) dispatchOne(ctx context.Context, sink *repository.WebhookSink, event *webhook.Event) {
	body, signature, err := d.formatAndSign(ctx, sink, event)
	if err != nil {
		d.logger.ErrorContext(ctx, "webhooksink: format/sign failed",
			slog.String("sink_id", sink.ID),
			slog.Any("error", err))
		d.metrics.WebhookDispatched(sink.TenantID, sink.ID, "format_error")
		d.recordDispatchFailedAudit(ctx, sink, event.EventID, "format_sign", "format/sign error: "+err.Error(), 0, 0)
		return
	}
	pubCtx, cancel := context.WithTimeout(ctx, d.publishTimeout)
	defer cancel()
	req := &webhook.Request{
		SinkID:     sink.ID,
		TenantID:   sink.TenantID,
		SinkName:   sink.Name,
		URL:        sink.URL,
		Format:     sink.Format,
		Body:       body,
		Signature:  signature,
		EventType:  webhook.EventTypeEmailEvaluation,
		EventID:    event.EventID,
		OccurredAt: event.OccurredAt,
		Attempt:    1,
	}
	result, perr := d.publisher.Publish(pubCtx, req)
	if perr != nil {
		d.logger.WarnContext(ctx, "webhooksink: publish errored",
			slog.String("sink_id", sink.ID),
			slog.Any("error", perr))
	}
	d.metrics.WebhookDispatched(sink.TenantID, sink.ID, result.Outcome.String())
	switch result.Outcome {
	case webhook.OutcomeSuccess:
		return
	case webhook.OutcomePermanentFailure:
		d.recordDispatchFailedAudit(ctx, sink, event.EventID, "http_permanent", result.Cause, result.HTTPStatus, 1)
		return
	default: // OutcomeRetriable / OutcomeUnknown
		d.routeToDLQ(ctx, sink, req, result, event)
	}
}

// formatAndSign decrypts the HMAC secret, formats the event in the
// sink's wire format, and signs the body. The secret is zeroed
// after signing so a heap dump from a later goroutine cannot
// recover it.
func (d *Dispatcher) formatAndSign(ctx context.Context, sink *repository.WebhookSink, event *webhook.Event) (body []byte, signature string, err error) {
	body, err = webhook.FormatEvent(event, sink.Format)
	if err != nil {
		return nil, "", fmt.Errorf("format: %w", err)
	}
	secret, err := d.encryptor.Decrypt(ctx, sink.TenantID, sink.HMACSecretCiphertext)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt secret: %w", err)
	}
	defer zeroBytes(secret)
	signature, err = webhook.Sign(secret, body)
	if err != nil {
		return nil, "", fmt.Errorf("sign: %w", err)
	}
	return body, signature, nil
}

// routeToDLQ republishes the request envelope onto
// sn360.dlq.webhook.<tenant>.<sink> so the durable consumer can
// retry on the documented exponential schedule.
func (d *Dispatcher) routeToDLQ(ctx context.Context, sink *repository.WebhookSink, req *webhook.Request, result webhook.PublishResult, event *webhook.Event) {
	now := d.now().UTC()
	env := &webhook.DLQEnvelope{
		SchemaVersion: webhook.DLQEnvelopeSchemaVersion,
		SinkID:        sink.ID,
		TenantID:      sink.TenantID,
		SinkName:      sink.Name,
		URL:           sink.URL,
		Format:        sink.Format,
		EventType:     req.EventType,
		EventID:       req.EventID,
		OccurredAt:    req.OccurredAt,
		Body:          req.Body,
		Signature:     req.Signature,
		Attempt:       req.Attempt,
		FirstFailedAt: now,
		LastCause:     result.Cause,
		LastStatus:    result.HTTPStatus,
	}
	blob, mErr := env.Marshal()
	if mErr != nil {
		d.logger.ErrorContext(ctx, "webhooksink: marshal dlq envelope",
			slog.String("sink_id", sink.ID),
			slog.Any("error", mErr))
		d.recordDispatchFailedAudit(ctx, sink, req.EventID, "dlq_marshal", "marshal dlq envelope: "+mErr.Error(), result.HTTPStatus, req.Attempt)
		return
	}
	subject := DLQSubject(sink.TenantID, sink.ID)
	// Use a deterministic dedup ID so a JetStream re-publish (e.g.
	// dispatcher re-runs after a crash) doesn't enqueue duplicate
	// retry envelopes for the same (sink, event, attempt).
	dedup := DedupID(sink.ID, req.EventID, req.Attempt)
	if perr := d.bus.Publish(ctx, subject, blob,
		events.WithMessageID(dedup),
		events.WithTenantID(sink.TenantID),
		events.WithEventType("webhook.dlq"),
	); perr != nil {
		d.logger.ErrorContext(ctx, "webhooksink: dlq publish failed",
			slog.String("sink_id", sink.ID),
			slog.String("subject", subject),
			slog.Any("error", perr))
		d.recordDispatchFailedAudit(ctx, sink, req.EventID, "dlq_publish", "dlq publish failed: "+perr.Error(), result.HTTPStatus, req.Attempt)
		return
	}
	if event != nil {
		// Best-effort; we already logged the dispatch attempt
		// above. The audit row is added by the DLQ consumer when
		// final-fail occurs, not here.
		_ = event
	}
}

// recordDispatchFailedAudit writes a dispatch_failed audit row.
// Reason is bounded and contains no payload bytes. SinkID +
// SinkName + attempt + status are all the audit table carries —
// payloads, secrets, and customer endpoint URLs are never logged.
func (d *Dispatcher) recordDispatchFailedAudit(ctx context.Context, sink *repository.WebhookSink, eventID, stage, cause string, status int, attempt int) {
	reason := cause
	if status > 0 {
		reason = "http=" + strconv.Itoa(status) + " " + reason
	}
	if attempt > 0 {
		reason = "attempt=" + strconv.Itoa(attempt) + " " + reason
	}
	// Audit dedup key is (sink, event, attempt, stage). Without the
	// stage qualifier, two different failure points for the same
	// (sink, event, attempt) would collapse into one row and we'd
	// lose the audit trail for whichever wrote second.
	dedup := sink.ID + "|" + eventID + "|attempt=" + strconv.Itoa(attempt) + "|stage=" + stage
	entry := repository.WebhookSinkAuditEntry{
		TenantID: sink.TenantID,
		SinkID:   sink.ID,
		SinkName: sink.Name,
		Action:   repository.WebhookSinkAuditActionDispatchFailed,
		DedupID:  dedup,
		Reason:   boundReason(reason),
	}
	if aerr := d.repo.AppendAudit(ctx, entry); aerr != nil {
		d.logger.WarnContext(ctx, "webhooksink: audit append failed",
			slog.String("sink_id", sink.ID),
			slog.Any("error", aerr))
	}
}

// buildSyntheticEvent constructs a deterministic-shape test event
// for the POST /webhook-sinks/{id}/test endpoint. The shape mirrors
// a real verdict so the customer's parser exercises the same
// fields it will see in production, but the content makes the
// synthetic origin obvious (Tier: Caution, primary: NEWSLETTER,
// reason: synthetic-test).
func (d *Dispatcher) buildSyntheticEvent(tenantID string) *webhook.Event {
	now := d.now().UTC()
	return &webhook.Event{
		EventID:       uuid.NewString(),
		OccurredAt:    now,
		TenantID:      tenantID,
		MessageID:     "test-" + uuid.NewString(),
		CorrelationID: "test-" + uuid.NewString(),
		Score:         42,
		Tier:          constant.TierCaution,
		Primary:       constant.CategoryNewsletter,
		ReasonCodes:   []string{"synthetic_test"},
		Test:          true,
	}
}

// DLQSubject is the JetStream subject the dispatcher republishes
// retriable failures onto. Exported so the consumer wiring and tests
// can target the same address.
func DLQSubject(tenantID, sinkID string) string {
	return "sn360.dlq.webhook." + tenantID + "." + sinkID
}

// DedupID is the deterministic JetStream Nats-Msg-Id stamped on
// each DLQ envelope. Equal (sink, event, attempt) tuples collapse
// to one in-flight retry message, even across producer restarts.
func DedupID(sinkID, eventID string, attempt int) string {
	return sinkID + "|" + eventID + "|" + strconv.Itoa(attempt)
}

// boundReason caps the cause string written to the audit table to
// 1024 bytes so a misbehaving customer endpoint can't fill the row
// with megabytes of error output.
func boundReason(s string) string {
	const maxLen = 1024
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// zeroBytes overwrites s with zeros. Used to scrub the plaintext
// HMAC secret after signing so a later heap snapshot can't recover
// it.
func zeroBytes(s []byte) {
	for i := range s {
		s[i] = 0
	}
}
