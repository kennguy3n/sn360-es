package telemetry

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is the application-wide Prometheus instrument set.
//
// It is intentionally narrow: only the counters and histograms named in
// ARCHITECTURE.md §6.3 ("Prometheus metrics") and PROPOSAL.md §8
// ("Observability") plus the cross-tier latency histograms required for
// SLO tracking. New metrics MUST be added here (not anonymously
// registered) so cardinality and label conventions stay consistent.
//
// All counters / histograms are constructed against a private registry
// when callers pass nil, which keeps tests hermetic. Production code
// should wire prometheus.DefaultRegisterer.
type Metrics struct {
	registry prometheus.Registerer
	gatherer prometheus.Gatherer

	// --- User-facing banner / action counters (ARCHITECTURE §6.3) --
	BannerRendered      *prometheus.CounterVec
	BannerAction        *prometheus.CounterVec
	QuarantineRelease   *prometheus.CounterVec
	URLRewriteClick     *prometheus.CounterVec
	PresendPrompt       *prometheus.CounterVec
	BannerRenderLatency *prometheus.HistogramVec

	// --- Detection pipeline (PROPOSAL §8) --------------------------
	Tier0Bypass     *prometheus.CounterVec
	Tier1Inferences *prometheus.CounterVec
	Tier1Latency    *prometheus.HistogramVec
	// Tier1BatchLegacyPayloadTotal counts every es.evaluate.request
	// message that arrived on the batch consumer in the legacy flat
	// dto.EvaluateRequest shape (instead of the canonical
	// BatchMessage{Request, Signals} wrapper). The orchestrator
	// processes both, but a non-zero rate here means at least one
	// upstream publisher has not migrated and the legacy decoder
	// branch cannot be removed yet. Partitioned by tenant so the
	// operator can pinpoint which publisher fleet still needs to roll.
	Tier1BatchLegacyPayloadTotal *prometheus.CounterVec
	Tier2Escalations             *prometheus.CounterVec
	Tier2Latency                 *prometheus.HistogramVec
	// Tier2Inflight is a scalar gauge tracking the number of Tier 2
	// SLM calls currently in flight on this replica. The evaluator
	// increments before invoking the Tier 2 client and decrements on
	// return (success or error). The WS-6a load harness reads this
	// gauge to capture SLM call concurrency during a scenario run,
	// and the SLO dashboard surfaces it next to Tier2Latency so a
	// queue-up under load is visible at a glance.
	Tier2Inflight    prometheus.Gauge
	RspamdLatency    *prometheus.HistogramVec
	EvaluateLatency  *prometheus.HistogramVec
	EvaluateOutcome  *prometheus.CounterVec
	EvaluateDegraded *prometheus.CounterVec

	// --- Circuit breakers wrapping Tier 1 / Tier 2 / Rspamd -------
	//
	// CircuitBreakerState is a gauge with value 0=closed, 1=open,
	// 2=half_open. Operators alert when any sample stays at >0 for
	// longer than the configured OpenTimeout; the WS-6b chaos
	// regression in tests/chaos/tier2_failure_test.go pins the
	// transition closed → open under sustained Tier 2 failure.
	CircuitBreakerState        *prometheus.GaugeVec
	CircuitBreakerShortCircuit *prometheus.CounterVec

	// --- Education service ----------------------------------------
	SimulationSent  *prometheus.CounterVec
	SimulationClick *prometheus.CounterVec
	ResilienceScore *prometheus.HistogramVec

	// --- Event bus -------------------------------------------------
	EventPublished  *prometheus.CounterVec
	EventConsumed   *prometheus.CounterVec
	EventErrors     *prometheus.CounterVec
	EventLagSeconds *prometheus.GaugeVec
	// NATSSchemaMismatch counts every WS-7c schema-validation
	// rejection, partitioned by subject_family + reason. The
	// `subject_family` label is the registry-matched key (e.g.
	// `es.evaluate.request`, NOT the high-cardinality
	// `es.evaluate.request.t-42`) so the counter stays cheap.
	// Reasons are the [schema.MismatchReason] enum values:
	// `missing_version` (legacy publisher path; emitted for
	// dashboard visibility only — not a DLQ event),
	// `unknown_version` (forward-compat trap — DLQ event),
	// `payload_validation_failure` (shape failure — DLQ event).
	// The `side` label is `publish` or `subscribe` so dashboards
	// can split producer- vs consumer-side failures.
	NATSSchemaMismatch *prometheus.CounterVec

	// --- HTTP server ----------------------------------------------
	HTTPRequests       *prometheus.CounterVec
	HTTPRequestLatency *prometheus.HistogramVec
	RateLimitedTotal   *prometheus.CounterVec
	// RateLimitStoreErrorsTotal counts every rate-limit bucket-store
	// failure, partitioned by backend ("memory", "redis"). An
	// uptick on the redis label is the operator-visible signal that
	// a Redis outage just kicked in and the limiter is either
	// failing open or falling back to per-replica counting.
	RateLimitStoreErrorsTotal *prometheus.CounterVec

	// --- Ingestion polling ----------------------------------------
	IngestionPolled      *prometheus.CounterVec
	IngestionPollLatency *prometheus.HistogramVec

	// --- Provider-side actions ------------------------------------
	ActionLabelApplied       *prometheus.CounterVec
	ActionBannerInjected     *prometheus.CounterVec
	ActionURLRewritten       *prometheus.CounterVec
	ActionQuarantineExecuted *prometheus.CounterVec

	// --- Periodic workers -----------------------------------------
	WorkerCycleCompleted *prometheus.CounterVec
	WorkerCycleLatency   *prometheus.HistogramVec

	// --- Threat-intel feed worker (WS-5B.3) ------------------------
	IntelFeedPolled     *prometheus.CounterVec
	IntelFeedIndicators *prometheus.CounterVec
	IntelFeedLatency    *prometheus.HistogramVec
	IntelFeedStale      *prometheus.CounterVec
	IntelGCDeleted      prometheus.Counter
	IntelTier0Lookups   *prometheus.CounterVec
	IntelTier0Matches   *prometheus.CounterVec
	IntelCacheHits      *prometheus.CounterVec
}

// MetricsConfig configures the metric set. Subsystem maps to Prometheus
// `subsystem`, Namespace to `namespace`. Sane defaults are filled in.
type MetricsConfig struct {
	Namespace  string
	Subsystem  string
	Registerer prometheus.Registerer
	Gatherer   prometheus.Gatherer
}

// NewMetrics constructs a Metrics set and registers each instrument
// against cfg.Registerer (or a new private registry when nil). Already
// registered instruments are returned via prometheus.AlreadyRegisteredError
// recovery so this is safe to call from multiple binaries that share the
// default registerer.
func NewMetrics(cfg MetricsConfig) *Metrics {
	if cfg.Namespace == "" {
		cfg.Namespace = "sn360"
	}
	if cfg.Subsystem == "" {
		cfg.Subsystem = "es"
	}
	reg := cfg.Registerer
	gatherer := cfg.Gatherer
	if reg == nil {
		r := prometheus.NewRegistry()
		reg = r
		if gatherer == nil {
			gatherer = r
		}
	} else if gatherer == nil {
		gatherer = prometheus.DefaultGatherer
	}

	b := builder{ns: cfg.Namespace, sub: cfg.Subsystem, reg: reg}

	m := &Metrics{
		registry: reg,
		gatherer: gatherer,

		BannerRendered: b.counterVec("banner_rendered_total",
			"Banners rendered, partitioned by tier and provider.",
			[]string{"tier", "provider"}),
		BannerAction: b.counterVec("banner_action_total",
			"Banner action button clicks (mark_safe / report / etc).",
			[]string{"tier", "action"}),
		QuarantineRelease: b.counterVec("quarantine_release_total",
			"Quarantine release requests grouped by approver role.",
			[]string{"role", "outcome"}),
		URLRewriteClick: b.counterVec("url_rewrite_click_total",
			"Rewritten URL click-throughs, partitioned by verdict.",
			[]string{"verdict"}),
		PresendPrompt: b.counterVec("presend_prompt_total",
			"Pre-send prompts shown to senders.",
			[]string{"reason"}),
		BannerRenderLatency: b.histogramVec("banner_render_latency_seconds",
			"Latency of banner rendering, end to end.",
			latencyBuckets(),
			[]string{"tier"}),

		Tier0Bypass: b.counterVec("tier0_bypass_total",
			"Tier 0 gate decisions; reason is one of the enum strings.",
			[]string{"reason"}),
		Tier1Inferences: b.counterVec("tier1_inferences_total",
			"Tier 1 encoder inferences, partitioned by verdict.",
			[]string{"verdict"}),
		Tier1BatchLegacyPayloadTotal: b.counterVec("tier1_batch_legacy_payload_total",
			"Tier 1 batch orchestrator received a legacy flat dto.EvaluateRequest payload (publisher has not migrated to BatchMessage), partitioned by tenant.",
			[]string{"tenant"}),
		Tier1Latency: b.histogramVec("tier1_inference_latency_seconds",
			"Tier 1 encoder inference latency.",
			latencyBuckets(),
			[]string{"verdict"}),
		Tier2Escalations: b.counterVec("tier2_escalations_total",
			"Tier 2 LLM escalations, partitioned by outcome.",
			[]string{"outcome"}),
		Tier2Latency: b.histogramVec("tier2_inference_latency_seconds",
			"Tier 2 LLM inference latency.",
			latencyBuckets(),
			[]string{"outcome"}),
		Tier2Inflight: b.gauge("tier2_inflight_requests",
			"Tier 2 SLM calls currently in flight on this replica."),
		RspamdLatency: b.histogramVec("rspamd_latency_seconds",
			"Rspamd scoring latency.",
			latencyBuckets(),
			[]string{"outcome"}),
		EvaluateLatency: b.histogramVec("evaluate_latency_seconds",
			"End-to-end evaluation latency per tier label.",
			latencyBuckets(),
			[]string{"tier"}),
		EvaluateOutcome: b.counterVec("evaluate_outcome_total",
			"Evaluation results, partitioned by tier label.",
			[]string{"tier"}),
		EvaluateDegraded: b.counterVec("evaluate_degraded_total",
			"Number of evaluations that ran in degraded mode.",
			[]string{"service"}),

		CircuitBreakerState: b.gaugeVec("circuit_breaker_state",
			"Circuit breaker state per dependency (0=closed, 1=open, 2=half_open).",
			[]string{"name"}),
		CircuitBreakerShortCircuit: b.counterVec("circuit_breaker_short_circuit_total",
			"Calls short-circuited by an open circuit breaker, partitioned by breaker name.",
			[]string{"name"}),

		SimulationSent: b.counterVec("simulation_sent_total",
			"Phishing simulations sent, partitioned by template.",
			[]string{"template"}),
		SimulationClick: b.counterVec("simulation_click_total",
			"Phishing simulation interactions (click / report / ignore).",
			[]string{"template", "outcome"}),
		ResilienceScore: b.histogramVec("resilience_score",
			"User resilience score distribution.",
			[]float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
			[]string{"cohort"}),

		EventPublished: b.counterVec("event_published_total",
			"Events published to the event bus.",
			[]string{"bus", "stream"}),
		EventConsumed: b.counterVec("event_consumed_total",
			"Events consumed from the event bus.",
			[]string{"bus", "stream"}),
		EventErrors: b.counterVec("event_errors_total",
			"Event bus errors, partitioned by stage.",
			[]string{"bus", "stream", "stage"}),
		EventLagSeconds: b.gaugeVec("event_lag_seconds",
			"Estimated consumer lag in seconds.",
			[]string{"bus", "stream"}),
		NATSSchemaMismatch: b.counterVec("nats_schema_mismatch_total",
			"NATS messages rejected by the WS-7c schema validator (publish or subscribe side), partitioned by subject_family + reason + side.",
			[]string{"subject_family", "reason", "side"}),

		HTTPRequests: b.counterVec("http_requests_total",
			"HTTP requests served, partitioned by method/route/status.",
			[]string{"method", "route", "status"}),
		RateLimitedTotal: b.counterVec("http_rate_limited_total",
			"HTTP requests rejected by the per-IP rate limiter, partitioned by path.",
			[]string{"path"}),
		RateLimitStoreErrorsTotal: b.counterVec("http_rate_limit_store_errors_total",
			"Rate-limit bucket store failures, partitioned by backend (memory|redis).",
			[]string{"backend"}),
		HTTPRequestLatency: b.histogramVec("http_request_latency_seconds",
			"HTTP request latency in seconds, partitioned by method/route.",
			latencyBuckets(),
			[]string{"method", "route"}),

		IngestionPolled: b.counterVec("ingestion_polled_total",
			"Emails polled from provider mailboxes.",
			[]string{"provider", "tenant"}),
		IngestionPollLatency: b.histogramVec("ingestion_poll_latency_seconds",
			"Per-mailbox poll latency.",
			latencyBuckets(),
			[]string{"provider"}),

		ActionLabelApplied: b.counterVec("action_label_applied_total",
			"Labels applied via the provider API.",
			[]string{"provider", "tier"}),
		ActionBannerInjected: b.counterVec("action_banner_injected_total",
			"Banners injected via the provider API.",
			[]string{"provider", "tier"}),
		ActionURLRewritten: b.counterVec("action_url_rewritten_total",
			"URLs rewritten in message bodies via the provider API.",
			[]string{"provider", "tier"}),
		ActionQuarantineExecuted: b.counterVec("action_quarantine_executed_total",
			"Messages quarantined via the provider API.",
			[]string{"provider"}),

		WorkerCycleCompleted: b.counterVec("worker_cycle_completed_total",
			"Periodic worker cycles completed, partitioned by worker name and outcome.",
			[]string{"worker", "outcome"}),
		WorkerCycleLatency: b.histogramVec("worker_cycle_latency_seconds",
			"Periodic worker cycle duration.",
			latencyBuckets(),
			[]string{"worker"}),

		IntelFeedPolled: b.counterVec("intel_feed_poll_total",
			"Threat-intel feed poll attempts, partitioned by feed and outcome (ok|error).",
			[]string{"feed", "outcome"}),
		IntelFeedIndicators: b.counterVec("intel_feed_indicators_total",
			"Indicators upserted by the intel worker, partitioned by feed.",
			[]string{"feed"}),
		IntelFeedLatency: b.histogramVec("intel_feed_poll_latency_seconds",
			"Per-feed poll duration.",
			latencyBuckets(),
			[]string{"feed"}),
		IntelFeedStale: b.counterVec("intel_feed_stale_total",
			"Threat-intel feed crossed the consecutive-failure threshold; the feed is considered stale until the next successful poll.",
			[]string{"feed"}),
		IntelGCDeleted: b.counter("intel_gc_deleted_total",
			"Indicators garbage-collected by the retention sweep."),
		IntelTier0Lookups: b.counterVec("intel_tier0_lookups_total",
			"Tier 0 ti_match lookups, partitioned by outcome (hit|miss|skipped|error).",
			[]string{"outcome"}),
		IntelTier0Matches: b.counterVec("intel_tier0_matches_total",
			"Tier 0 ti_match matches, partitioned by severity tier (block|quarantine|flag).",
			[]string{"tier"}),
		IntelCacheHits: b.counterVec("intel_cache_total",
			"Tier 0 redis negative-cache results, partitioned by outcome (hit|miss|error).",
			[]string{"outcome"}),
	}
	return m
}

// ObserveHTTPRequest records a single completed HTTP request against
// the request counter + latency histogram. The route argument should
// be a low-cardinality template (e.g. "/v1/predict/open"), not the raw
// path with query string or interpolated IDs.
func (m *Metrics) ObserveHTTPRequest(method, route, status string, latencySeconds float64) {
	if m == nil {
		return
	}
	m.HTTPRequests.WithLabelValues(method, route, status).Inc()
	m.HTTPRequestLatency.WithLabelValues(method, route).Observe(latencySeconds)
}

// ObserveIngestionPoll records a completed mailbox poll. count is the
// number of new messages fetched in the cycle; latency is end-to-end
// (lock acquire through publish).
func (m *Metrics) ObserveIngestionPoll(provider, tenant string, count int, latency time.Duration) {
	if m == nil {
		return
	}
	if provider == "" {
		provider = "unknown"
	}
	if tenant == "" {
		tenant = "default"
	}
	if count > 0 {
		m.IngestionPolled.WithLabelValues(provider, tenant).Add(float64(count))
	}
	m.IngestionPollLatency.WithLabelValues(provider).Observe(latency.Seconds())
}

// ObserveAction records a single provider-side action execution.
// kind is one of "label", "banner", "url_rewrite", "quarantine".
func (m *Metrics) ObserveAction(kind, provider, tier string) {
	if m == nil {
		return
	}
	if provider == "" {
		provider = "unknown"
	}
	if tier == "" {
		tier = "unknown"
	}
	switch kind {
	case "label":
		m.ActionLabelApplied.WithLabelValues(provider, tier).Inc()
	case "banner":
		m.ActionBannerInjected.WithLabelValues(provider, tier).Inc()
	case "url_rewrite":
		m.ActionURLRewritten.WithLabelValues(provider, tier).Inc()
	case "quarantine":
		m.ActionQuarantineExecuted.WithLabelValues(provider).Inc()
	}
}

// ObserveSchemaMismatch increments nats_schema_mismatch_total
// with a low-cardinality `subject_family` label (the registry
// key — e.g. `es.evaluate.request` — NOT the per-message subject
// suffix which would include tenant/correlation IDs). `reason`
// matches the [schema.MismatchReason] enum values. `side` is
// either `publish` or `subscribe` so the dashboards can separate
// producer- and consumer-side failures.
//
// Defensive fallbacks (empty -> "unknown") keep the cardinality
// bounded even if a future call site forgets to populate the
// labels.
func (m *Metrics) ObserveSchemaMismatch(subjectFamily, reason, side string) {
	if m == nil {
		return
	}
	if subjectFamily == "" {
		subjectFamily = "unknown"
	}
	if reason == "" {
		reason = "unknown"
	}
	if side == "" {
		side = "unknown"
	}
	m.NATSSchemaMismatch.WithLabelValues(subjectFamily, reason, side).Inc()
}

// ObserveWorkerCycle records a periodic worker cycle outcome. err is
// nil on success; any non-nil err counts as a failure.
func (m *Metrics) ObserveWorkerCycle(worker string, latency time.Duration, err error) {
	if m == nil {
		return
	}
	if worker == "" {
		worker = "unknown"
	}
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	m.WorkerCycleCompleted.WithLabelValues(worker, outcome).Inc()
	m.WorkerCycleLatency.WithLabelValues(worker).Observe(latency.Seconds())
}

// Registerer returns the underlying registerer (useful for sub-component
// wiring).
func (m *Metrics) Registerer() prometheus.Registerer { return m.registry }

// Gatherer returns the underlying gatherer.
func (m *Metrics) Gatherer() prometheus.Gatherer { return m.gatherer }

// HTTPHandler returns an http.Handler exposing the gathered metrics in
// Prometheus exposition format. Wire it under `/metrics`.
func (m *Metrics) HTTPHandler() http.Handler {
	return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
		Registry:      m.registry,
	})
}

// ObserveLatency is a small helper that captures the elapsed time since
// start as a histogram observation. Usage:
//
//	defer m.ObserveLatency(m.EvaluateLatency.WithLabelValues(tier), time.Now())
func (m *Metrics) ObserveLatency(h prometheus.Observer, start time.Time) {
	if h == nil {
		return
	}
	h.Observe(time.Since(start).Seconds())
}

// --- internal helpers -----------------------------------------------------

type builder struct {
	ns, sub string
	reg     prometheus.Registerer
}

func (b builder) counterVec(name, help string, labels []string) *prometheus.CounterVec {
	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: b.ns, Subsystem: b.sub, Name: name, Help: help,
	}, labels)
	return register(b.reg, cv).(*prometheus.CounterVec)
}

// counter constructs an unlabeled prometheus.Counter. Use this for
// scalar event counters that have no partitioning dimension; using
// counterVec with a nil/empty label set is idiomatically equivalent
// but forces every call site through `WithLabelValues()` which is
// noisy and obscures the fact that the metric is scalar.
func (b builder) counter(name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: b.ns, Subsystem: b.sub, Name: name, Help: help,
	})
	return register(b.reg, c).(prometheus.Counter)
}

func (b builder) histogramVec(name, help string, buckets []float64, labels []string) *prometheus.HistogramVec {
	hv := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: b.ns, Subsystem: b.sub, Name: name, Help: help, Buckets: buckets,
	}, labels)
	return register(b.reg, hv).(*prometheus.HistogramVec)
}

func (b builder) gauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: b.ns, Subsystem: b.sub, Name: name, Help: help,
	})
	return register(b.reg, g).(prometheus.Gauge)
}

func (b builder) gaugeVec(name, help string, labels []string) *prometheus.GaugeVec {
	gv := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: b.ns, Subsystem: b.sub, Name: name, Help: help,
	}, labels)
	return register(b.reg, gv).(*prometheus.GaugeVec)
}

func register(reg prometheus.Registerer, c prometheus.Collector) prometheus.Collector {
	err := reg.Register(c)
	if err == nil {
		return c
	}
	if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
		return are.ExistingCollector
	}
	// Fall back to a private registry so a misconfigured shared
	// registry never crashes the service. The instrument is still
	// usable, just not exported on the default endpoint.
	private := prometheus.NewRegistry()
	if rerr := private.Register(c); rerr != nil {
		panic(rerr)
	}
	return c
}

func latencyBuckets() []float64 {
	// 1 ms .. 30 s in roughly logarithmic steps. Matches the SLO
	// budgets quoted in ARCHITECTURE.md §6 (p99 < 1.5 s for Tier 1,
	// < 10 s for Tier 2 LLM).
	return []float64{
		0.001, 0.005, 0.01, 0.025, 0.05, 0.1,
		0.25, 0.5, 1, 2.5, 5, 10, 30,
	}
}

// --- accessors used by services ------------------------------------------

// once-cached helpers so callers don't have to thread `labels` through
// every code path.

// PipelineObserver exposes the subset of metrics the evaluator and tier
// services use. It hides the concrete prometheus types behind a small
// interface so tests can supply a fake.
type PipelineObserver interface {
	ObserveTier0(reason string)
	ObserveTier1(verdict string, latency time.Duration)
	ObserveTier2(outcome string, latency time.Duration)
	ObserveRspamd(outcome string, latency time.Duration)
	ObserveEvaluate(tier string, latency time.Duration)
	ObserveDegraded(service string)
	// ObserveTier2InflightDelta adjusts the Tier 2 SLM in-flight
	// gauge by delta (+1 entering runTier2, -1 on return). Kept on
	// the interface so the evaluator does not need a direct
	// reference to *Metrics — the no-op observer still composes
	// cleanly in test wiring.
	ObserveTier2InflightDelta(delta int)
	// ObserveCircuitBreakerState records the current state of the
	// named circuit breaker. The numeric mapping is fixed by
	// pkg/telemetry/metrics.go::CircuitBreakerStateClosed and
	// friends so dashboards can reference the integer directly.
	ObserveCircuitBreakerState(name string, state int)
	// ObserveCircuitBreakerShortCircuit increments the short-circuit
	// counter for the named breaker. Operators sum this counter
	// across all replicas to detect a sustained open state.
	ObserveCircuitBreakerShortCircuit(name string)
}

// Circuit-breaker state ordinals used by the CircuitBreakerState
// gauge. The values are the same Closed/Open/HalfOpen constants the
// evaluate package uses for [evaluate.State]; we mirror them here to
// keep the telemetry interface independent of the evaluate package.
const (
	CircuitBreakerStateClosed   = 0
	CircuitBreakerStateOpen     = 1
	CircuitBreakerStateHalfOpen = 2
)

type metricsPipelineObserver struct{ m *Metrics }

// PipelineObserver returns a PipelineObserver implementation backed by m.
func (m *Metrics) PipelineObserver() PipelineObserver {
	return &metricsPipelineObserver{m: m}
}

func (p *metricsPipelineObserver) ObserveTier0(reason string) {
	if reason == "" {
		reason = "none"
	}
	p.m.Tier0Bypass.WithLabelValues(reason).Inc()
}
func (p *metricsPipelineObserver) ObserveTier1(verdict string, latency time.Duration) {
	if verdict == "" {
		verdict = "unknown"
	}
	p.m.Tier1Inferences.WithLabelValues(verdict).Inc()
	p.m.Tier1Latency.WithLabelValues(verdict).Observe(latency.Seconds())
}
func (p *metricsPipelineObserver) ObserveTier2(outcome string, latency time.Duration) {
	if outcome == "" {
		outcome = "unknown"
	}
	p.m.Tier2Escalations.WithLabelValues(outcome).Inc()
	p.m.Tier2Latency.WithLabelValues(outcome).Observe(latency.Seconds())
}
func (p *metricsPipelineObserver) ObserveTier2InflightDelta(delta int) {
	if p.m.Tier2Inflight == nil {
		return
	}
	p.m.Tier2Inflight.Add(float64(delta))
}
func (p *metricsPipelineObserver) ObserveRspamd(outcome string, latency time.Duration) {
	if outcome == "" {
		outcome = "ok"
	}
	p.m.RspamdLatency.WithLabelValues(outcome).Observe(latency.Seconds())
}
func (p *metricsPipelineObserver) ObserveEvaluate(tier string, latency time.Duration) {
	if tier == "" {
		tier = "unknown"
	}
	p.m.EvaluateLatency.WithLabelValues(tier).Observe(latency.Seconds())
	p.m.EvaluateOutcome.WithLabelValues(tier).Inc()
}
func (p *metricsPipelineObserver) ObserveDegraded(service string) {
	if service == "" {
		service = "unknown"
	}
	p.m.EvaluateDegraded.WithLabelValues(service).Inc()
}
func (p *metricsPipelineObserver) ObserveCircuitBreakerState(name string, state int) {
	if name == "" {
		name = "unknown"
	}
	p.m.CircuitBreakerState.WithLabelValues(name).Set(float64(state))
}
func (p *metricsPipelineObserver) ObserveCircuitBreakerShortCircuit(name string) {
	if name == "" {
		name = "unknown"
	}
	p.m.CircuitBreakerShortCircuit.WithLabelValues(name).Inc()
}

// NoopPipelineObserver returns a PipelineObserver that does nothing.
// Useful for tests and bootstrapping when no metric set is wired.
func NoopPipelineObserver() PipelineObserver { return noopPipelineObserver{} }

type noopPipelineObserver struct{}

func (noopPipelineObserver) ObserveTier0(string)                      {}
func (noopPipelineObserver) ObserveTier1(string, time.Duration)       {}
func (noopPipelineObserver) ObserveTier2(string, time.Duration)       {}
func (noopPipelineObserver) ObserveTier2InflightDelta(int)            {}
func (noopPipelineObserver) ObserveRspamd(string, time.Duration)      {}
func (noopPipelineObserver) ObserveEvaluate(string, time.Duration)    {}
func (noopPipelineObserver) ObserveDegraded(string)                   {}
func (noopPipelineObserver) ObserveCircuitBreakerState(string, int)   {}
func (noopPipelineObserver) ObserveCircuitBreakerShortCircuit(string) {}

// defaultMetrics is a process-wide lazily-instantiated Metrics set
// shared by code that does not want to thread its own instance through
// every constructor. It uses prometheus.DefaultRegisterer.
var (
	defaultMetricsOnce sync.Once
	defaultMetricsVal  *Metrics
)

// DefaultMetrics returns the process-wide Metrics instance, lazily
// initialising it against prometheus.DefaultRegisterer on first call.
// Tests should always construct a private Metrics via NewMetrics and
// avoid DefaultMetrics for hermeticity.
func DefaultMetrics() *Metrics {
	defaultMetricsOnce.Do(func() {
		defaultMetricsVal = NewMetrics(MetricsConfig{
			Registerer: prometheus.DefaultRegisterer,
			Gatherer:   prometheus.DefaultGatherer,
		})
	})
	return defaultMetricsVal
}
