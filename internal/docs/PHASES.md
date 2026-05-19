# SN360-ES Codebase Guide

A contributor-oriented map of the SN360-ES source tree. For the design
rationale behind each subsystem, see [`PROPOSAL.md`](./PROPOSAL.md);
for the runtime topology and data flow, see
[`ARCHITECTURE.md`](./ARCHITECTURE.md). The project status matrix in
[`README.md`](../../README.md#project-status) lists which routes and
consumers are wired today.

---

## Event Bus

- **NATS JetStream client** — `pkg/events/nats/`, canonical streams
  (`ES_EVALUATE`, `ES_ONBOARDING`, `ES_EDUCATION`, `ES_ACTION`,
  `ES_DLQ`), durable consumers, dedup window, file storage, replicas.
- **`EventService` interface** — `pkg/events/interface.go` with NATS
  and Redis Streams implementations selected at runtime by the
  `EVENT_BUS` config flag (`pkg/events/factory.go`).
- **Dead-letter routing** — `pkg/events/nats/dlq.go` and
  `internal/service/dlq_processor.go`.

## Detection Pipeline

### Tier 0 — Classification Gate

`internal/service/tier0/` — pure-CPU, sub-millisecond gates:
internal-trusted, vendor-trusted, recurring service, high-volume
sender, first-time-external, and partner/customer relationship
modifiers.

### Evaluator + Scorer

`internal/service/evaluate/evaluator.go` — graceful-degradation
orchestrator with per-component circuit breakers
(`evaluate/circuit_breaker.go`) and weighted score aggregation
(`evaluate/scorer.go`).

### Tier 1 — Encoder Model

- **Client** — `internal/service/tier1/encoder.go` with per-tenant
  threshold logic, language-hint extraction, and individual / batch
  endpoint negotiation (`tier1/batch.go`).
- **Inference service** — `deployments/encoder/` (FastAPI + ONNX
  Runtime, GPU pod spec with CPU fallback, HPA on queue depth).
- **Micro-batching** — `internal/service/evaluate/batch.go` using
  `nats.JetStream.Fetch(batchSize, MaxWait)` to pull up to 50
  messages, group by tenant, and batch-load config via Redis pipeline.

### Tier 2 — SLM (Ternary-Bonsai-8B)

- **Client** — `internal/service/evaluate/tier2.go` using the shared
  `pkg/httpclient` pool.
- **Deployment** — `deployments/llm/` (multi-stage Dockerfile,
  kennguy3n/llama.cpp fork, GGUF model download via init container).

### Categoriser

`internal/service/evaluate/categorizer.go` — 16-category vocabulary
(`internal/constant/categories.go`), produces primary + up to 2
secondaries with deterministic ordering.

### URL + Attachment Pre-Scanning

- **URL scanner** — `internal/service/evaluate/url_scanner.go`,
  bounded-concurrency batch scanner with VirusTotal v3 provider and
  Redis-compatible cache.
- **Attachment scanner** —
  `internal/service/evaluate/attachment_scanner.go`, YARA engine with
  zero-dep default rules, ClamAV INSTREAM client over TCP, oversize
  and suspicious-extension guards.

## Privacy Layer

- **`pkg/privacy/`** — Blake2b-256 keyed pseudonymisation
  (`pseudonymizer.go`), AES-256-GCM envelope encryption with AWS KMS
  (`encryptor.go`, `kms.go`), data-classification types (`types.go`).
- **Log sanitisation** —
  `internal/middleware/log_sanitizer.go` backed by regex scrubbers in
  `pkg/privacy/sanitizer.go`.
- **Cryptographic erasure** — `pkg/privacy/erasure.go` +
  `internal/service/tenant/delete.go`.

## Caching

- **AI result cache** — `internal/service/cache/ai_cache.go` (1 h
  TTL).
- **Rspamd result cache** — `internal/service/cache/rspamd_cache.go`
  (30 m TTL).
- **Redis pipeline** — `pkg/storage/redis/pipeline.go` for batched
  config loads.

## AI Agents

- **Onboarding Agent** — `internal/service/agent/onboarding.go`:
  tenant bootstrap, label creation per mailbox, default policy
  seeding, vendor list from 30-day history, group-based sensitivity
  tuning.
- **Tuning Agent** — `internal/service/agent/tuning.go`: daily FP/FN
  rate analysis, per-tenant Tier 0 / Tier 1 / score-weight
  adjustment, audit log + metrics.
- **Support Agent** — `internal/service/agent/support.go` +
  `internal/handler/support.go`: user-query explanation,
  quarantine-release flow, SecOps escalation when confidence is low.

## Onboarding Service

- **OAuth flow** — `internal/service/onboarding/` with encrypted
  token storage.
- **Org-graph builder** — `onboarding/org_graph.go` producing the
  org hierarchy, department mapping, role classifications, and
  high-risk group identification (Finance, C-suite, HR).

## Tiered UX (Banners, Labels, Quarantine, URL Rewriting)

### Banner Renderer

`internal/service/action/banner_renderer.go` — deterministic
`html/template`, inline CSS, no remote assets, dark-mode safe. i18n
catalogs in `action/catalogs/{th,ja,ko,zh}.json` (Thai, Japanese,
Korean, Simplified Chinese) plus English default.

### Tier Decider

`internal/service/action/tier_decider.go` — score thresholds with
per-tenant overrides and first-contact floor.

### Label Applier

`internal/service/action/label_applier.go` +
`label_colors.go` — Gmail labels + Outlook Master Categories,
per-tier colours, idempotent creation, lazy sub-labels, label-ID
caching in Redis.

### URL Rewriter

`internal/service/action/url_rewriter.go` — HighRisk + Blocked only,
replaces external HTTP(S) `href` values with interstitial tokens.
Interstitial endpoint at `internal/handler/interstitial.go`.

### Quarantine + Release

`internal/service/action/quarantine.go`, `quarantine_release.go`,
`internal/handler/quarantine.go` — hidden `SN360 / Blocked` label,
stub body, AES-GCM-protected provider reference in Redis, AI Support
Agent release hook with Tier 0 + Tier 1 re-evaluation.

### Sender Auth Chip

`internal/service/action/auth_verdict.go` — SPF / DKIM / DMARC
aggregate verdict (Verified / Unverified / Failed / Unknown).

### Action Token Service

`pkg/privacy/jwt.go` — HS256 JWT, per-tenant secret, 7-day TTL, no
PII payload. Feedback endpoint at `internal/handler/banner_action.go`.

### Accessibility

WCAG 2.1 AA contrast at every tier, `role="alert"` on HighRisk and
Blocked, `dir="rtl"` injection for RTL locales.

## Education

- **Micro-lessons** —
  `internal/service/education/micro_lesson.go`, 30-second plain-
  language lesson for each of the 16 threat categories; locale
  fallback to `en`; served via
  `GET /v1/education/lesson/{category}?locale=en`.
- **Phishing simulation engine** — `education/simulation.go`,
  `simulation_tracker.go` — campaign lifecycle, per-target dispatch,
  per-user interaction tracking, pseudonymised results.
- **Resilience scoring** — `education/resilience.go` —
  `0.40 * simulation_performance + 0.25 * report_rate + 0.20 *
  lesson_engagement + 0.15 * incident_history`.
- **Adaptive difficulty** — `education/adaptive.go` — Easy / Medium /
  Hard selection from resilience bands.
- **Template library** — `education/templates.go` — parameterised
  BEC, credential phishing, QR code, invoice, lookalike domain, and
  ATO templates.

## Relationship Intelligence

- **Categories** — `internal/service/relationship/categories.go`:
  Partner, Customer, FirstTimeExternal, LapsedContact,
  RecurringService.
- **Vulnerability scoring** — `relationship/vulnerability.go`.
- **Vendor auto-discovery** — `relationship/vendor_discovery.go` —
  30-day history scan, domain frequency + bidirectional heuristics,
  weekly periodic job.
- **Timing anomaly detection** — `relationship/timing.go` —
  per-sender hour-of-day baseline with circular distance.

## Pre-Send / Pre-Open Add-Ins

- **Pre-send** — `deployments/addins/outlook/`,
  `deployments/addins/gmail/`, `internal/handler/predict.go`,
  `internal/service/predict/recipient.go` — lookalike-domain,
  external-on-internal-thread, and unusual-recipient checks.
- **Pre-open** — `internal/service/predict/open.go`,
  `POST /v1/predict/open` — Warning-tier-or-higher modal gate.

## Dashboard

`internal/service/dashboard/generator.go`,
`internal/handler/dashboard.go` —
`GET /v1/dashboard/summary?range=7d` aggregating emails processed,
threats by tier and category, feedback stats, quarantine stats,
simulation stats, FP/FN rates. AI-generated narrative with a
deterministic fallback.

## Report Workflow + Escalation

- **User-reported phishing** —
  `internal/service/action/report_workflow.go` — multi-user
  aggregation, forced Tier 1 + Tier 2 re-evaluation, tenant-wide
  auto-quarantine when confirmed.
- **SecOps escalation** —
  `internal/service/agent/escalation.go`,
  `internal/handler/escalation.go`.

## Ingestion

- **Poller** — `internal/service/ingestion/poller.go` — per-(tenant,
  mailbox) polling against a bounded worker pool with Redis
  distributed locking.
- **Normaliser** — `internal/service/ingestion/normalizer.go` —
  HTML stripping, pseudonymisation, hash computation, SPF/DKIM/DMARC
  extraction.
- **Checkpoint** — `internal/service/ingestion/checkpoint.go` —
  Redis-backed high-water mark.
- **Provider clients** — `pkg/email_provider/{gmail,outlook}/` —
  concrete `LabelProvider`, `BannerInjector`, `QuarantineProvider`,
  `DirectoryClient`, and `MailboxProvider` implementations.

## Periodic Workers

`internal/service/worker/` — relationship aggregator (4 h), vendor
discovery (7 d), data-retention cleanup (24 h). Each uses a Redis
distributed lock so only one replica runs per cycle.

## Observability

- **Tracing** — `pkg/telemetry/` — W3C `traceparent` propagation
  across HTTP + NATS, in-memory and OTLP exporters.
- **Metrics** — `pkg/telemetry/metrics.go` — Prometheus counters and
  histograms (namespace `sn360`, subsystem `es`), exposed at
  `GET /metrics`.
- **Health probes** — `internal/handler/health.go` — `/healthz`
  (liveness) and `/readyz` (readiness: NATS / Redis / PG
  connectivity).

## Composition (`cmd/sn360-es/main.go`)

The binary composes every package above into a single runnable
process. Key wiring:

- PostgreSQL + Redis bootstrap with health probes and repository
  registry.
- Every service constructor invoked with the relevant config struct;
  HTTP handlers registered with `handler != nil` guards so missing
  dependencies return 503 instead of crashing.
- Middleware chain: telemetry → JWT auth → CORS → request logger.
- NATS consumers registered before HTTP `ListenAndServe`; graceful
  shutdown closes subscriptions before the HTTP server and event bus.
- Provider-side action consumers
  (`es.action.{banner,label,url_rewrite,quarantine}`) route through
  the `providerRegistry` keyed by `(tenant_id, provider_kind)`.

## Cross-Cutting

| Track | Notes |
|---|---|
| Unit tests | One `_test.go` per package; full coverage of all service, handler, middleware, and privacy packages. |
| Integration tests | testcontainers-based suites for NATS JetStream, Redis pipeline, PostgreSQL + golang-migrate, bus factory, and an end-to-end pipeline test. Behind `//go:build integration` and `make test-integration`. |
| Benchmarks | Labelled 1 000-email corpus + Go microbenchmarks + accuracy / precision / recall / F1 / confusion-matrix harness + resource profiler. Run via `make bench-all`. See [`benchmarks/`](../../benchmarks/). |
| Lint | `make lint` runs `gofmt -l` and `go vet`. |
| Database migrations | `cmd/sn360-es-migrate/` wraps `golang-migrate` v4; `make migrate-up/-down/-check`; schema in `migrations/`. |
| API documentation | `api/openapi.yaml` documents every public handler; Swagger UI at `/docs` and raw spec at `/openapi.yaml`. |
| Helm + ArgoCD | `deployments/helm/sn360-es/` with NATS subchart, HPA, ServiceMonitor, migration Job. `deployments/argocd/application.yaml` covers dev / qa / uat / prod. |

## Remaining Work

The codebase compiles and the binary boots end-to-end, but the
following items are deliberately out of scope of the in-repo work:

- **Tier 1 encoder service**: the Python FastAPI service in
  `deployments/encoder/` is a skeleton — running it requires baking
  the actual XLM-RoBERTa model weights and bringing up the inference
  pod. Until then, the Tier 1 client degrades gracefully and forces
  Tier 2 escalation.
- **Tier 2 SLM service**: the Ternary-Bonsai-8B deployment in
  `deployments/llm/` is described by manifests only. Until the model
  is loaded and the service is reachable, the Tier 2 client returns
  errors and the evaluator marks Tier 2 as "pending".
- **External-provider OAuth credentials**: GWS domain-wide delegation
  and O365 client credentials are required for live polling. Without
  them, the ingestion poller is inactive but the binary still serves
  every HTTP route.
- **Production secrets**: KMS CMK ARNs, JWT signing secrets, provider
  client secrets are expected to be injected via AWS Secrets Manager
  in real deployments; the dev path uses local keys from
  `.env.example`.

These are operational tasks that belong in the deployment pipeline,
not in the codebase. The
[`README.md`](../../README.md#project-status) project status matrix is
the authoritative view of what is wired vs. optional.
