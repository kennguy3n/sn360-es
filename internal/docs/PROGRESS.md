# SN360-ES Changelog

This file is a release-style changelog for the `sn360-es` repository.
Per-task tracking and exhaustive code pointers live in
[`PHASES.md`](./PHASES.md); the design specification lives in
[`PROPOSAL.md`](./PROPOSAL.md). The project status matrix in the root
[`README.md`](../../README.md#project-status) is the authoritative
view of what is wired vs. optional in the running binary.

---

## Project Status

**Implementation status.** All eight design phases (`PROPOSAL.md`
Section 9) have been implemented as Go packages, with unit tests on
every package, integration tests behind `//go:build integration`, and
a labelled-corpus accuracy + profile harness behind
`//go:build benchmark`. The wiring layer in
`cmd/sn360-es/main.go` was added in a later chunk and composes every
package into a single runnable binary.

**Operational status.** The binary boots end-to-end against the
in-repo `docker-compose.yaml` stack (NATS + PostgreSQL + Redis +
Rspamd + ClamAV). The Tier 1 encoder service (`deployments/encoder/`)
and the Tier 2 SLM service (`deployments/llm/`) are described by
deployment manifests but require model weights and infrastructure
that are out of scope of this repository; until they are running, the
evaluator degrades gracefully and surfaces those tiers as "pending".

### What is wired today

| Area | State |
|---|---|
| HTTP API server, health probes, OpenAPI docs at `/docs` | Wired |
| Middleware chain (telemetry → JWT auth → CORS → request logger) | Wired |
| Banner action, dashboard, education, predict, quarantine, escalation, interstitial handlers | Wired |
| NATS / Redis Streams event bus selectable via `EVENT_BUS` | Wired |
| `es.evaluate.request` consumer (`evaluate-svc` durable, evaluator entry point) | Wired (critical when the evaluator is constructed) |
| `es.evaluate.result` consumers (`management-persist`, `education-trigger`, `ingestion-action`) | Wired (critical when their service deps are present) |
| `es.action.feedback.>` consumer (`feedback-persist`) | Wired (critical when feedback repo present) |
| `es.action.quarantine.release` consumer (`quarantine-release`) | Wired (critical when release service present) |
| `es.action.escalation.>` consumer (`escalation`) | Wired (critical when escalation service present) |
| `es.action.banner` / `.label` / `.url_rewrite` / `.quarantine` provider-side consumers (`action-banner`, `action-label`, `action-url-rewrite`, `action-quarantine`) | Wired (best-effort; degrade to logging when no provider is registered) |
| `es.education.simulation.send` + `.result` consumers (`education-sim`, `education-sim-track`) | Wired (`send` critical, `result` best-effort) |
| `es.onboarding.>` consumer (`ingestion-onboard`) | Wired (best-effort, observe-only until a DirectoryClient is provided) |
| Ingestion polling (Gmail + Outlook `MailboxProvider`s + `Poller` + Redis checkpoint + per-mailbox distributed lock) | Wired (no-op when no provider credentials are configured) |
| AI agents (Onboarding / Tuning / Support) | Wired in `buildAgents` (best-effort; only constructed when their inputs are present) |
| Periodic workers (relationship aggregation 4h, vendor discovery 7d, data cleanup 24h) | Wired in `buildWorkers`; coordinated via Redis distributed lock so only one replica runs each cycle |
| Provider-side label / banner / quarantine / URL-rewrite execution (Gmail import-and-trash, Outlook `PATCH /me/messages/{id}`) | Wired via `pkg/email_provider/{gmail,outlook}/` |
| Distributed Redis lock (`pkg/storage/redis/lock.go`, `SET NX EX` + Lua-scripted Release/Extend) | Wired |
| Tier 1 batch orchestrator (NATS pull-fetch, 50/msg batches, fallback to evaluator) | Wired when `TIER1_BATCH_ENABLED=true` and bus is NATS |
| DLQ processor (`service.DLQProcessor`) on the canonical DLQ subjects | Wired (best-effort, log-only by default) |
| Tier 0 classification gate | Wired (pure CPU) |
| Tier 1 encoder client + Tier 2 SLM client | Wired in process via adapters (`evaluate.Tier1Adapter`, `Tier2HTTPClient`); remote services optional |
| Rspamd client + AI / Rspamd Redis caches | Wired (Rspamd optional via docker-compose) |
| PostgreSQL repositories + golang-migrate runner | Wired (degrades to nil if DSN unset) |
| Privacy layer (Blake2b pseudonymisation, KMS envelope encryption, log sanitiser) | Wired |
| Helm chart + ArgoCD application + ServiceMonitor + migration Job | Manifests committed |
| Benchmarks (`make bench`, `make bench-accuracy`, `make bench-profile`, `make bench-all`, `make gen-corpus`) | Wired |

### Optional / requires external infra

| Item | Notes |
|---|---|
| Tier 1 encoder model weights | `deployments/encoder/` manifests only |
| Tier 2 Ternary-Bonsai-8B SLM | `deployments/llm/` manifests only |
| GWS domain-wide delegation credentials | Required for live polling |
| O365 client credentials | Required for live polling |
| AWS KMS CMK ARNs | Required for production envelope encryption |
| Production JWT signing secret | Required for `/v1/banner/action` tokens in prod |

---

## Changelog

The dates below are commit dates on the `main` branch.

### 2026-05-18 — Provider-side action consumers + ingestion polling + AI agents + periodic workers

- **Provider-side action consumers** (`cmd/sn360-es/main.go`,
  `cmd/sn360-es/providers.go`): four new event subscriptions
  (`es.action.banner`, `.label`, `.url_rewrite`, `.quarantine`)
  routed through a per-tenant `providerRegistry` that maps
  `(tenant_id, provider_kind)` onto the Gmail / Outlook adapters.
  Each consumer skips gracefully when no provider is registered for
  the target tenant so the binary still functions as a pipeline
  processor without provider credentials. Unit tests live in
  `cmd/sn360-es/main_action_consumers_test.go`.
- **Provider clients** (`pkg/email_provider/{gmail,outlook}/`): new
  `BannerInjector`, `QuarantineProvider`, `DirectoryClient`, and
  `MailboxProvider` implementations. Gmail uses the import-and-trash
  pattern for body modification (the Gmail API does not allow
  in-place body edits). Outlook uses `PATCH /me/messages/{id}` and
  Microsoft Graph categories. Every client is covered by
  `httptest`-mocked unit tests.
- **Ingestion polling**
  (`internal/service/ingestion/{poller,normalizer,checkpoint}.go`):
  per-(tenant, mailbox) polling engine with a bounded worker pool, a
  Redis-backed checkpoint store, and a Redis distributed lock that
  prevents two replicas from polling the same mailbox. The
  normalizer strips HTML, pseudonymises addresses, extracts auth
  results (SPF / DKIM / DMARC) from the headers, and computes the
  `RawBodyHash` / `NormalisedHash` pair before publishing
  `es.evaluate.request`.
- **Distributed Redis lock** (`pkg/storage/redis/lock.go`): generic
  `SET NX EX` + Lua-scripted `Release` / `Extend` with value-based
  ownership checks; tested against `miniredis`.
- **AI agents** wired in `buildAgents`: the onboarding agent
  consumes the `DirectoryClient`, the tuning agent consumes the
  evaluation-result repository, and the support agent consumes the
  release / lookup adapters. Each is constructed only when its
  inputs are available so the wiring is graceful by default.
- **Periodic workers** (`internal/service/worker/`): `RelationshipWorker`
  (4h), `VendorWorker` (7d), and `CleanupWorker` (24h) all run
  against a `LockFactory` + `MetricsRecorder` and are started
  alongside the poller from `application.StartBackground(ctx)` on
  the same context as the consumers so SIGTERM cleanly stops them.
- **Telemetry** (`pkg/telemetry/metrics.go`): new counters /
  histograms for ingestion (`ingestion_polled_total`,
  `ingestion_poll_latency_seconds`), actions
  (`action_{label_applied,banner_injected,url_rewritten,quarantine_executed}_total`),
  and periodic workers (`worker_cycle_completed_total`,
  `worker_cycle_latency_seconds`). `ObserveIngestionPoll`,
  `ObserveAction`, `ObserveWorkerCycle` helpers expose them in a
  single call.
- **Health checks** (`cmd/sn360-es/main.go`): `/readyz` now
  reports informational status for the provider registry, the
  ingestion poller, and the configured periodic workers.

### 2026-05-17 — Evaluation pipeline wiring + provider adapters

- `internal/service/evaluate/` adds three HTTP transport adapters
  that close the gap between the multi-tier `Evaluator` and the
  per-tier client packages: `tier1_adapter.go` bridges the existing
  `tier1.Client` onto `evaluate.Tier1Client`; `tier2_http.go` is a new
  OpenAI-compatible client that targets the Ternary-Bonsai-8B server
  exposed by `kennguy3n/llama.cpp` at `POST /v1/chat/completions`;
  `rspamd_http.go` is a standard Rspamd `POST /checkv2` client with
  Password-header auth and score / action / symbol parsing. Each
  adapter has table-driven tests covering happy path, timeout,
  malformed response, and auth header propagation.
- `cmd/sn360-es/main.go` `newApplication()` now instantiates the
  Tier 0 gate unconditionally (pure CPU), the Tier 1 / Tier 2 /
  Rspamd clients conditionally on their URLs being set, and the
  `evaluate.Evaluator` whenever the bus is up — relying on the
  evaluator's existing `markDegraded` path to keep the binary
  bootable even when every remote tier is unreachable. The Tier 1
  encoder health probe is added to `/readyz` when the raw client is
  wired.
- `StartConsumers()` now subscribes the remaining event consumers
  documented in ARCHITECTURE.md §8.4: `es.evaluate.request`
  (`evaluate-svc`, critical), `es.evaluate.result` →
  `ingestion-action` (banner / label / URL-rewrite / quarantine
  fan-out, critical), `es.education.simulation.send` and `.result`,
  `es.onboarding.>`, `es.action.quarantine.release`, and
  `es.action.escalation.>`. An optional Tier 1 batch orchestrator is
  wired behind `TIER1_BATCH_ENABLED=true` when the bus is NATS.
- `internal/service/action/banner_injector.go` introduces the
  `BannerInjector` interface plus a `LoggingBannerInjector` adapter
  so the action consumer chain has a typed seam for downstream
  provider integrations.
- `pkg/email_provider/gmail/label_provider.go` and
  `pkg/email_provider/outlook/label_provider.go` implement the
  `action.LabelProvider` interface against the Gmail REST API
  (`users.labels.create` + `users.messages.modify`) and the
  Microsoft Graph API (`PATCH /me/messages/{id}` for categories),
  both with table-driven tests.
- `internal/service/education/smtp_sender.go` adds an SMTP
  `SimulationSender` (STARTTLS + implicit TLS, RFC 2047 / Q-encoded
  display names, parameterised From / Reply-To); wired into the
  `SimulationEngine` when `SMTP_HOST` + `SMTP_FROM` are configured.
- `cmd/sn360-es/main_consumers_test.go` adds integration tests for
  `handleEvaluateRequest`, `handleIngestionAction`, and the
  `StartConsumers` / `StopConsumers` lifecycle, using a richer
  recording bus + fake Tier 1 / Tier 2 clients.

### 2026-05-17 — Composition + middleware + missing tests

- `cmd/sn360-es/main.go` now composes every package in the repo into
  a single runnable binary: PostgreSQL + Redis bootstrap with health
  probes, repository registry, Tier 0 / Tier 1 / Tier 2 / Rspamd
  clients, AI + Rspamd caches, evaluator + JWT issuer + banner
  renderer + feedback / release services + URL rewriter, education
  micro-lesson + simulation engines, dashboard generator, predict
  (recipient + open) services, escalation service, AI onboarding /
  tuning / support agents, every HTTP handler with a 503 guard when
  dependencies are nil, the middleware chain
  (telemetry → JWT auth → CORS → request logger), two
  `es.evaluate.result` consumers (`management-persist` for the
  Postgres repository and `education-trigger` for the micro-lesson
  service) treated as critical when their dependencies are wired,
  a best-effort `service.DLQProcessor` on the canonical DLQ
  subjects, and a graceful shutdown that closes subscriptions
  before the HTTP server and event bus. The remaining event
  subjects (`es.evaluate.request`, `es.education.simulation.*`,
  `es.action.*`, `es.onboarding.>`, `es.action.feedback.>`) have
  per-package handlers but are NOT yet subscribed in the binary.
- `internal/middleware/` adds the four middleware components
  referenced by `main.go`: `auth.go` (JWT auth with skip-list),
  `cors.go` (configurable origins / methods / headers + preflight),
  `request_logger.go` (sanitised structured access log), and
  `telemetry.go` (Prometheus counter + histogram per route).
- `internal/service/predict/open.go` adds the `OpenService` referenced
  by `PredictHandler`, with table-driven tests in `open_test.go`.
- `internal/handler/` adds the missing handler tests for
  `banner_action`, `dashboard`, `education`, `predict`, `escalation`,
  `quarantine`, and `interstitial`.
- `internal/service/` adds tests for the agent layer (onboarding /
  support / tuning), Tier 1 encoder, onboarding (discovery / oauth),
  action label applier, and the education simulation tracker.
- `internal/middleware/log_sanitizer_test.go` covers email masking,
  subject elision, group attribute recursion, and pass-through of
  non-string attributes.
- `cmd/sn360-es/main_test.go` covers `buildMux` route registration.
- `factoryConfigFromAppConfig` (Redis path) — fixed the
  `FetchBatchSize` source so it reads from `cfg.Redis.FetchBatchSize`
  instead of `cfg.NATS.FetchBatchSize`.

### 2026-05-16 — Benchmarks + corpus

- Labelled email corpus (`scripts/corpus/`, generated via
  `scripts/corpus_generator/` and `cmd/gen-corpus/`) covering 16
  threat categories, 6 tiers, and all 6 relationship categories.
- Accuracy / precision / recall / F1 / confusion-matrix harness
  (`internal/service/evaluate/accuracy_{test,report}.go`) behind
  `//go:build benchmark`.
- Go microbenchmarks for evaluator, scorer, categoriser, Tier 0 gate,
  banner renderer, and education templates / simulation engine.
- Resource profiler (`profile_test.go`,
  `latency_distribution_test.go`) capturing peak heap, GC pauses,
  throughput, p50 / p95 / p99 latency, and a Prometheus-bucket
  histogram.
- Makefile targets `make bench`, `make bench-accuracy`,
  `make bench-profile`, `make bench-all`, `make gen-corpus`, plus
  baseline artefacts under `benchmarks/` and `benchmarks/BASELINE.md`.

### 2026-05-16 — Cross-cutting infrastructure

- `golang-migrate` v4 wrapper at `cmd/sn360-es-migrate/` with the
  `make migrate-up/-down/-check` targets and the initial schema
  (`migrations/0001_init.{up,down}.sql`) for all 13 tables.
- `pkg/storage/{postgres,redis,s3}/` and the `internal/repository/`
  layer (Postgres + in-memory implementations for every domain
  entity).
- `pkg/httpclient/` HTTP/2 pooled client with retry, circuit breaker,
  and per-call timeout, shared by the URL pre-scanner, encoder
  client, SLM client, and tenant API clients.
- `pkg/telemetry/metrics.go` Prometheus counters + histograms for
  banner rendering, banner actions, quarantine releases, URL clicks,
  pre-send prompts, Tier 0 / 1 / 2 verdicts, Rspamd, education
  simulations, and resilience. `/metrics` endpoint wired in
  `cmd/sn360-es/main.go`.
- `api/openapi.yaml` (OpenAPI 3.1) covering every public handler;
  Swagger UI at `/docs` and the raw spec at `/openapi.yaml`
  (`internal/handler/docs.go`).
- `/healthz` and `/readyz` probes with NATS / Redis / PG connectivity
  checks (`internal/handler/health.go`).
- `internal/service/action/subject_tag.go` — opt-in
  `[SN360: WARN]`-style subject prefix at Warning+ tiers.
- `internal/service/cache/{ai,rspamd}_cache_test.go` covering
  serialisation, TTL, and miss paths with miniredis.
- `deployments/helm/sn360-es/` (Deployment, Service, HPA, ConfigMap,
  Secret, ServiceAccount, ServiceMonitor, migration Job, NATS
  subchart) and `deployments/argocd/application.yaml` for dev / qa
  / uat / prod.
- testcontainers-based integration suites under
  `//go:build integration` for NATS, Redis, PostgreSQL, bus factory,
  and an end-to-end pipeline test.
- `docker-compose.yaml` adds ClamAV alongside NATS / Postgres / Redis
  / Rspamd so the attachment pre-screen path runs end-to-end locally.

### 2026-05-16 — Phases 5–8

- **Phase 5**: Quarantine + release flow, banner accessibility
  hardening (WCAG 2.1 AA, RTL support), and banner i18n catalogs for
  Thai, Japanese, Korean, and Simplified Chinese.
- **Phase 6**: Education micro-lessons for all 16 categories with
  locale fallback; phishing simulation engine with campaign
  lifecycle and per-user interaction tracking; resilience scoring
  with Redis caching; adaptive simulation difficulty; parameterised
  template library.
- **Phase 7**: Expanded relationship categories (Partner, Customer,
  FirstTimeExternal, LapsedContact, RecurringService) with Tier 0 /
  Tier 1 modifiers; employee vulnerability scoring; weekly vendor
  auto-discovery; timing anomaly detection.
- **Phase 8**: Pre-send and pre-open add-ins for Outlook + Gmail
  with `POST /v1/predict/{recipient,open}` endpoints; admin
  dashboard summary endpoint with deterministic-fallback narrative;
  user-reported phishing workflow with multi-user aggregation and
  auto-quarantine; SN360 SecOps escalation tickets with
  `/v1/escalation/resolve`; W3C distributed tracing across HTTP +
  NATS; URL pre-scanning (VirusTotal v3); attachment pre-screen
  (YARA + ClamAV).
- Unit tests added for every new service.

### 2026-05-16 — Phases 1–4

- **Phase 1**: NATS JetStream event bus with five canonical streams
  (`ES_EVALUATE`, `ES_ONBOARDING`, `ES_EDUCATION`, `ES_ACTION`,
  `ES_DLQ`), an `EventService` interface, and a Redis-Streams
  fallback selected at runtime by `EVENT_BUS`. Dead-letter routing
  with replay support. Tier 0 classification gates (internal,
  vendor, recurring service, high-volume bypass). Graceful
  degradation orchestrator with per-component circuit breakers and
  weighted score aggregation.
- **Phase 2**: `pkg/privacy/` package (Blake2b pseudonymisation,
  AES-256-GCM per-tenant envelope encryption, AWS KMS wrapper,
  log-sanitisation slog handler, cryptographic erasure). AI result
  cache (1 h TTL) and Rspamd cache (30 m TTL). Redis pipeline
  wrapper for batched tenant config loads.
- **Phase 3**: Tier 1 encoder client (XLM-RoBERTa) with per-tenant
  threshold logic and language-hint extraction. Kubernetes encoder
  inference service (FastAPI + ONNX Runtime + HPA + GPU/CPU
  fallback). Micro-batching using NATS pull fetch (up to 50
  messages) with batch Tier 1 GPU inference and an individual-call
  fallback.
- **Phase 4**: AI Onboarding / Tuning / Support agents with
  role-based sensitivity tiers and FP/FN-driven threshold tuning.
  OAuth auto-onboarding for Google Workspace and Microsoft 365 with
  org-graph discovery (high-risk group identification).
- Unit tests added for tier_decider, banner_renderer (including i18n
  + determinism), auth_verdict, url_rewriter, feedback, categoriser,
  scorer, Tier 0 gate, recurring detector, Blake2 pseudonymiser, and
  JWT issuer.
