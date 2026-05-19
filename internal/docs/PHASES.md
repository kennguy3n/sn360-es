# SN360-ES Development History

This document is a concise, narrative history of the SN360-ES
codebase. It captures the major chunks of work that have landed, with
code pointers, so a new contributor can locate the relevant packages
without reading every commit. Per-task changelog entries live in
[`PROGRESS.md`](./PROGRESS.md); the design specification lives in
[`PROPOSAL.md`](./PROPOSAL.md).

**Overall status.** The eight design phases below have all been
implemented as packages in the `sn360-es` Go binary, with full unit
test coverage, integration tests behind `//go:build integration`, and
a labelled corpus + accuracy / profile harness behind
`//go:build benchmark`. The most recent chunk of work (the
"Composition" entry under [Remaining Work](#remaining-work)) closed
the wiring gap between the packages and `cmd/sn360-es/main.go`. The
project status matrix in [`README.md`](../../README.md) lists which
routes / consumers are wired today versus optional / degraded when
their backing infrastructure is missing.

---

## Phase 1 — Event Bus + Detection Foundations

- NATS JetStream client in `pkg/events/nats/` with the canonical streams
  (`ES_EVALUATE`, `ES_ONBOARDING`, `ES_EDUCATION`, `ES_ACTION`,
  `ES_DLQ`), durable consumers, dedup window, file storage, replicas.
- Provider-agnostic `EventService` interface (`pkg/events/interface.go`)
  with NATS and Redis-Streams implementations selected at runtime by
  the `EVENT_BUS` config (`pkg/events/factory.go`).
- Dead-letter routing (`pkg/events/nats/dlq.go`) and DLQ processor
  service (`internal/service/dlq_processor.go`).
- Tier 0 classification gates (`internal/service/tier0/`) covering
  internal-trusted, vendor-trusted, recurring service, high-volume
  sender, first-time-external, and partner/customer relationship
  modifiers — pure CPU, sub-millisecond.
- Graceful-degradation evaluator
  (`internal/service/evaluate/evaluator.go`) with per-component
  circuit breakers (`evaluate/circuit_breaker.go`) and weighted score
  aggregation (`evaluate/scorer.go`).

## Phase 2 — Privacy Layer + Caching

- `pkg/privacy/` package: Blake2b-256 keyed pseudonymisation
  (`pseudonymizer.go`), AES-256-GCM envelope encryption with AWS KMS
  (`encryptor.go`, `kms.go`), top-level orchestration (`privacy.go`),
  data-classification types (`types.go`).
- Log-sanitisation slog handler
  (`internal/middleware/log_sanitizer.go`) backed by regex scrubbers
  in `pkg/privacy/sanitizer.go`.
- Cryptographic erasure on tenant delete (`pkg/privacy/erasure.go` +
  `internal/service/tenant/delete.go`).
- AI result cache (`internal/service/cache/ai_cache.go`, 1 h TTL) and
  Rspamd result cache (`internal/service/cache/rspamd_cache.go`,
  30 m TTL).
- Redis pipeline wrapper for batched config loads
  (`pkg/storage/redis/pipeline.go`).

## Phase 3 — Tier 1 Encoder

- Tier 1 encoder client (`internal/service/tier1/encoder.go`) with
  per-tenant threshold logic, language-hint extraction, and
  individual / batch endpoint negotiation (`tier1/batch.go`).
- K8s inference service (`deployments/encoder/`) — FastAPI + ONNX
  Runtime Python wrapper, GPU pod spec with CPU fallback, HPA on
  queue depth, liveness / readiness probes.
- Micro-batching orchestrator (`internal/service/evaluate/batch.go`)
  using `nats.JetStream.Fetch(batchSize, MaxWait)` to pull up to 50
  messages, group by tenant, batch-load config via Redis pipeline.

## Phase 4 — AI Agents + Auto-Onboarding

- AI Onboarding Agent (`internal/service/agent/onboarding.go`):
  tenant bootstrap, label creation per mailbox, default policy
  seeding, vendor list from 30-day history, group-based sensitivity
  tuning.
- AI Tuning Agent (`agent/tuning.go`): daily FP/FN-rate analysis,
  per-tenant Tier 0 / Tier 1 / score-weight adjustment, audit log
  + metrics.
- AI Support Agent (`agent/support.go`) + HTTP handler
  (`handler/support.go`): user-query explanation, quarantine-release
  flow, SecOps escalation when confidence is low.
- OAuth auto-onboarding for GWS + O365
  (`internal/service/onboarding/`) with encrypted token storage in S3.
- Org-graph builder (`onboarding/org_graph.go`) producing the org
  hierarchy, department mapping, role classifications, and high-risk
  group identification (Finance, C-suite, HR).

## Phase 5 — Tiered UX (Banner + Labels + Quarantine + URL Rewriting)

- 6-tier banner system (`internal/service/action/`): `tier_decider.go`
  (score thresholds + per-tenant overrides + first-contact floor),
  `banner_renderer.go` (deterministic `html/template`, inline CSS,
  no remote assets, dark-mode safe), `banner_i18n.go` (embedded JSON
  catalogs).
- Native provider labels (`action/label_applier.go` +
  `label_colors.go`): Gmail labels + Outlook Master Categories,
  per-tier colours, idempotent creation, lazy sub-labels, label-ID
  caching in Redis (`{provider}:{tenant}:{email}:label:{tier}`).
- 16-category vocabulary (`internal/constant/categories.go`) and
  rule categoriser (`internal/service/evaluate/categorizer.go`)
  producing primary + up to 2 secondaries with deterministic ordering.
- Sender-auth chip (`action/auth_verdict.go`) — SPF / DKIM / DMARC
  aggregate verdict (Verified / Unverified / Failed / Unknown).
- Action token service (`pkg/privacy/jwt.go`) — HS256 JWT,
  per-tenant secret, 7-day TTL, no PII payload.
- One-click feedback endpoint (`internal/handler/banner_action.go`
  + `action/feedback.go`) accepting `report_phishing`, `mark_safe`,
  `trust_sender`; publishes `es.action.feedback.<action>` with
  optional best-effort re-evaluation.
- URL rewriter (`action/url_rewriter.go`) — HighRisk + Blocked
  only, replaces external HTTP(S) `href` values with interstitial
  tokens, preserves quote style, skips `mailto:` / `tel:` /
  `javascript:` / etc., stores encrypted pre-image in Redis with
  30-day TTL.
- Interstitial endpoint (`internal/handler/interstitial.go`) —
  verifies token, optionally re-checks URL against threat intel,
  redirects on safe, renders a block page on unsafe / expired.
- Quarantine + release flow (`action/quarantine.go`,
  `quarantine_release.go`, `handler/quarantine.go`) — hidden
  `SN360 / Blocked` label, stub body, AES-GCM-protected provider
  reference in Redis with TTL, AI Support Agent `ReleaseQuarantine`
  hook with Tier 0 + Tier 1 re-eval,
  `es.action.quarantine.release` events.
- Banner accessibility (WCAG 2.1 AA) — `role="alert"` on HighRisk
  and Blocked, severity-prefixed `aria-label`s, contrast-safe
  6-tier palette, logical focus order, `dir="rtl"` injection for
  RTL locales.
- Banner i18n catalogs (`action/catalogs/{th,ja,ko,zh}.json`) — Thai,
  Japanese, Korean, and Simplified Chinese.

## Phase 6 — Education

- Education micro-lessons (`internal/service/education/micro_lesson.go`,
  `lessons/en.json`) — 30-second, plain-language lesson for each of
  the 16 threat categories; locale fallback to `en`; publishes
  `es.education.lesson.trigger`; served via
  `GET /v1/education/lesson/{category}?locale=en`
  (`internal/handler/education.go`).
- Phishing simulation engine (`education/simulation.go`,
  `simulation_tracker.go`) — campaign lifecycle, per-target dispatch,
  per-user interaction tracking, pseudonymised results, NATS consumer
  for `es.education.simulation.send`, publisher for
  `es.education.simulation.result`.
- Resilience scoring (`education/resilience.go`) —
  `0.40 * simulation_performance + 0.25 * report_rate + 0.20 *
  lesson_engagement + 0.15 * incident_history`; per-user and per-group
  aggregation; Redis cache `tenant:{name}:resilience:{user_hash}`
  with 24 h TTL.
- Adaptive simulation difficulty (`education/adaptive.go`) — Easy /
  Medium / Hard selection from resilience bands.
- Simulation template library (`education/templates.go`) —
  parameterised BEC, credential phishing, QR code, invoice,
  lookalike domain, and ATO templates.

## Phase 7 — Enriched Relationship Intelligence

- Expanded relationship categories
  (`internal/service/relationship/categories.go`) — Partner,
  Customer, FirstTimeExternal, LapsedContact, RecurringService.
- Employee vulnerability scoring
  (`relationship/vulnerability.go`) —
  `0.30 * role_risk + 0.20 * external_volume + 0.10 *
  first_contact_frequency + 0.15 * incident_history + 0.25 *
  inverse_resilience`; Redis cache with 24 h TTL.
- Vendor auto-discovery (`relationship/vendor_discovery.go`) —
  30-day history scan with domain frequency + bidirectional +
  consistent-sender heuristics, confidence-scored auto-approval
  or admin review queue, weekly periodic job.
- Timing anomaly detection (`relationship/timing.go`) —
  per-sender hour-of-day baseline with circular distance.

## Phase 8 — Add-ins, Pre-Send/Pre-Open, Dashboard, Ops

- Pre-send warning (`deployments/addins/outlook/`,
  `deployments/addins/gmail/`, `internal/handler/predict.go`,
  `internal/service/predict/recipient.go`) — lookalike-domain,
  external-on-internal-thread, and unusual-recipient checks;
  pseudonymised inputs; sub-300 ms p95 budget.
- Pre-open warning (`internal/service/predict/open.go`,
  `POST /v1/predict/open` in the same handler) — Warning-tier-or-
  higher modal gating before the message body renders.
- Admin dashboard (`internal/service/dashboard/generator.go`,
  `internal/handler/dashboard.go`, `internal/dto/dashboard.go`) —
  `GET /v1/dashboard/summary?range=7d` aggregating emails processed,
  threats by tier and category, feedback stats, quarantine stats,
  simulation stats, FP / FN rates; AI-generated narrative with a
  deterministic fallback.
- User-reported phishing workflow
  (`internal/service/action/report_workflow.go`) — multi-user
  aggregation with reporter-hash dedup, forced Tier 1 + Tier 2
  re-eval, tenant-wide auto-quarantine when confirmed.
- SN360 SecOps escalation
  (`internal/service/agent/escalation.go`,
  `internal/handler/escalation.go`, `internal/dto/escalation.go`).
- Distributed tracing (`pkg/telemetry/`) — W3C `traceparent`
  propagation across HTTP + NATS, in-memory and OTLP exporters.
- URL pre-scanning (`internal/service/evaluate/url_scanner.go`) —
  bounded-concurrency batch scanner, VirusTotal v3 provider,
  Redis-compatible cache.
- Attachment pre-screen
  (`internal/service/evaluate/attachment_scanner.go`) — YARA engine
  with zero-dep default rules, ClamAV INSTREAM client over TCP,
  oversize and suspicious-extension guards.

## Composition (`cmd/sn360-es/main.go`)

This is the chunk of work that turned all of the above packages into
a runnable binary:

- PostgreSQL connection bootstrap (`pkg/storage/postgres/`) and Redis
  client bootstrap (`pkg/storage/redis/`) wired into the application
  struct with `defer` close + readiness checkers.
- Repository registry instantiated via
  `repository.NewPostgresRegistry(pgDB)` (degrading to nil when the
  DSN is unset).
- Every service constructor from the phases above is invoked with
  the relevant config struct: Tier 0 gate, Tier 1 encoder, Tier 2
  SLM client, Rspamd client, AI + Rspamd caches, evaluator, JWT
  issuer, banner renderer, feedback service, release service, URL
  rewriter, micro-lesson service, simulation engine, dashboard
  generator, recipient + open predictors, escalation service, and
  the AI onboarding / tuning / support agents.
- HTTP handlers from `internal/handler/` registered against `mux`
  with `handler != nil` guards so that routes whose dependencies are
  missing return a clean 503 instead of crashing.
- Middleware chain (telemetry → JWT auth → CORS → request logger)
  from `internal/middleware/` wraps the mux, with the JWT middleware
  skipping `/healthz`, `/readyz`, `/metrics`, `/docs`, and
  `/openapi.yaml`.
- NATS consumers registered before HTTP `ListenAndServe`:
  - `es.evaluate.result` × 2 (durables `management-persist` and
    `education-trigger`) wired in `StartConsumers`. The persist
    consumer is critical when the repository layer is wired and
    the education-trigger consumer is critical when the
    micro-lesson service is wired — `StartConsumers` returns an
    error and the binary fails fast if either subscription fails.
  - `service.DLQProcessor` watches the canonical DLQ subjects
    (`es.evaluate.dlq`, `es.action.dlq`, `es.onboarding.dlq`) and
    logs each failed message. It is best-effort: a failure to
    init or start the processor is logged and the binary keeps
    running without it.
  - `es.onboarding.>` — dispatches `.tenant.created` to the
    onboarding agent, logs `.user.created`, `.user.deleted`, and
    `.vendor.seeded` (informational downstream events).
  - `es.action.escalation.>` — SecOps escalation events from the
    support agent.
  - `es.action.quarantine.release` — quarantine release events
    with `pseudonymized_message_id` field.
  - `es.action.feedback.>` — user feedback events from banner
    actions.
  - The following subjects called out in earlier drafts of this
    document (`es.evaluate.request`, `es.education.simulation.*`)
    are NOT yet wired in `StartConsumers`. Their handlers are
    implemented in the relevant service packages and can be plugged
    in via `eventBus.Subscribe`, but the management binary does not
    do that today — see the [`README.md`](../../README.md#project-status)
    project-status matrix.
- Graceful shutdown closes all subscriptions and the DLQ processor
  before HTTP `Shutdown`, then the event bus / Redis / PG `defer`s
  close out.
- Redis `FetchBatchSize` regression guard
  (`factoryConfigFromAppConfig`) — previously read from
  `cfg.NATS.FetchBatchSize`, now correctly reads from
  `cfg.Redis.FetchBatchSize`.

---

## Cross-Cutting Tracks

| Track | Notes |
|---|---|
| Unit tests | One `_test.go` per package; full coverage of tier decider, auth verdict, categoriser, banner renderer (a11y + RTL + locales), URL rewriter, feedback, scorer, Tier 0 gate, recurring service, pseudonymiser, JWT, quarantine + release, education (lessons, simulation, resilience, adaptive, templates), relationship (categories, vulnerability, vendor, timing), predict (recipient + open), dashboard, report workflow, escalation, telemetry, URL scanner (VirusTotal HTTP), attachment scanner (clamd protocol), AI + Rspamd caches, subject-line tag, Prometheus metrics, and `cmd/sn360-es/buildMux`. |
| Integration tests | testcontainers-based suites for NATS JetStream, Redis pipeline, PostgreSQL + golang-migrate, bus factory (NATS / Redis), and an end-to-end pipeline test. Behind `//go:build integration` and `make test-integration`. |
| Benchmarks | Labelled 1 000-email corpus (`scripts/corpus/`, `scripts/corpus_generator/`) + Go microbenchmarks (`internal/service/evaluate/*_bench_test.go`, `internal/service/tier0/gate_bench_test.go`, `internal/service/action/banner_renderer_bench_test.go`, `internal/service/education/simulation_bench_test.go`) + accuracy / precision / recall / F1 / confusion-matrix harness (`internal/service/evaluate/accuracy_{test,report}.go`, `//go:build benchmark`) + resource profiler (`profile_test.go`, `latency_distribution_test.go`). Run via `make bench`, `make bench-accuracy`, `make bench-profile`, `make bench-all`, `make gen-corpus`. Artefacts and `BASELINE.md` are committed under `benchmarks/`. |
| Lint | `make lint` runs `gofmt -l` and `go vet`. |
| Database migrations | `cmd/sn360-es-migrate/` wraps `golang-migrate` v4; `make migrate-up/-down/-check`; schema in `migrations/0001_init.{up,down}.sql`. |
| Observability | `pkg/telemetry/` provides W3C tracing across HTTP + NATS and Prometheus metrics for banners, pipeline stages, education, and quarantine releases. `/metrics` is exposed by the HTTP server. |
| API documentation | `api/openapi.yaml` documents every public handler; Swagger UI is served at `/docs` and the raw spec at `/openapi.yaml` (`internal/handler/docs.go`). |
| Helm + ArgoCD | `deployments/helm/sn360-es/` with NATS Helm subchart, HPA, ServiceMonitor, migration Job. `deployments/argocd/application.yaml` covers dev / qa / uat / prod. |
| Health / readiness | `/healthz` (liveness) and `/readyz` (NATS / Redis / PG connectivity) in `internal/handler/health.go`, wired into the Helm chart's probes. |

---

## Composition (2026-05-18 update)

The binary now produces and consumes the full pipeline end-to-end
when provider credentials are present, and degrades gracefully when
they are not:

- **Ingestion polling** — `internal/service/ingestion/{poller,normalizer,checkpoint}.go`
  drives per-(tenant, mailbox) polling against a bounded worker pool.
  Each cycle takes a Redis distributed lock
  (`pkg/storage/redis/lock.go`), reads the previous high-water mark
  from the Redis-backed `CheckpointStore`, fetches new messages from
  the appropriate `MailboxProvider`, normalises them (HTML stripping,
  pseudonymisation, hash computation, SPF / DKIM / DMARC extraction),
  publishes `es.evaluate.request`, and advances the checkpoint.
- **Provider-side action consumers** — `cmd/sn360-es/main.go`
  subscribes to `es.action.{label,banner,url_rewrite,quarantine}`
  with `MaxDeliver=3`. Each handler routes through the
  `providerRegistry` (`cmd/sn360-es/providers.go`) keyed by
  `(tenant_id, provider_kind)`. When no provider is registered for a
  tenant the handlers skip the work but ACK the message so the
  pipeline does not back up.
- **Provider clients** — `pkg/email_provider/{gmail,outlook}/`
  hosts the concrete `LabelProvider`, `BannerInjector`,
  `QuarantineProvider`, `DirectoryClient`, and `MailboxProvider`
  implementations. Gmail uses the import-and-trash pattern for body
  modification; Outlook uses `PATCH /me/messages/{id}` via Microsoft
  Graph categories.
- **AI agents** — `buildAgents` constructs the Onboarding / Tuning
  / Support agents on top of `pkg/email_provider` directory clients,
  the evaluation-result repository, and the release / lookup
  adapters. Each is wired when its inputs are present.
- **Periodic workers** — `internal/service/worker/` runs the
  relationship aggregator (4h), the vendor discovery job (7d), and
  the data-retention cleanup job (24h) on a single `Runner`
  abstraction that obtains a distributed lock per worker name so
  only one replica runs each cycle.
- **Health checks** — `/readyz` reports informational status for
  the provider registry, the ingestion poller, and the configured
  periodic workers in addition to the existing event-bus / Postgres
  / Redis / Tier 1 probes. The provider registry check now returns
  an error (degraded) when no tenants are registered.
- **Metrics** — `pkg/telemetry/metrics.go` adds counters and
  histograms for ingestion, actions, and worker cycles (see
  PROGRESS.md changelog for the 2026-05-18 entry).
- **Onboarding service** — `internal/service/onboarding/` is wired
  into the application when `ONBOARDING_STATE_SECRET` and
  `ONBOARDING_CALLBACK_URL` are set plus at least one provider
  credential (GWS or O365). HTTP routes at `/v1/onboarding/{start,
  callback, status, revoke}` delegate to the service via an adapter
  that bridges `handler.OnboardingService` (including the `Status`
  method backed by PostgreSQL user/group counts). The onboarding
  agent receives `es.onboarding.tenant.created` events to kick off
  directory discovery + sensitivity classification + vendor scanning.
  Tokens are encrypted at rest with AES-256-GCM and a
  `ProviderRegistrar` adapter registers runtime Outlook providers
  from OAuth tokens.

## Cross-Cutting Tracks (additions)

| Track | Source of truth |
|---|---|
| Provider-side action execution | `cmd/sn360-es/providers.go`, `pkg/email_provider/{gmail,outlook}/`, `cmd/sn360-es/main_action_consumers_test.go`. |
| Ingestion polling | `internal/service/ingestion/`, `pkg/email_provider/{gmail,outlook}/mailbox_provider.go`. |
| Periodic workers | `internal/service/worker/`, `cmd/sn360-es/main.go` (`buildWorkers`). |
| Distributed locking | `pkg/storage/redis/lock.go`, `pkg/storage/redis/lock_test.go`. |

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
