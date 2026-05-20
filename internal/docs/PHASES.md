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
  `EVENT_BUS_TYPE` config flag (`pkg/events/factory.go`).
- **Dead-letter routing** — `pkg/events/nats/dlq.go`,
  `internal/service/dlq_processor.go` (DLQ consumer), and
  `internal/service/dlq_alerting.go` (per-tenant burst detection +
  warn-level alerting on sustained NAK loops).

## Detection Pipeline

### Tier 0 — Classification Gate

`internal/service/tier0/` — pure-CPU, sub-millisecond gates:
internal-trusted, vendor-trusted (with compromise detection guard),
recurring service, high-volume sender, first-time-external, and
partner/customer relationship modifiers. The vendor bypass checks
`LooksLikeVendorCompromise` before granting trust — if the signal
is set, the gate force-escalates instead of bypassing ML.

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

### Sensitivity Classifier

`internal/service/agent/sensitivity_classifier.go` — tiered
classification pipeline for user sensitivity (Critical / Max / High /
Elevated / Default) used during onboarding and directory sync:

- **Encoder** — first pass via the Tier 1 encoder model.
- **Bonsai** (optional) — second pass via the Bonsai SLM when
  `SENSITIVITY_BONSAI_URL` is configured. Falls back to encoder-only
  when unset.
- **Keyword fallback** — multilingual keyword matching across English,
  Japanese, Korean, Thai, Vietnamese, and Chinese. The keyword sets
  cover infrastructure-access roles (Critical: DBA, SRE Lead, Cloud
  Admin, Platform Engineer), executive titles (Max: CEO, CFO, Board),
  finance / legal / HR / M&A / R&D roles (High), and procurement /
  admin / DevOps / paralegal roles (Elevated). Activates when ML
  classifiers are unavailable. The five-tier model is persisted via
  `migrations/0012_expand_sensitivity_tiers`.

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
- **GWS setup wizard** — `internal/handler/onboarding_wizard.go` +
  `cmd/sn360-es/gws_setup_checker.go`:
  `GET /v1/onboarding/gws-setup-status?tenant_id={id}` validates
  domain-wide delegation step-by-step (service account, delegated
  admin, domain, directory access, Gmail access) and returns
  human-readable `steps_remaining`.

## Directory Intelligence

### Directory Sync Worker

`internal/service/worker/directory_sync_worker.go` — periodic (6 h)
per-tenant directory synchronisation. Discovers users and groups from
GWS or O365, upserts into the repository, classifies user sensitivity,
and persists the org graph snapshot.

### Delta / Incremental Sync

The `DeltaSyncCapable` interface
(`internal/service/agent/types.go`) enables incremental directory
fetches:

- **O365** — `pkg/email_provider/outlook/directory_client.go`
  implements MS Graph `/users/delta` queries. The delta token is an
  opaque `@odata.deltaLink` URL persisted across runs.
- **GWS** — `pkg/email_provider/gmail/directory_client.go` implements
  incremental sync via the Admin SDK `updatedMin` filter. The delta
  token is an RFC 3339 timestamp.
- **Checkpoint persistence** — `SyncCheckpointRepository`
  (`internal/repository/types.go`) with Postgres and in-memory
  implementations. Migration: `migrations/0008_sync_checkpoints`.
- The `DirectorySyncJob` auto-detects whether the provider supports
  delta sync and falls back to full enumeration on first run or
  when no checkpoint exists.

### Nested Group Resolution (O365)

`pkg/email_provider/outlook/directory_client.go`
`resolveTransitiveGroups` — after the initial `/users` pagination,
a second pass calls `/users/{id}/transitiveMemberOf` for each user
to resolve nested group memberships. Uses bounded concurrency (10
goroutines). Controlled by `O365_RESOLVE_NESTED_GROUPS` (default
`true`); falls back to direct `memberOf` on error.

### Per-User Behavioral Baselines

- **Repository** — `UserBehavioralBaselineRepository`
  (`internal/repository/types.go`) with Postgres and in-memory
  implementations. Tracks per-(user, sender-domain) send-hour
  distributions, device types, and weekly message volume.
  Migration: `migrations/0009_user_behavioral_baselines`.
- **Worker integration** — the relationship aggregation worker
  (`internal/service/worker/relationship_worker.go`) populates
  baselines during its 4 h cycle.
- **Timing anomaly check** — `relationship/timing.go`
  `CheckBaselineAnomaly` compares current message timing against the
  stored per-user baseline.

### Org Graph Persistence

- **Repository** — `OrgGraphRepository`
  (`internal/repository/types.go`) with Postgres and in-memory
  implementations. Stores per-tenant JSONB snapshots with aggregate
  stats (employee, group, department counts, high-risk user IDs).
  Migration: `migrations/0010_org_graphs`.
- **Worker integration** — after directory sync, the worker builds
  the org graph via `onboarding.Project()` and upserts the snapshot.
- **API** — `internal/handler/org_graph.go`:
  `GET /v1/org-graph?tenant_id={id}` returns the stored snapshot.

## Vendor Management

- **Auto-discovery** — `relationship/vendor_discovery.go` — 30-day
  history scan, domain frequency + bidirectional heuristics, weekly
  periodic job.
- **Admin CRUD API** — `internal/handler/vendor.go`:
  - `GET /v1/vendors?tenant_id={id}` — list all vendors (discovered
    + manual, approved + pending).
  - `POST /v1/vendors` — add a manual vendor.
  - `PUT /v1/vendors/{domain}/approve` — approve a vendor.
  - `PUT /v1/vendors/{domain}/revoke` — revoke approval.
  - `DELETE /v1/vendors/{domain}?tenant_id={id}` — remove entirely.
- **Repository** — `VendorRepository`
  (`internal/repository/types.go`) with `List`, `Delete`, `Upsert`,
  `GetByDomain`, `ListApproved` methods, backed by Postgres and
  in-memory implementations.

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
  per-sender hour-of-day baseline with circular distance, plus
  per-user behavioral baseline comparison.

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
- **Push-notification receivers** (implemented, not yet routed) —
  `internal/service/ingestion/push.go` (PushManager + receivers) and
  `internal/handler/push_webhook.go` (`POST /v1/push/{provider}/{tenant}`)
  with Google Pub/Sub OIDC + Microsoft Graph clientState verification
  in `internal/handler/push_signature.go`. The handler is unit-tested
  but the route is intentionally not mounted in
  `cmd/sn360-es/routes.go` yet — see
  [ARCHITECTURE.md §5.1.2](./ARCHITECTURE.md#512-push-notification-receivers-implemented-not-yet-routed).

## Periodic Workers

`internal/service/worker/` — relationship aggregator (4 h), vendor
discovery (7 d), data-retention cleanup (24 h), directory sync (6 h).
Each uses a Redis distributed lock so only one replica runs per cycle.

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
- Middleware chain (outside→in): telemetry → request-id → request-logger
  → CORS → rate-limit → JWT-auth → mux. Each tier short-circuits on
  failure; the JWT layer is skipped only on the paths listed in
  `defaultAuthSkipPaths()` in [`cmd/sn360-es/routes.go`](../../cmd/sn360-es/routes.go):
  `/healthz`, `/readyz`, `/metrics`, `/docs`, `/docs/`, `/openapi.yaml`,
  `/l/`, `/v1/banner/action`, `/v1/quarantine/release`,
  `/v1/education/lesson/`, and `/v1/onboarding/callback`. Every other
  route — including `/v1/predict/*` and the rest of `/v1/onboarding/*`
  (`start`, `status`, `revoke`) — requires a valid JWT.
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

## Operational Prerequisites

The codebase compiles and the binary boots end-to-end, but the
following items are deployment-time concerns:

- **Tier 1 encoder service**: the Python FastAPI service in
  `deployments/encoder/` requires baking the XLM-RoBERTa model weights
  and bringing up the inference pod. The Tier 1 client degrades
  gracefully and forces Tier 2 escalation when unavailable.
- **Tier 2 SLM service**: the Ternary-Bonsai-8B deployment in
  `deployments/llm/` is described by manifests; the model must be
  loaded and the service reachable. The Tier 2 client returns errors
  and the evaluator marks Tier 2 as "pending" when unavailable.
- **Provider OAuth credentials**: GWS domain-wide delegation and O365
  client credentials are required for live polling. Without them the
  ingestion poller is inactive but all HTTP routes remain available.
  The GWS setup wizard at `/v1/onboarding/gws-setup-status` can
  validate the delegation configuration step-by-step.
- **Production secrets**: KMS CMK ARNs, JWT signing secrets, and
  provider client secrets are expected to be injected via AWS Secrets
  Manager in production. The dev path uses local keys from
  `.env.example`.

These are operational tasks that belong in the deployment pipeline.
The [`README.md`](../../README.md#project-status) project status matrix
is the authoritative view of what is wired vs. optional.
