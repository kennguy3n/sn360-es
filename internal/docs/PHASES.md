# SN360-ES Implementation Phases

Phase-level rollup of the v2 platform. Detailed per-task status is tracked in
[`PROGRESS.md`](./PROGRESS.md); the canonical specification lives in
[`PROPOSAL.md`](./PROPOSAL.md) Section 9. This document summarises *what*
each phase delivers and where to find the code.

**Overall status:** 51 / 51 tasks complete (100%). All phases complete.

---

## Phase 1 — Event Bus + Detection Foundations &nbsp;✅ COMPLETE (6 / 6)

Deliverables:

- NATS JetStream client (`pkg/events/nats/`) with the 5 canonical streams
  (`ES_EVALUATE`, `ES_ONBOARDING`, `ES_EDUCATION`, `ES_ACTION`, `ES_DLQ`),
  durable consumers, dedup window, file storage, replicas.
- Provider-agnostic `EventService` interface (`pkg/events/interface.go`)
  with both NATS and Redis-Streams implementations, selected at runtime by
  the `EVENT_BUS_TYPE` feature flag (`pkg/events/factory.go`).
- Dead-letter routing (`pkg/events/nats/dlq.go`) and the DLQ processor
  service (`internal/service/dlq_processor.go`).
- Tier 0 classification gates (`internal/service/tier0/`) covering
  internal-trusted, vendor-trusted, recurring service, high-volume sender,
  first-time-external and partner/customer relationship modifiers — all
  pure CPU, <1 ms.
- Graceful-degradation orchestrator (`internal/service/evaluate/evaluator.go`)
  with per-component circuit breakers (`evaluate/circuit_breaker.go`) and
  weighted score aggregation (`evaluate/scorer.go`).

## Phase 2 — Privacy Layer + Caching &nbsp;✅ COMPLETE (8 / 8)

Deliverables:

- `pkg/privacy/` package: Blake2b-256 keyed pseudonymisation
  (`pseudonymizer.go`), AES-256-GCM envelope encryption with AWS KMS
  (`encryptor.go`, `kms.go`), top-level orchestration (`privacy.go`),
  data-classification types (`types.go`).
- Log-sanitisation slog handler (`internal/middleware/log_sanitizer.go`)
  backed by regex-based scrubbers in `pkg/privacy/sanitizer.go`.
- Cryptographic erasure on tenant delete (`pkg/privacy/erasure.go` +
  `internal/service/tenant/delete.go`).
- AI result cache (`internal/service/cache/ai_cache.go`, 1 h TTL) and
  Rspamd result cache (`internal/service/cache/rspamd_cache.go`, 30 m
  TTL).
- Redis pipeline wrapper for batched config loads
  (`pkg/storage/redis/pipeline.go`).

## Phase 3 — Tier 1 Encoder &nbsp;✅ COMPLETE (4 / 4)

Deliverables:

- Tier 1 encoder client (`internal/service/tier1/encoder.go`) with
  per-tenant threshold logic, language-hint extraction, and individual /
  batch endpoint negotiation (`tier1/batch.go`).
- K8s inference service (`deployments/encoder/`) — FastAPI + ONNX Runtime
  Python wrapper, GPU pod spec with CPU fallback, HPA on queue depth,
  liveness/readiness probes.
- Micro-batching orchestrator (`internal/service/evaluate/batch.go`)
  using `nats.JetStream.Fetch(batchSize, MaxWait)` to pull up to 50
  messages, group by tenant, batch-load config via Redis pipeline.

## Phase 4 — AI Agents + Auto-Onboarding &nbsp;✅ COMPLETE (5 / 5)

Deliverables:

- AI Onboarding Agent (`internal/service/agent/onboarding.go`): tenant
  bootstrap, label creation per mailbox, default policy seeding, vendor
  list from 30-day history, group-based sensitivity tuning.
- AI Tuning Agent (`agent/tuning.go`): daily FP/FN-rate analysis,
  per-tenant Tier 0 / Tier 1 / score-weight adjustment, audit log + metrics.
- AI Support Agent (`agent/support.go`) + HTTP handler (`handler/support.go`):
  user-query explanation, quarantine-release flow, SecOps escalation when
  confidence is low.
- OAuth auto-onboarding for GWS + O365 (`internal/service/onboarding/`)
  with encrypted token storage in S3.
- Org-graph builder (`onboarding/org_graph.go`) producing the org
  hierarchy, department mapping, role classifications, and high-risk
  group identification (Finance, C-suite, HR).

## Phase 5 — Tiered UX &nbsp;✅ COMPLETE (11 / 11)

Deliverables:

- 6-tier banner system (`internal/service/action/`): `tier_decider.go`
  (score thresholds + per-tenant overrides + first-contact floor),
  `banner_renderer.go` (deterministic Go `html/template`, inline CSS,
  no remote assets, dark-mode safe), `banner_i18n.go` (embedded JSON
  catalogs).
- Native provider labels (`action/label_applier.go` +
  `label_colors.go`): Gmail labels + Outlook Master Categories, per-tier
  colours, idempotent creation, lazy sub-labels, label-ID caching in
  Redis (`{provider}:{tenant}:{email}:label:{tier}`).
- 16-category vocabulary (`internal/constant/categories.go`) and rule
  categorizer (`internal/service/evaluate/categorizer.go`) producing
  primary + up to 2 secondaries with deterministic ordering.
- Sender-auth chip (`action/auth_verdict.go`) — SPF / DKIM / DMARC
  aggregate verdict (Verified / Unverified / Failed / Unknown).
- Action token service (`pkg/privacy/jwt.go`) — HS256 JWT, per-tenant
  secret, 7-day TTL, no PII payload.
- One-click feedback endpoint (`internal/handler/banner_action.go` +
  `action/feedback.go`) accepting `report_phishing`, `mark_safe`,
  `trust_sender`; publishes `es.action.feedback.<action>` with optional
  best-effort re-evaluation for `mark_safe` / `trust_sender`.
- URL rewriter (`action/url_rewriter.go`) — High Risk + Blocked only,
  replaces external HTTP(S) `href` values with interstitial tokens,
  preserves quote style, skips `mailto:` / `tel:` / `javascript:` / etc.,
  stores encrypted pre-image in Redis with 30-day TTL.
- Interstitial endpoint (`internal/handler/interstitial.go`) — verifies
  token, optionally re-checks URL against threat intel, redirects on
  safe, renders a block page on unsafe / expired.
- Quarantine + release flow (`action/quarantine.go`,
  `quarantine_release.go`, `handler/quarantine.go`) — hidden
  `SN360 / Blocked` label, stub body, AES-GCM-protected provider
  reference in Redis with TTL, AI Support Agent `ReleaseQuarantine` hook
  with Tier 0 + Tier 1 re-eval, `es.action.quarantine.release` events.
- Banner accessibility (WCAG 2.1 AA) — `role="alert"` on High Risk and
  Blocked, severity-prefixed `aria-label`s, contrast-safe 6-tier palette,
  logical focus order (severity → reasons → auth chip → buttons),
  `dir="rtl"` injection for RTL locales.
- Banner i18n expansion (`action/catalogs/{th,ja,ko,zh}.json`) — Thai,
  Japanese, Korean, and Simplified Chinese catalogs for all 6 tiers,
  16 categories, auth chip, action buttons, and micro-lesson prompts.

## Phase 6 — Education &nbsp;✅ COMPLETE (5 / 5)

Deliverables:

- Education micro-lessons (`internal/service/education/micro_lesson.go`,
  `lessons/en.json`) — 30-second, plain-language lesson for each of the
  16 threat categories with `lesson_id`, `category`, `title`,
  `body_html` (inline CSS, no remote assets), `estimated_seconds`;
  locale fallback to `en`; publishes `es.education.lesson.trigger`;
  served via `GET /v1/education/lesson/{category}?locale=en`
  (`internal/handler/education.go`).
- Phishing simulation engine (`education/simulation.go`,
  `simulation_tracker.go`) — campaign lifecycle, per-target dispatch,
  per-user interaction tracking (clicked / submitted / reported /
  ignored / opened), pseudonymised results, NATS consumer for
  `es.education.simulation.send`, publisher for
  `es.education.simulation.result`.
- Resilience scoring (`education/resilience.go`) —
  `0.40 * simulation_performance + 0.25 * report_rate + 0.20 *
  lesson_engagement + 0.15 * incident_history`; per-user and per-group
  aggregation; Redis cache `tenant:{name}:resilience:{user_hash}` with
  24 h TTL; feeds detection sensitivity and simulation frequency.
- Adaptive simulation difficulty (`education/adaptive.go`) — Easy /
  Medium / Hard selection from resilience bands (0-40 / 40-70 /
  70-100), template filtering, progression tracking for users who
  consistently detect simulations.
- Simulation template library (`education/templates.go`) —
  parameterised BEC, credential phishing, QR code, invoice, lookalike
  domain and ATO templates across all difficulty levels with
  deterministic rendering.

## Phase 7 — Enriched Relationship Intelligence &nbsp;✅ COMPLETE (4 / 4)

Deliverables:

- Expanded relationship categories
  (`internal/service/relationship/categories.go`) — Partner, Customer,
  FirstTimeExternal, LapsedContact, RecurringService; Tier 0 / Tier 1
  threshold modifiers; force-escalate on FirstTimeExternal and
  LapsedContact (re-emerging senders after long silence — a classic
  ATO vector). `RiskSignals.RelationshipCategory` extended to match.
- Employee vulnerability scoring (`relationship/vulnerability.go`) —
  `0.30 * role_risk + 0.20 * external_volume + 0.10 *
  first_contact_frequency + 0.15 * incident_history + 0.25 *
  inverse_resilience`; Redis cache
  `tenant:{name}:vulnerability:{user_hash}` with 24 h TTL; per-user
  detection sensitivity adjustment.
- Vendor auto-discovery (`relationship/vendor_discovery.go`) — 30-day
  history scan with domain frequency + bidirectional + consistent
  sender heuristics, confidence-scored auto-approval or admin review
  queue, weekly periodic job.
- Timing anomaly detection (`relationship/timing.go`) — per-sender
  hour-of-day baseline with circular distance; `TimingSignal` with
  anomaly score (0-1) and binary flag; `RiskSignals.TimingAnomalyScore`
  field for the scorer.

## Phase 8 — Add-ins + Pre-Send / Pre-Open + Ops &nbsp;✅ COMPLETE (8 / 8)

Deliverables:

- Pre-send warning add-in (`deployments/addins/outlook/`,
  `deployments/addins/gmail/`, `internal/handler/predict.go`,
  `internal/service/predict/recipient.go`) —
  `POST /v1/predict/recipient` with lookalike-domain, external-on-
  internal-thread, and unusual-recipient checks; pseudonymised inputs;
  <300 ms p95 latency budget; Outlook Office Add-in manifest (Manifest
  v3) and Gmail Add-on `appsscript.json` with companion JS / Apps
  Script files.
- Pre-open warning add-in (`POST /v1/predict/open` in the same handler,
  `deployments/addins/{outlook,gmail}/src/preopen.{js,gs}`) —
  Warning-tier-or-higher modal gating before the message body renders.
- Admin dashboard (`internal/service/dashboard/generator.go`,
  `internal/handler/dashboard.go`, `internal/dto/dashboard.go`) —
  `GET /v1/dashboard/summary?range=7d` aggregating emails processed,
  threats by tier and category, feedback stats, quarantine stats,
  simulation stats, FP / FN rates; AI-generated narrative with a
  deterministic fallback for tests and audit replay.
- User-reported phishing workflow
  (`internal/service/action/report_workflow.go`) — multi-user
  aggregation with reporter-hash dedup, forced Tier 1 + Tier 2 re-eval,
  tenant-wide auto-quarantine when confirmed,
  `es.action.feedback.report_{confirmed,dismissed}` events, anonymised
  feed into the training pipeline.
- SN360 SecOps escalation (`internal/service/agent/escalation.go`,
  `internal/handler/escalation.go`, `internal/dto/escalation.go`) —
  triggers on breach indicators / account compromise / zero-day
  attachment / AI low-confidence; anonymised context package; ticket
  store; `POST /v1/escalation/resolve` for SecOps outcome feedback;
  `es.action.escalation.{created,resolved}` events.
- Distributed tracing (`pkg/telemetry/`) — W3C `traceparent` propagation,
  HTTP middleware (`middleware.go`) recording status + 5xx errors,
  NATS header inject / extract helpers (`nats.go`), pluggable sampler
  + exporter (no-op / in-memory / OTLP).
- URL pre-scanning (`internal/service/evaluate/url_scanner.go`) —
  bounded-concurrency batch scanner, VirusTotal v3 provider,
  Redis-compatible cache (`url_scan:{sha256}`) with 1 h TTL, dedup,
  `links` weight category integration.
- Attachment pre-screen (`internal/service/evaluate/attachment_scanner.go`)
  — YARA engine with zero-dep default rules (OLE magic, VBA verbs,
  PE header, credential-form HTML), ClamAV INSTREAM client over TCP,
  suspicious-extension guard, oversize guard, only suspicious /
  malicious results escalate to ShieldNet sandbox.

---

## Cross-Cutting Tracks

These are not phases per se but apply across all phases:

| Track | Status | Notes |
|---|---|---|
| Unit tests | ✅ Complete | Phases 1-8 unit tests covered: tier_decider, auth_verdict, categorizer, banner_renderer (incl. a11y + RTL + locales), url_rewriter, feedback, scorer, tier0 gate, recurring, pseudonymizer, jwt, quarantine + release, education (lessons, simulation, resilience, adaptive, templates), relationship (categories, vulnerability, vendor, timing), predict (recipient + open), dashboard, report workflow, escalation, telemetry, url scanner (incl. VirusTotal HTTP), attachment scanner (incl. clamd protocol), AI + Rspamd caches, subject-line tag, Prometheus metrics. |
| Integration tests | ✅ Complete | testcontainers-based suites for NATS JetStream, Redis pipeline, PostgreSQL + golang-migrate, bus factory (NATS / Redis), and an end-to-end pipeline test. Behind `//go:build integration` and `make test-integration`. |
| Benchmarks & quality measurement | ✅ Complete | Labelled corpus generator (`internal/testdata/corpus/`, 1 000+ emails, 16 categories, 6 tiers, all 6 relationship categories) + CLI (`cmd/gen-corpus/`); accuracy / precision / recall / F1 / confusion-matrix harness (`internal/service/evaluate/accuracy_{test,report}.go`, `//go:build benchmark`); Go microbenchmarks for evaluator / scorer / categorizer / Tier 0 gate / banner renderer / education templates + simulation engine; resource profiler (`profile_test.go`, `latency_distribution_test.go`) covering peak heap, GC pauses, throughput, p50 / p95 / p99 latency, and a Prometheus-bucket histogram; baseline artefacts committed under `benchmarks/` and exercised via `make bench`, `make bench-accuracy`, `make bench-profile`, `make bench-all`, `make gen-corpus`. |
| Lint (`gofmt -l`, `go vet`) | ✅ Clean | `make lint` gate enforced in CI. |
| Database migrations | ✅ Complete | `cmd/sn360-es-migrate/` wraps golang-migrate v4; `make migrate-up/-down/-check`; initial schema covers all 13 tables. |
| Observability (metrics, tracing) | ✅ Complete | `pkg/telemetry/` provides W3C tracing across HTTP + NATS and Prometheus metrics for banners, pipeline stages, education, and quarantine releases. `/metrics` exposed by the API server. |
| API documentation (OpenAPI 3.1) | ✅ Complete | `api/openapi.yaml` documents every public handler; Swagger UI is served at `/docs` and the raw spec at `/openapi.yaml` (`internal/handler/docs.go`). |
| Helm charts + ArgoCD | ✅ Complete | `deployments/helm/sn360-es/` with NATS Helm subchart, HPA, ServiceMonitor, migration Job. `deployments/argocd/application.yaml` covers dev / qa / uat / prod. |
| Health / readiness probes | ✅ Complete | `/healthz` (liveness) and `/readyz` (NATS / Redis / PG connectivity probes) in `internal/handler/health.go`, wired into the Helm chart. |
