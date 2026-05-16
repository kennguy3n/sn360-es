# SN360-ES Progress & Changelog

## Project Status Dashboard

### v1 (NGES) — Completed Features

| Area | Status | Notes |
|---|---|---|
| GWS ingestion + delta sync | ✅ Done | Gmail History API, distributed locking |
| O365 ingestion + delta sync | ✅ Done | Microsoft Graph delta sync, dedup/gap handling |
| Email normalizer (GWS + O365) | ✅ Done | Unified EmailEvent format |
| Rspamd heuristic detection | ✅ Done | v3.14.2, custom Lua plugins, LLM context |
| AI/LLM detection | ✅ Done | External API with retry/backoff |
| ShieldNet attachment scanning | ✅ Done | Feature-flagged, weight=0 |
| Weighted risk scoring | ✅ Done | Per-tenant configurable weights |
| Banner injection (GWS) | ✅ Done | HTML banner with score theming (v1 single tier) |
| Banner injection (O365) | ✅ Done | Graph API message update (v1 single tier) |
| FYI Labels (GWS) | ✅ Done | Gmail label creation + application (single "FYI" label) |
| FYI Labels (O365) | ✅ Done | Master Categories via Graph API (single "FYI" category) |
| Multi-tenant management API | ✅ Done | CRUD for tenants, users, groups, labels |
| Score engine management | ✅ Done | Per-tenant weight configuration |
| Email classification | ✅ Done | FREE, DISPOSABLE, ANONYMOUS categories |
| Tenant vendor management | ✅ Done | Per-tenant approved vendor list |
| Communication history | ✅ Done | Sender→receiver pair tracking |
| Relationship aggregation | ✅ Done | 7d/30d counts, Redis caching, retention cleanup |
| Risk signals (prefilter) | ✅ Done | IsExternal, IsInternal, IsFromVendor, IsFreeDomain, etc. |
| Links extraction (body + QR) | ✅ Done | URL extraction from HTML body and QR codes |
| Redis Streams event bus | ✅ Done | Consumer groups, pending recovery, backoff |
| GitOps deployment (ArgoCD) | ✅ Done | Helmfile, 4 environments |
| CI/CD pipelines | ✅ Done | GitHub Actions, Trivy, Gitleaks, SonarQube |
| Performance test harness | ✅ Done | Redis load gen, SMTP fixtures, domain seeder |
| Banner i18n (en, vi) | ✅ Done | Translation layer in evaluate-svc |

### v2 (SN360-ES) — Planned Features

**Overall v2 Status**: Complete | 100% (51/51 tasks complete — all phases complete)

| Area | Status | Priority | Phase |
|---|---|---|---|
| **Tier 0 classification gates** | ✅ Done | Critical | Phase 1 |
| **Graceful degradation (AI failure)** | ✅ Done | Critical | Phase 1 |
| **NATS JetStream event bus** | ✅ Done | Critical | Phase 1 |
| **NATS `EventService` interface** | ✅ Done | Critical | Phase 1 |
| **Feature flag: EVENT_BUS_TYPE** | ✅ Done | High | Phase 1 |
| **Dead-letter queue handling** | ✅ Done | High | Phase 1 |
| **Privacy layer (`pkg/privacy/`)** | ✅ Done | Critical | Phase 2 |
| **PII pseudonymization (Blake2)** | ✅ Done | Critical | Phase 2 |
| **Per-tenant encryption (KMS)** | ✅ Done | Critical | Phase 2 |
| **Log sanitization middleware** | ✅ Done | High | Phase 2 |
| **Cryptographic erasure on delete** | ✅ Done | High | Phase 2 |
| **AI result caching** | ✅ Done | High | Phase 2 |
| **Rspamd result caching** | ✅ Done | Medium | Phase 2 |
| **Redis pipelining (batch reads)** | ✅ Done | Medium | Phase 2 |
| **Tier 1 encoder model (XLM-RoBERTa)** | ✅ Done | Critical | Phase 3 |
| **Encoder inference service (K8s)** | ✅ Done | Critical | Phase 3 |
| **Micro-batching (NATS batch fetch)** | ✅ Done | High | Phase 3 |
| **Batch Tier 1 GPU inference** | ✅ Done | High | Phase 3 |
| **AI Onboarding Agent** | ✅ Done | High | Phase 4 |
| **AI Tuning Agent** | ✅ Done | High | Phase 4 |
| **AI Support Agent** | ✅ Done | Medium | Phase 4 |
| **Auto-onboarding (OAuth flow)** | ✅ Done | High | Phase 4 |
| **Org graph discovery** | ✅ Done | High | Phase 4 |
| **Tiered banner system (6 tiers)** | ✅ Done | Critical | Phase 5 |
| **Native provider labels per tier (Gmail + Outlook)** | ✅ Done | Critical | Phase 5 |
| **Category vocabulary (16 categories)** | ✅ Done | High | Phase 5 |
| **One-click Report Phishing / Mark Safe** | ✅ Done | High | Phase 5 |
| **Sender authentication chip in banner** | ✅ Done | High | Phase 5 |
| **Action token service (signed JWT)** | ✅ Done | High | Phase 5 |
| **URL rewriting (High Risk + Blocked)** | ✅ Done | High | Phase 5 |
| **URL interstitial service** | ✅ Done | High | Phase 5 |
| **Quarantine + release flow** | ✅ Done | High | Phase 5 |
| **Banner accessibility (WCAG 2.1 AA)** | ✅ Done | Medium | Phase 5 |
| **Banner i18n expansion (th, ja, ko, zh)** | ✅ Done | Medium | Phase 5 |
| **Education micro-lessons** | ✅ Done | High | Phase 6 |
| **Phishing simulation engine** | ✅ Done | High | Phase 6 |
| **Resilience scoring** | ✅ Done | Medium | Phase 6 |
| **Adaptive simulation difficulty** | ✅ Done | Medium | Phase 6 |
| **Simulation template library** | ✅ Done | Medium | Phase 6 |
| **Expanded relationship categories** | ✅ Done | High | Phase 7 |
| **Employee vulnerability scoring** | ✅ Done | Medium | Phase 7 |
| **Vendor auto-discovery** | ✅ Done | Medium | Phase 7 |
| **Timing anomaly detection** | ✅ Done | Medium | Phase 7 |
| **Pre-send warning add-in (Tessian-style)** | ✅ Done | High | Phase 8 |
| **Pre-open warning add-in** | ✅ Done | Medium | Phase 8 |
| **Admin dashboard (AI-generated)** | ✅ Done | High | Phase 8 |
| **User-reported phishing workflow** | ✅ Done | Medium | Phase 8 |
| **SN360 SecOps escalation** | ✅ Done | Medium | Phase 8 |
| **Distributed tracing (OTel)** | ✅ Done | Medium | Phase 8 |
| **URL pre-scanning (VirusTotal)** | ✅ Done | Medium | Phase 8 |
| **Attachment pre-screen (YARA/ClamAV)** | ✅ Done | Medium | Phase 8 |

### Cross-Cutting / Infrastructure Tasks

**Overall status**: 8/8 task groups complete

| Area | Status | Notes |
|---|---|---|
| **Database migrations (golang-migrate)** | ✅ Done | `migrations/0001_init.{up,down}.sql`, `cmd/sn360-es-migrate/`, `make migrate-up/-down/-check` |
| **NATS integration tests** | ✅ Done | `pkg/events/nats/nats_integration_test.go` (testcontainers, `//go:build integration`) |
| **Redis integration tests** | ✅ Done | `pkg/storage/redis/redis_integration_test.go` (pipeline + TTL coverage) |
| **PostgreSQL integration tests** | ✅ Done | `pkg/storage/postgres/postgres_integration_test.go` (migrations + repository CRUD) |
| **Bus factory integration tests** | ✅ Done | `pkg/events/bus/bus_integration_test.go` (NATS + Redis backends) |
| **E2E pipeline integration test** | ✅ Done | `internal/service/evaluate/pipeline_integration_test.go` (request → tier 0/1/2 → action) |
| **OpenAPI 3.1 spec** | ✅ Done | `api/openapi.yaml` documents every public handler |
| **Swagger UI + spec serving** | ✅ Done | `GET /docs`, `GET /openapi.yaml` (`internal/handler/docs.go`) |
| **Prometheus metrics package** | ✅ Done | `pkg/telemetry/metrics.go` + `/metrics` endpoint |
| **Pipeline instrumentation** | ✅ Done | Tier 0 / Tier 1 / Tier 2 / Rspamd / banner / education metrics |
| **Helm chart** | ✅ Done | `deployments/helm/sn360-es/` with NATS subchart and HPA/ServiceMonitor |
| **ArgoCD applications** | ✅ Done | `deployments/argocd/application.yaml` (dev / qa / uat / prod) |
| **`pkg/httpclient/`** | ✅ Done | HTTP/2 pooled client, retry, circuit breaker, used by VT / encoder / LLM |
| **`pkg/storage/{postgres,redis,s3}/`** | ✅ Done | pgx-backed PostgreSQL, Redis pipeline wrapper, AWS S3 client |
| **`internal/repository/`** | ✅ Done | Postgres + in-memory implementations for all domain entities |
| **`internal/translation/`** | ✅ Done | Banner i18n bundles re-exported from action catalogs |
| **Subject-line tag (optional)** | ✅ Done | `internal/service/action/subject_tag.go` (default off, configurable prefix) |
| **AI / Rspamd cache tests** | ✅ Done | `internal/service/cache/{ai,rspamd}_cache_test.go` (miniredis) |
| **Docker-compose completeness** | ✅ Done | NATS + Postgres + Redis + Rspamd + ClamAV |
| **Health / readiness endpoints** | ✅ Done | `/healthz`, `/readyz` with NATS / Redis / PG probes |

---

## Changelog (Reverse Chronological)

### 2026-05-16 (v2 / SN360-ES — Cross-cutting / Infrastructure)

- **Migrations**: golang-migrate v4 wired into `make migrate-up/-down/-check` via `cmd/sn360-es-migrate/`; initial schema (`migrations/0001_init.{up,down}.sql`) for tenants, users, groups, labels, score_engine, email_classifications, vendors, evaluation_results, communication_histories, campaigns, simulation_results, escalation_tickets, audit_logs.
- **Persistence packages**: `pkg/storage/postgres/` (pgx wrapper + config), `pkg/storage/redis/` (pipeline + scan helpers), `pkg/storage/s3/` (AWS S3 client). `internal/repository/` exposes Postgres + in-memory implementations for every domain entity.
- **HTTP client**: `pkg/httpclient/` provides a shared HTTP/2 pooled client with retry, circuit breaker, and per-call timeout — used by URL pre-scanner, encoder client, LLM client, and tenant API clients.
- **Telemetry**: `pkg/telemetry/metrics.go` adds Prometheus counters / histograms for banner rendering, banner actions, quarantine releases, URL clicks, pre-send prompts, Tier 0/1/2 verdicts, Rspamd, education simulations and resilience. `/metrics` endpoint wired in `cmd/sn360-es/main.go`.
- **API documentation**: `api/openapi.yaml` (OpenAPI 3.1) documents every public handler; `internal/handler/docs.go` serves Swagger UI at `/docs` and the raw spec at `/openapi.yaml`.
- **Health probes**: `/healthz` (liveness, always 200) and `/readyz` (NATS / Redis / PG connectivity probes with 2 s timeout) in `internal/handler/health.go`.
- **Subject-line tag**: `internal/service/action/subject_tag.go` adds an opt-in `[SN360: WARN]`-style prefix at Warning+ tiers; per-tenant `subject_tag_enabled` + `subject_tag_prefix` columns.
- **Caches**: `internal/service/cache/{ai,rspamd}_cache_test.go` cover serialization, TTL, and miss paths using miniredis.
- **Helm + ArgoCD**: `deployments/helm/sn360-es/` (Deployment, Service, HPA, ConfigMap, Secret, ServiceAccount, ServiceMonitor, migration Job, NATS subchart) and `deployments/argocd/application.yaml` for dev / qa / uat / prod.
- **Integration tests**: testcontainers-based suites under `//go:build integration` for NATS, Redis, PostgreSQL, bus factory, and an end-to-end pipeline test that runs the full evaluator over a real NATS server.
- **Docker compose**: adds ClamAV alongside NATS / Postgres / Redis / Rspamd so the attachment pre-screen path runs end-to-end locally.

### 2026-05-16 (v2 / SN360-ES — Phases 5-8)

- **Phase 5**: Quarantine + release flow (`internal/service/action/quarantine.go`, `quarantine_release.go`, `internal/handler/quarantine.go`) — hidden `SN360 / Blocked` label, stub body, AES-GCM-protected provider reference in Redis with TTL, AI Support Agent `ReleaseQuarantine` hook with Tier 0 + Tier 1 re-eval, `es.action.quarantine.release` events
- **Phase 5**: Banner accessibility hardening (`internal/service/action/banner_renderer.go`) — `role="alert"` on High Risk + Blocked, severity-prefixed `aria-label`s, contrast-safe 6-tier palette, focus order (severity → reasons → auth chip → buttons), `dir="rtl"` injection for RTL locales
- **Phase 5**: Banner i18n expansion (`internal/service/action/catalogs/{th,ja,ko,zh}.json`) — Thai / Japanese / Korean / Simplified Chinese catalogs for all 6 tiers, 16 categories, auth chip, action buttons, micro-lesson prompts
- **Phase 6**: Education micro-lessons (`internal/service/education/micro_lesson.go`, `lessons/en.json`) — 16-category catalog with locale fallback, inline-CSS lesson bodies, `es.education.lesson.trigger` events, `GET /v1/education/lesson/{category}` endpoint
- **Phase 6**: Phishing simulation engine (`internal/service/education/simulation.go`, `simulation_tracker.go`) — campaign lifecycle, target dispatch, interaction tracking (clicked / submitted / reported / ignored / opened), pseudonymised per-user results, `es.education.simulation.{send,result}` events
- **Phase 6**: Resilience scoring (`internal/service/education/resilience.go`) — per-user score `0.4*sim + 0.25*report_rate + 0.20*lesson_engagement + 0.15*incident_history`, Redis-backed 24 h cache, group aggregation, feedback into detection sensitivity
- **Phase 6**: Adaptive simulation difficulty (`internal/service/education/adaptive.go`) — Easy / Medium / Hard selection by resilience band with progression tracking and template filtering
- **Phase 6**: Simulation template library (`internal/service/education/templates.go`) — parameterised BEC, credential, QR, invoice, lookalike, and ATO templates across all difficulty levels with deterministic rendering
- **Phase 7**: Expanded relationship categories (`internal/service/relationship/categories.go`) — Partner, Customer, FirstTimeExternal, LapsedContact, RecurringService with Tier 0 / Tier 1 threshold modifiers and force-escalate on FirstTimeExternal + LapsedContact
- **Phase 7**: Employee vulnerability scoring (`internal/service/relationship/vulnerability.go`) — `0.30*role + 0.20*volume + 0.10*first_contact + 0.15*incidents + 0.25*inverse_resilience`, Redis 24 h cache, per-user sensitivity adjustment
- **Phase 7**: Vendor auto-discovery (`internal/service/relationship/vendor_discovery.go`) — 30-day history scan, bidirectional + frequency heuristics, confidence-scored auto-approval or admin review queue, weekly job hook
- **Phase 7**: Timing anomaly detection (`internal/service/relationship/timing.go`) — per-sender hour-of-day baseline with circular distance, `TimingAnomalyScore` signal feeding the scorer
- **Phase 8**: Pre-send + pre-open add-ins (`deployments/addins/{outlook,gmail}`, `internal/handler/predict.go`, `internal/service/predict/recipient.go`) — `POST /v1/predict/recipient` + `POST /v1/predict/open`, Outlook MailboxItem hooks and Gmail Apps Script, <300 ms p95 latency budget
- **Phase 8**: Admin dashboard (`internal/service/dashboard/generator.go`, `internal/handler/dashboard.go`) — `GET /v1/dashboard/summary?range=7d`, per-tenant aggregation of emails / tiers / categories / feedback / quarantine / simulation / FP-FN, AI-generated narrative with deterministic fallback
- **Phase 8**: User-reported phishing workflow (`internal/service/action/report_workflow.go`) — multi-user aggregation with reporter dedup, forced Tier 1 + Tier 2 re-eval, tenant-wide auto-quarantine, `es.action.feedback.report_{confirmed,dismissed}` events
- **Phase 8**: SN360 SecOps escalation (`internal/service/agent/escalation.go`, `internal/handler/escalation.go`, `internal/dto/escalation.go`) — auto-triggers on breach / ATO / zero-day / low-confidence, anonymised context packages, `POST /v1/escalation/resolve` for SOC outcome feedback, `es.action.escalation.{created,resolved}` events
- **Phase 8**: Distributed tracing (`pkg/telemetry/tracer.go`, `middleware.go`, `nats.go`) — W3C `traceparent` propagation, HTTP middleware with 5xx span errors, NATS header inject / extract helpers, pluggable sampler + exporter
- **Phase 8**: URL pre-scanning (`internal/service/evaluate/url_scanner.go`) — bounded-concurrency batch scanner, VirusTotal v3 provider, `url_scan:{sha256}` Redis cache with 1 h TTL, dedup, `links` weight category integration
- **Phase 8**: Attachment pre-screen (`internal/service/evaluate/attachment_scanner.go`) — YARA (zero-dep default rules) + ClamAV INSTREAM over TCP, suspicious extension guard, oversize guard, only suspicious / malicious results escalate to ShieldNet sandbox
- **Tests**: Table-driven unit tests added for every new service (quarantine, banner i18n / a11y, micro_lesson, simulation, resilience, adaptive, templates, relationship categories / vulnerability / vendor / timing, predict, dashboard, report workflow, escalation, telemetry, url scanner, attachment scanner)
- **Docs**: `internal/docs/PHASES.md` and this file updated to 100% (51/51) — see Phases 5-8 deliverable maps for code pointers

### 2026-05-16 (v2 / SN360-ES)

- **Phase 1**: NATS JetStream event bus (5 streams: `ES_EVALUATE`, `ES_ONBOARDING`, `ES_EDUCATION`, `ES_ACTION`, `ES_DLQ`) with `EventService` interface and Redis-Streams fallback behind `EVENT_BUS_TYPE` feature flag
- **Phase 1**: Dead-letter queue routing + DLQ processor service with replay support
- **Phase 1**: Tier 0 classification gates (internal / vendor / recurring service / high-volume bypass) — pure CPU, <1 ms
- **Phase 1**: Graceful-degradation orchestrator with circuit breakers and weighted score aggregation
- **Phase 2**: Privacy layer (`pkg/privacy/`) — Blake2b pseudonymisation, AES-256-GCM per-tenant envelope encryption, AWS KMS wrapper, log-sanitisation slog handler, cryptographic erasure
- **Phase 2**: AI result cache (1 h TTL) + Rspamd cache (30 m TTL) + Redis pipeline wrapper for batched tenant config loads
- **Phase 3**: Tier 1 encoder client (XLM-RoBERTa) with per-tenant threshold logic and language-hint extraction
- **Phase 3**: K8s encoder inference service (FastAPI + ONNX Runtime + HPA + GPU/CPU fallback)
- **Phase 3**: Micro-batching (NATS pull fetch, up to 50 msgs) + batch Tier 1 GPU inference with individual-call fallback
- **Phase 4**: AI Onboarding / Tuning / Support agents with role-based sensitivity tiers and FP/FN-driven threshold tuning
- **Phase 4**: OAuth auto-onboarding for Google Workspace + Microsoft 365 with org graph discovery (high-risk group identification)
- **Phase 5**: 6-tier banner system (Trusted / Informational / Caution / Warning / HighRisk / Blocked) with deterministic `html/template` renderer, inline CSS, dark-mode safe, WCAG 2.1 AA
- **Phase 5**: Native provider labels (Gmail labels + Outlook Master Categories) per tier with idempotent application and label-ID caching
- **Phase 5**: 16-category vocabulary + rule categorizer (primary + up to 2 secondaries)
- **Phase 5**: Sender-auth chip (SPF/DKIM/DMARC aggregate verdict)
- **Phase 5**: Action token service (HS256 JWT, per-tenant secret, no PII)
- **Phase 5**: One-click `POST /v1/banner/action` (Report Phishing / Mark Safe / Trust Sender) with `es.action.feedback.*` events and optional re-evaluation
- **Phase 5**: URL rewriter (HighRisk + Blocked) + interstitial endpoint with encrypted pre-image storage in Redis and optional threat-intel re-check
- **Tests**: Table-driven unit tests for tier_decider, banner_renderer (incl. i18n + determinism), auth_verdict, url_rewriter, feedback, categorizer, scorer, tier0 gate, recurring detector, Blake2 pseudonymizer, JWT issuer
- See `internal/docs/PHASES.md` for phase-level tracking.

## v1 / NGES Changelog

### 2026-05-15

- **management-svc**: `EMAIL-283` — Record per-tenant `last_run` timestamp for relationship aggregation worker
- **k8s-assets**: Auto-deploy all services to QA

### 2026-05-14

- **evaluate-svc**: `EMAIL-283` — Add relationship enrichment and user note parsing for AI detection
- **ingestion-svc**: `EMAIL-283` — Parse user cache JSON to extract role field for poll dispatcher
- **management-svc**: `EMAIL-283` — Add communication history tracking and relationship aggregation worker
- **k8s-assets**: `EMAIL-283` — Enable cleanup and relationship aggregation workers in dev/qa/uat

### 2026-05-12

- **evaluate-svc**: `EMAIL-282` — Update get user profile role for AI detection
- **management-svc**: `EMAIL-284` — Refactor event processing to use StreamService
- **management-svc**: Add UI email vendor and classification support

### 2026-05-11

- **evaluate-svc**: `EMAIL-269` — Detect external mail sent into tenant; fix attempts logic
- **management-svc**: `add_communication_histories` migration — Sender→receiver tracking

### 2026-05-08

- All services: Add prod pipelines (`NGES-226`, `NGES-223`)
- **ingestion-svc**: Add configurable max results for GWS history and recent data

### 2026-05-07

- All services: Add Gitleaks secret scanning to CI
- **management-svc**: `EMAIL-237` — Update Redis read-through logic
- **external-deps**: `NGES-223` — Add prod pipeline for Rspamd/Unbound

### 2026-05-05

- **evaluate-svc**: `EMAIL-000` — Return error when AI result errors

### 2026-05-04

- **ingestion-svc**: `EMAIL-244` — Implement O365 Outlook label integration with Master Categories

### 2026-04-24

- **evaluate-svc**: `EMAIL-243` — Links extractor from email body and QR code decode

### 2026-04-23

- **management-svc**: `EMAIL-245` — Add preset field to Label Management
- **external-deps**: Update Rspamd threshold config

### 2026-04-22

- All services: QA and UAT pipeline setup
- **ingestion-svc**: `EMAIL-231` — Add label message from configuration
- **evaluate-svc**: `EMAIL-238` — Refactor prefilter service

### 2026-04-20

- **evaluate-svc**: `EMAIL-236`, `EMAIL-232` — Update label/score engine Redis key format
- **evaluate-svc**: `EMAIL-211` — Add email classification RiskSignals fields and Redis lookup
- **ingestion-svc**: `EMAIL-236` — Update label read path

### 2026-04-16

- **management-svc**: Add tenant vendor table + email classification table

### 2026-04-15

- **evaluate-svc**: `EMAIL-205` — AI severity mapping
- All services: QA pipeline setup

### 2026-04-13

- All services: Latency logging improvements

### 2026-04-10

- All services: `EMAIL-216` — Keep correlationId
