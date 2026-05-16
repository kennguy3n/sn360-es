# SN360-ES Implementation Phases

Phase-level rollup of the v2 platform. Detailed per-task status is tracked in
[`PROGRESS.md`](./PROGRESS.md); the canonical specification lives in
[`PROPOSAL.md`](./PROPOSAL.md) Section 9. This document summarises *what*
each phase delivers and where to find the code.

**Overall status:** 30 / 51 tasks complete (~59%). Phases 1-4 are complete;
Phase 5 is partial (8 / 11 tasks); Phases 6-8 are not started.

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

## Phase 5 — Tiered UX &nbsp;🔶 IN PROGRESS (8 / 11)

Done (8 / 11):

- 6-tier banner system (`internal/service/action/`): `tier_decider.go`
  (score thresholds + per-tenant overrides + first-contact floor),
  `banner_renderer.go` (deterministic Go `html/template`, inline CSS,
  no remote assets, dark-mode safe), `banner_i18n.go` (embedded JSON
  catalogs), translations in `action/catalogs/{en,vi}.json`.
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

Remaining (3 / 11):

- Quarantine + release flow (admin-approval UI + AI auto-approve).
- Banner accessibility audit pass (WCAG 2.1 AA across all tiers,
  screen-reader copy, focus order in injected HTML).
- Banner i18n expansion (`th`, `ja`, `ko`, `zh`).

## Phase 6 — Education &nbsp;🔲 NOT STARTED (0 / 4)

Scope: micro-lessons, phishing-simulation engine, resilience scoring,
adaptive difficulty, simulation template library. See PROPOSAL.md §9.

## Phase 7 — Enriched Relationship Intelligence &nbsp;🔲 NOT STARTED (0 / 4)

Scope: expanded relationship categories (Partner, Customer,
FirstTimeExternal, LapsedContact), employee vulnerability scoring,
vendor auto-discovery, timing-anomaly baselines.

## Phase 8 — Add-ins + Pre-Send / Pre-Open Warnings &nbsp;🔲 NOT STARTED (0 / 8)

Scope: Gmail / Outlook add-ins for pre-send and pre-open warnings,
AI-generated admin dashboard, user-reported-phishing workflow, SN360
SecOps escalation, distributed tracing (OTel), URL pre-scan
(VirusTotal), attachment pre-screen (YARA / ClamAV).

---

## Cross-Cutting Tracks

These are not phases per se but apply across all phases:

| Track | Status | Notes |
|---|---|---|
| Unit tests | 🔶 Partial | tier_decider, auth_verdict, categorizer, banner_renderer, url_rewriter, feedback, scorer, tier0 gate, recurring, pseudonymizer, jwt — all covered. Integration tests for NATS / Redis / PG still pending. |
| Lint (`gofmt -l`, `go vet`) | ✅ Clean | `make lint` gate enforced in CI. |
| Observability (metrics, tracing) | 🔲 Not started | Phase 8. |
| API documentation (OpenAPI / Huma) | 🔲 Not started | Will follow service surface stabilising. |
| Helm charts + ArgoCD | 🔲 Not started | Will reuse patterns from `uneycom/nges-k8s-assets`. |
