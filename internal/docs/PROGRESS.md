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

| Area | Status | Priority | Phase |
|---|---|---|---|
| **Tier 0 classification gates** | 🔲 Not started | Critical | Phase 1 |
| **Graceful degradation (AI failure)** | 🔲 Not started | Critical | Phase 1 |
| **NATS JetStream event bus** | 🔲 Not started | Critical | Phase 1 |
| **NATS `EventService` interface** | 🔲 Not started | Critical | Phase 1 |
| **Feature flag: EVENT_BUS_TYPE** | 🔲 Not started | High | Phase 1 |
| **Dead-letter queue handling** | 🔲 Not started | High | Phase 1 |
| **Privacy layer (`pkg/privacy/`)** | 🔲 Not started | Critical | Phase 2 |
| **PII pseudonymization (Blake2)** | 🔲 Not started | Critical | Phase 2 |
| **Per-tenant encryption (KMS)** | 🔲 Not started | Critical | Phase 2 |
| **Log sanitization middleware** | 🔲 Not started | High | Phase 2 |
| **Cryptographic erasure on delete** | 🔲 Not started | High | Phase 2 |
| **AI result caching** | 🔲 Not started | High | Phase 2 |
| **Rspamd result caching** | 🔲 Not started | Medium | Phase 2 |
| **Redis pipelining (batch reads)** | 🔲 Not started | Medium | Phase 2 |
| **Tier 1 encoder model (XLM-RoBERTa)** | 🔲 Not started | Critical | Phase 3 |
| **Encoder inference service (K8s)** | 🔲 Not started | Critical | Phase 3 |
| **Micro-batching (NATS batch fetch)** | 🔲 Not started | High | Phase 3 |
| **Batch Tier 1 GPU inference** | 🔲 Not started | High | Phase 3 |
| **AI Onboarding Agent** | 🔲 Not started | High | Phase 4 |
| **AI Tuning Agent** | 🔲 Not started | High | Phase 4 |
| **AI Support Agent** | 🔲 Not started | Medium | Phase 4 |
| **Auto-onboarding (OAuth flow)** | 🔲 Not started | High | Phase 4 |
| **Org graph discovery** | 🔲 Not started | High | Phase 4 |
| **Tiered banner system (6 tiers)** | 🔲 Not started | Critical | Phase 5 |
| **Native provider labels per tier (Gmail + Outlook)** | 🔲 Not started | Critical | Phase 5 |
| **Category vocabulary (16 categories)** | 🔲 Not started | High | Phase 5 |
| **One-click Report Phishing / Mark Safe** | 🔲 Not started | High | Phase 5 |
| **Sender authentication chip in banner** | 🔲 Not started | High | Phase 5 |
| **Action token service (signed JWT)** | 🔲 Not started | High | Phase 5 |
| **URL rewriting (High Risk + Blocked)** | 🔲 Not started | High | Phase 5 |
| **URL interstitial service** | 🔲 Not started | High | Phase 5 |
| **Quarantine + release flow** | 🔲 Not started | High | Phase 5 |
| **Banner accessibility (WCAG 2.1 AA)** | 🔲 Not started | Medium | Phase 5 |
| **Banner i18n expansion (th, ja, ko, zh)** | 🔲 Not started | Medium | Phase 5 |
| **Education micro-lessons** | 🔲 Not started | High | Phase 6 |
| **Phishing simulation engine** | 🔲 Not started | High | Phase 6 |
| **Resilience scoring** | 🔲 Not started | Medium | Phase 6 |
| **Adaptive simulation difficulty** | 🔲 Not started | Medium | Phase 6 |
| **Simulation template library** | 🔲 Not started | Medium | Phase 6 |
| **Expanded relationship categories** | 🔲 Not started | High | Phase 7 |
| **Employee vulnerability scoring** | 🔲 Not started | Medium | Phase 7 |
| **Vendor auto-discovery** | 🔲 Not started | Medium | Phase 7 |
| **Timing anomaly detection** | 🔲 Not started | Medium | Phase 7 |
| **Pre-send warning add-in (Tessian-style)** | 🔲 Not started | High | Phase 8 |
| **Pre-open warning add-in** | 🔲 Not started | Medium | Phase 8 |
| **Admin dashboard (AI-generated)** | 🔲 Not started | High | Phase 8 |
| **User-reported phishing workflow** | 🔲 Not started | Medium | Phase 8 |
| **SN360 SecOps escalation** | 🔲 Not started | Medium | Phase 8 |
| **Distributed tracing (OTel)** | 🔲 Not started | Medium | Phase 8 |
| **URL pre-scanning (VirusTotal)** | 🔲 Not started | Medium | Phase 8 |
| **Attachment pre-screen (YARA/ClamAV)** | 🔲 Not started | Medium | Phase 8 |

---

## Changelog (v1 / NGES — Reverse Chronological)

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
