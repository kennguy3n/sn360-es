# Degradation Modes

SN360-ES is a modular monolith that tolerates partial failure of every
optional dependency. This document enumerates each optional dependency,
explains exactly what the binary does when it's missing or unhealthy,
and rates the **data-loss risk** so operators know which failures can
be tolerated indefinitely and which must be fixed before the next
deployment.

The contract is:

* **Required** dependencies cause `newApplication` to return an error
  and the binary refuses to start.
* **Optional** dependencies log a warning at boot and the affected
  feature reports degraded status on `/readyz` (but the binary stays
  up so unrelated routes keep serving).

All checks are wired in
[`cmd/sn360-es/health.go`](../../cmd/sn360-es/health.go) and serve
the `/readyz` JSON payload.

## Risk levels

* **None** — the feature is purely an optimisation; no user-visible
  effect on degradation.
* **Low** — minor functional loss or observability gap; safe to
  operate in this state for hours.
* **Medium** — a class of messages is processed less effectively;
  safe for tens of minutes during an incident, but not as a steady
  state.
* **High** — verdicts may be wrong, slow, or missing; restore the
  dependency as soon as possible.
* **Data loss on restart** — in-memory stores will silently drop
  state when the process restarts; never run this configuration in
  production.

## Dependency table

| Dependency | Required? | Behaviour when missing | `/readyz` impact | Data-loss risk |
|---|---|---|---|---|
| **NATS event bus** | **Yes** | Binary refuses to start (`event bus: …`). | n/a — boot fails. | None — by definition unreachable in degraded mode. |
| **Postgres** | No | Repository layer is skipped; vendor lookups, audit log writes, plan-cache reads degrade to in-memory or no-op. Tier 0 still gates on allow-/block-list config; categorizer still runs. | `postgres` check absent; binary still ready. | **Medium** — vendor-compromise verdicts lose precision (no historical baseline); audit log gaps. |
| **Redis** | No | The URL rewriter (interstitial click-through) is **disabled entirely** — outbound action handlers that try to rewrite a URL no-op and the message ships with the original URL. Label cache falls back to a per-process in-memory map (cache hits per-replica only). Rate-limit token buckets are always in-memory by design, so Redis presence has no effect on them. Quarantine envelopes spool in-memory and would be lost on restart — `assertProductionDurableStores` therefore refuses to boot in production when the quarantine service is wired without Redis. | `redis` check absent; binary still ready. | **High** in non-production for in-flight quarantine; production startup hard-fails the boot before this matters. Interstitials are unavailable until Redis is restored. |
| **Tier 1 encoder service** | No | The encoder-side risk score is set to 0 and the `tier1` reason-code is annotated `degraded`. Categorizer still runs, but the encoder's contribution to the score vanishes. | `tier1_encoder` check fails; `/readyz` returns 503 only if the encoder was wired and is failing. | **High** — encoder is the strongest signal for novel phishing; verdicts skew toward "trusted" until restored. |
| **Tier 2 LLM service** | No | LLM is skipped; LLM-proposed categories vanish (the `LLMCategoryWeight` line goes unused). Reason codes from Tier 1 still surface. | Not a separate checker; lag visible via `event_lag_seconds` if a queue builds up. | **Low** — LLM is advisory by design (weight 1.5); deterministic signals still produce verdicts. |
| **Rspamd** | No | Rspamd outcome is empty; URL / attachment / spam scores from Rspamd vanish. Categorizer still scores using Tier 1 + Tier 2 + risk-signals. | Not a separate checker. | **Medium** — Rspamd catches a long-tail of spam patterns that the encoder doesn't; some commodity spam slips through. |
| **JWT issuer (`BANNER_TOKEN_SECRET`)** | No (logs warning) | Banner action handler skips token issuance; banners render without click-to-acknowledge tokens. | Not a separate checker. | **Low** — banners still display; only the acknowledge tracking is lost. |
| **Provider registry (Gmail, Microsoft Graph, etc.)** | No | Tenants with no provider wired skip ingestion / label / quarantine actions. The rest of the pipeline (consumers, evaluators) still runs. | `provider_registry` check passes but logs "no tenants registered" at debug. | **None** — degradation is per-tenant, not global. |
| **Ingestion poller** | No | Pull-based mailbox ingestion is disabled. When `INGESTION_MODE` includes `push` and a [push manager](./ARCHITECTURE.md#512-push-notification-receivers) is wired, push delivery continues to land new mail; otherwise tenants relying on poll mode stop seeing new mail until the poller is restored. | `ingestion_poller` check present if wired, never returns an error. | **Medium** — tenants on poll-only mode stop seeing new mail; **None** for tenants on `push`/`hybrid` modes with the push manager healthy. |
| **Push ingestion (`INGESTION_MODE=push` or `hybrid`)** | No | The `/v1/push/{provider}/{tenant}` route is mounted only when the manager + signature verifier both wire successfully. With push disabled (`INGESTION_MODE=poll` or unset), the route is absent and the binary falls back to poll-mode ingestion. With push enabled but a provider half misconfigured (e.g. no `INGESTION_PUSH_GMAIL_TOPIC`), the other provider remains operational; both halves missing drops the route and logs a warning at boot. | `ingestion_push` check present if wired, never returns an error. | **Medium** — tenants on `push`-only mode stop seeing new mail until a provider restores webhook delivery; `hybrid`-mode tenants degrade silently to poll-mode latency. |
| **Relationship worker** | No | First-contact / known-contact signal stops getting refreshed. New senders default to `IsRecurringService = false`. | `worker_relationship` check present if wired, no-op. | **Low** — categorizer slightly over-fires on first-contact in steady state. |
| **Vendor worker** | No | Vendor risk-signal baseline stops being refreshed. `IsFromVendor` / `IsVendorCompromise` use the most recent snapshot. | `worker_vendor` check present if wired, no-op. | **Low → Medium** — fresh vendor onboarding doesn't get its baseline until the worker comes back. |
| **Cleanup worker** | No | Expired quarantine / banner / token records are not garbage-collected. The DB grows unbounded. | `worker_cleanup` check present if wired, no-op. | **Low (immediate) → High (long-term)** — the system stays correct but storage usage grows; restore before reaching disk pressure. |
| **Directory-sync worker** | No | Internal-vs-external sender classification uses the stale roster. Newly-joined employees may be flagged as external. | `worker_directory_sync` check present if wired, no-op. | **Low** — a few percent of internal mail mis-classified as external. |
| **Tuning agent** | No | Per-tenant weight overrides aren't recomputed. Defaults from `DefaultCategoryWeights()` apply. | `agent_tuning` check present if wired, no-op. | **None** — defaults are conservative; tuning is an optimisation. |
| **Onboarding service (OAuth)** | No | New tenants can't complete provider onboarding. Existing tenants are unaffected. | Not a separate checker; failed `/onboarding/*` HTTP returns surface the issue. | **None** for existing tenants. |
| **Tier 1 batch orchestrator** | No (mutually exclusive with per-message Tier 1) | Tier 1 runs in per-message mode. Throughput is lower but verdicts are identical. | n/a — orchestrator is opt-in via `TIER1_BATCH_ENABLED`. | **None** — verdicts are bit-identical between batch and per-message paths. |
| **NATS DLQ** | No (auto-derived) | Failed messages are NAK'd back to JetStream; redelivery still works via `MaxDeliver`. | Not a separate checker. | **Low** — eventually-poisoned messages bubble up as repeated failures in logs. |

## In-memory stores (production warning)

The following stores fall back to **in-memory** implementations when
their durable backend is unavailable. **They are explicitly logged at
`Error` level when `Environment.IsProduction()`** by `newApplication`:

* `MemoryCampaignStore` (simulation engine) — phishing-simulation
  campaigns and their tracking IDs.
* `MemoryTicketStore` (escalation service) — escalation tickets.
* `memoryQuarantineStore` (quarantine subsystem) — quarantine
  records and release tokens.

Data-loss risk for all three is **Data loss on restart**. Operators
should treat the warning log as a paging signal — production must
have a durable store wired or active campaigns / tickets / quarantines
will silently vanish on the next deploy.

The warning is intentionally loud (`logger.Error`) but does not refuse
boot: the system is still useful for evaluating messages while the
durable store is being provisioned. Once the durable store is wired,
the warning disappears and `/readyz` is unchanged.

## Per-feature degradation cheat sheet

When triaging an incident, map the symptom to the dependency below and
read the table row above for the data-loss profile:

| Symptom | Likely degraded dependency |
|---|---|
| Verdicts skew toward "trusted" on novel mail | Tier 1 encoder |
| Verdicts skew toward "phishing" on legit first-contact | Relationship worker (stale `IsRecurringService`) |
| Quarantine tokens fail to validate after restart | Redis (in-memory fallback wiped) |
| Vendor-compromise detections vanish | Vendor worker / Postgres (no baseline) |
| Banner click tracking missing | JWT issuer / `BANNER_TOKEN_SECRET` |
| `/readyz` returns 503 with `tier1_encoder` failing | Tier 1 service is unreachable |
| Audit log gaps | Postgres |
| Disk usage growing unbounded | Cleanup worker not running |

## Tests that exercise degradation

* `evaluator_degraded_test.go` — Tier 1 / Tier 2 / Rspamd return error;
  verifies `Degraded` field carries the failing tier names and the
  remaining tiers still produce a verdict.
* `circuit_breaker_test.go` — fast-fails when a tier is repeatedly
  failing, then opens a single half-open probe on recovery.
* `categorizer_test.go` — published fixtures with missing Tier 2 and
  missing Rspamd; verifies the rule engine still produces deterministic
  verdicts.
* `rate_limit_test.go` — verifies the in-memory rate limiter still
  works when Redis is unavailable.

When you add a new degradation mode, add a corresponding test that
proves the system still answers correctly with the dependency missing.
