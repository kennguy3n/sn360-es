# SN360-ES — Technical Critique

**Repo**: `kennguy3n/sn360-es`  
**Language**: Go 1.25 (primary), Python (Tier 1 encoder)  
**Codebase**: ~73K LoC across 321 Go files, 1 Python file, 24 SQL migrations, 114 test files (~24K test LoC)

---

## 1. Architecture

### Strengths

**Deliberate domain decomposition.** The four-domain split (Ingestion → Evaluation → Management → Education) maps cleanly to the email security lifecycle. Each domain has clear ownership boundaries: Ingestion produces `es.evaluate.request` events, Evaluation consumes them and emits `es.action.*` verdicts, Management persists and aggregates, Education handles simulation campaigns. The event subjects (`ES_EVALUATE`, `ES_ONBOARDING`, `ES_EDUCATION`, `ES_ACTION`, `ES_DLQ`) give each domain a dedicated communication channel.

**Monolith-with-seams, not a monolith-with-coupling.** Compiling as a single binary (`cmd/sn360-es`) avoids the operational overhead of microservices while maintaining deployability as separate concerns. JetStream consumer groups (`evaluate-svc`, `ingestion-action`, `management-persist`, etc.) enable horizontal scaling — adding replicas means messages partition across consumers automatically. This is a pragmatic choice for a system at this maturity stage.

**Multi-tier detection pipeline is well-stratified.** The 3-tier model (Tier 0: <1ms classification gate → Tier 1: XLM-RoBERTa 50-200ms → Tier 2: LLM fallback) creates natural cost/latency trade-offs. The `shouldRunTier2` decision logic (`evaluator.go:367-379`) is clean: skip if Tier 0 says `SkipML`/`RspamdOnly`, always escalate on `ForceEscalate`, escalate on Tier 1 flag/unavailability. The batch orchestrator (`batch.go`) provides a separate fast-path for bulk processing.

**Graceful degradation is first-class.** This is a standout quality. The entire application is wired for optional dependencies:
- Postgres unavailable → in-memory repositories, degraded mode
- Redis unavailable → `NoopLock`, no cross-replica coordination but still runs
- JWT issuer not configured → fail-closed (returns 401), not fail-open
- Tier 1 encoder down → `degraded: true` flag propagated to verdicts
- KMS unavailable → mock encryptor in dev (guarded by `KMS_USE_MOCK`)

This pattern in `main.go` (lines 271-401) where each optional component is built with an `if err != nil { log warning, continue }` flow means the binary always starts — never crashes on missing infra. Production systems benefit enormously from this.

### Concerns

**`main.go` is 4,242 lines — a structural bottleneck.** This single file contains application bootstrap, all consumer wiring, all HTTP route registration, background job setup, and graceful shutdown orchestration. While it works, it's the most likely file to produce merge conflicts and the hardest file for a new contributor to navigate. The file does *too many things*: dependency injection, route mounting, consumer subscription, provider registry management, health check aggregation, and metrics wiring all live here.

*Recommendation*: Split into focused files: `wire.go` (DI/construction), `routes.go` (HTTP mux), `consumers.go` (event subscriptions), `health.go` (probe handlers). The `cmd/sn360-es/` package can remain the wiring root, but the 4K-line single-file pattern invites accidental coupling.

**Event bus abstraction leaks JetStream specifics into the batch path.** `BatchOrchestratorConfig` (`batch.go:46`) requires a `*natsevents.Client` directly — not the abstract `EventService` interface. This means the batch orchestrator cannot use the Redis Streams fallback bus. If Redis Streams is truly a supported fallback (it's advertised in ARCHITECTURE.md), either the batch orchestrator should work through the abstract interface, or the Redis fallback documentation should note this limitation.

**No API versioning strategy beyond `/v1/`.** All routes sit under `/v1/` (`openapi.yaml`), which is fine today, but there's no mechanism for introducing `/v2/` endpoints with breaking changes. The OpenAPI spec and handler registration should anticipate version coexistence.

---

## 2. Code Quality

### Strengths

**Interface-first design throughout.** With ~140 interfaces across the non-test codebase, nearly every dependency boundary is defined as a narrow interface. Examples:
- `MailboxProvider` (poller.go:40) — only `Kind()`, `ListMailboxes()`, `FetchNew()`
- `Pseudonymizer`, `FreeDomainSet`, `DisposableDomainSet` (normalizer.go:21-37)
- `CampaignStore`, `SimulationSender` (simulation.go:20-31)
- `DistributedLock`, `LockFactory` (worker.go:22-33)

This keeps packages decoupled and makes testing trivial with small fakes.

**Consistent config pattern.** Every service follows the `XxxConfig` struct → `NewXxx(cfg)` constructor → validate-and-default pattern. `OnboardingConfig`, `RelationshipJobConfig`, `BatchOrchestratorConfig`, `EngineConfig` — they all validate required fields, default optional ones, and return descriptive errors. This makes the codebase predictable for anyone familiar with one package.

**Zero TODO/FIXME/HACK markers in production code.** `grep` finds none in non-test Go files. This is rare and signals discipline about not shipping known debt markers.

**Minimal `panic` usage.** Panics are limited to startup (`MustLoad`, `MustNew` wrappers called only from `main()`), a defensive check in `newPgPruner` (allow-list enforcement), and an unreachable default in a circuit breaker state switch. None are in hot paths.

**Strong doc comments.** Repository interfaces in `types.go:262-307` have multi-paragraph docstrings explaining zero-value semantics for `since` and `limit`, how in-memory vs Postgres backends must behave identically, and the optimistic-concurrency contract on `UpdateCountsIfFresh`. This level of documentation on interfaces is unusual and valuable.

### Concerns

**Three parallel classification code paths.** `ClassifyUserSensitivity` (onboarding.go, inline `containsAny`), `KeywordClassifyInput` (sensitivity_classifier.go, `sensitivityKeywords` map), and `RoleRiskFromTitle` (vulnerability.go, token-phrase matching) all classify users by job title keywords but use different data structures and matching strategies. After the A0.1-A0.12 work, the first two are synchronized — but they *can* drift again because there's no shared source of truth. The `sensitivityKeywords` map and the `switch` statement in `ClassifyUserSensitivity` are two separate declarations of the same domain knowledge.

*Recommendation*: Extract a single `KeywordRuleset` that both `ClassifyUserSensitivity` and `KeywordClassifyInput` consume. `RoleRiskFromTitle` uses token-matching intentionally (different granularity), so it can remain separate but should reference the shared ruleset where categories overlap.

**`RiskSignals` struct is growing unbounded.** At 30+ fields (`risk_signals.go:58-108`), this struct is a bag of booleans, strings, and ints that every pipeline stage reads from and some stages write to. It's serialized as JSON across the event bus, so every new signal adds a field to every message. There's no grouping (auth signals, behavioral signals, directory signals are interleaved) and no versioning.

*Recommendation*: Group into sub-structs (`AuthSignals`, `BehavioralSignals`, `DirectoryContext`) and consider a signals envelope with a version field for forward compatibility across deployments.

**Positional mapping in encoder batch response.** `EncoderSensitivityClassifier.ClassifyBatch` (sensitivity_classifier.go:300-310) maps results by array index, ignoring the `Index` field the Python encoder returns. This is correct today because the Python endpoint preserves order — but it's fragile. If the encoder ever parallelizes internally or reorders results, the Go client silently misclassifies users.

---

## 3. Security

### Strengths

**Privacy-by-design is genuine, not cosmetic.** The privacy layer (`pkg/privacy/`) implements:
- **Pseudonymization** via Blake2 with per-tenant derived keys
- **Envelope encryption** (AES-256-GCM) with KMS-wrapped per-tenant DEKs
- **Cryptographic erasure**: `Forget(tenantID)` drops the cached DEK, `KMSClient.ForgetKey` deletes the CMK alias → all tenant data becomes unrecoverable
- **Log sanitization** via a dedicated `Sanitizer` that strips PII patterns before slog output
- **JWT-scoped action tokens** for banner interactions, so user clicks don't expose tenant-wide API keys

The `Privacy` facade (`privacy.go:13-24`) bundles all of these behind a single construction point so callers can't accidentally skip a layer.

**Auth middleware fails closed.** `JWTAuth.ServeHTTP` (auth.go:90-92) returns 401 when the issuer is nil, not 200. This means a misconfigured deployment (no JWT secret) rejects all authenticated requests rather than silently allowing them. The skip-path mechanism uses exact matches + prefix matches — no regex, no wildcards that could be exploited.

**Database schema enforces invariants.** CHECK constraints on `score BETWEEN 0 AND 100`, `sensitivity_tier IN (...)`, `risk_class IN (...)`, and `threshold_blocked > threshold_high > ... > threshold_info` catch bad data at the Postgres level, not just in application code. The migration down scripts (`0012_expand_sensitivity_tiers.down.sql`) correctly remap new enum values before reinstating the old CHECK constraint.

**Container runs as nonroot.** The Dockerfile uses `gcr.io/distroless/static-debian12:nonroot` with `USER nonroot:nonroot`. No shell, no package manager, no escalation path.

### Concerns

**DEK cache has no TTL or size bound.** `kmsEncryptor.cache` (`encryptor.go:57`) is a `map[string]cachedKey` protected by `sync.RWMutex`. There's no eviction — once a tenant's DEK is decrypted, it lives in memory forever. In a multi-tenant deployment with thousands of tenants, this becomes a memory leak (each DEK is 32 bytes + wrapped blob, so the per-entry cost is small, but the map never shrinks).

*Recommendation*: Add an LRU or TTL-based eviction policy. Even a simple "last-accessed" timestamp with periodic sweeps would bound growth.

**`CORS_ALLOWED_ORIGINS=*` in `.env.example`.** The default CORS configuration allows any origin. While `.env.example` is not production, it sets the template that operators copy. A wildcard CORS combined with cookie-based or bearer-token auth is a classic misconfiguration vector.

*Recommendation*: Default to an empty or localhost-only origin list in the example, with a comment explaining that production must set explicit origins.

**`BANNER_TOKEN_SECRET=replace-me-with-a-strong-secret`** in `.env.example` is a placeholder that will get deployed as-is by inattentive operators. Consider requiring the value via validation in `config.Load()` for production environments (`IsProduction()` already exists).

**`IsInternal` / `IsExternal` semantics are ambiguous.** The docstring says `IsExternal: convenience boolean = !IsInternal`, but both are independently settable `bool` fields in the JSON struct. The ATO heuristic and the gate rely on `IsInternal` meaning "sender is in the tenant directory," but nothing enforces mutual exclusivity. Tests set both to `true` simultaneously (which contradicts the doc). This isn't a security vulnerability today — the gate only calls ATO for internal senders — but the ambiguity could lead to bypass bugs in future code that trusts `IsExternal`.

---

## 4. Scalability

### Strengths

**Consumer group architecture scales horizontally.** Each JetStream consumer group (e.g., `evaluate-svc`) can be served by multiple replicas of the binary. Messages are partitioned by the broker — no application-level sharding needed. The poller uses per-(tenant, mailbox) distributed Redis locks, so adding replicas divides the mailbox-polling workload.

**Circuit breakers on every outbound call.** Tier 1, Tier 2, and Rspamd each have dedicated `CircuitBreaker` instances (`evaluator.go` Config). The breaker is concurrency-safe (mutex + atomics for metrics), configurable per-tenant, and uses the standard closed→open→half-open state machine. This prevents a single slow downstream from cascading into full pipeline stalls.

**Batch orchestrator for Tier 1.** `BatchOrchestrator` (`batch.go`) fetches N messages from JetStream, applies Tier 0 per-message, batches the survivors to the encoder's `/predict/batch` endpoint, then fans out Tier 2 fallback only for escalated messages. This amortizes HTTP overhead and GPU inference cost.

### Concerns

**No backpressure signal from evaluation to ingestion.** The poller publishes `es.evaluate.request` events as fast as it can fetch from mailbox APIs. If the evaluation pipeline is overloaded (Tier 1 encoder at capacity, Tier 2 LLM queue deep), messages accumulate in the JetStream stream with no feedback to slow ingestion. The rate limiter in `pkg/events/rate_limiter.go` exists but isn't wired into the polling loop.

*Recommendation*: Implement a flow-control mechanism — either monitor JetStream consumer lag and throttle polling when lag exceeds a threshold, or use a bounded semaphore in the poller's publish path.

**Relationship worker scans entire tenant communication history.** `RelationshipJob` iterates all tenants, then for each tenant calls `ListByTenant` with a 30-day window and a per-tenant cap (default 1000). For tenants with high email volume, 1000 rows per cycle may be insufficient; for many tenants, the sequential tenant-by-tenant scan becomes a bottleneck.

*Recommendation*: Consider partitioning work across replicas (e.g., hash-based tenant assignment) rather than relying solely on the distributed lock to serialize.

**No connection pooling configuration for outbound HTTP.** The Tier 1 `Client` (`encoder.go:69-74`) creates a raw `http.Client{Timeout: v.BatchTimeout}` with default transport settings. Go's `DefaultTransport` has `MaxIdleConnsPerHost: 2`, which means under high concurrency, connections are constantly being established and torn down to the encoder.

*Recommendation*: Configure `http.Transport` with appropriate `MaxIdleConns`, `MaxIdleConnsPerHost`, and `IdleConnTimeout` for the expected concurrency.

---

## 5. Testing

### Strengths

**High test file ratio.** 114 test files for 321 source files (35% ratio). ~24K lines of test code against ~73K total. Major packages have dedicated test files covering the primary code paths.

**Test-friendly architecture.** The narrow-interface design means tests inject small fakes rather than pulling in real infrastructure. Examples: `NoopLock` for the poller, `staticFreeDomains`/`staticDisposableDomains` for the normalizer, `Clock` function fields for deterministic time. The `MetricsRecorder` interface in the worker package avoids importing Prometheus in tests.

**Race detection enabled by default.** `Makefile` uses `GOTEST_FLAGS ?= -race -timeout 120s`. Every `make test` invocation runs with the race detector. Given the 245 references to concurrency primitives (mutexes, goroutines, atomics) in non-test code, this is essential.

**Testcontainers integration tests exist.** 22 references to `testcontainers` in test files indicate that real Postgres/NATS/Redis are tested, not just mocks.

### Concerns

**No coverage reporting in CI (visible).** `make cover` exists but there's no `.github/` CI configuration in the repo. Coverage is a local-only concern — there's no gate preventing regression.

*Recommendation*: Add CI (GitHub Actions or similar) with coverage reporting and a minimum coverage threshold.

**Python encoder has no visible test suite.** `deployments/encoder/app/app.py` (504 lines) implements the `/predict`, `/predict/batch`, and `/classify/roles` endpoints plus keyword classification. There are no `test_app.py` or `pytest` fixtures. The keyword classifier logic — which is safety-critical (it determines sensitivity tiers) — is tested only indirectly through Go integration tests.

*Recommendation*: Add a pytest suite for the encoder, testing at minimum: keyword classification across all tiers, degraded-mode behavior, batch response ordering, and LRU cache correctness.

**Test data uses hardcoded dates.** The `TestPoller_RunOnce_PublishesEvaluateRequests` failure (fixed in PR #23) was caused by a hardcoded `2026-05-17` that drifted past the lookback window. While the sibling test (`TestPoller_SkipsOlderThanCheckpoint`) is safe due to pre-seeded checkpoints, the pattern of embedding absolute dates in tests is fragile. Any future test that interacts with time-windowed logic should use `time.Now()` or an injected clock.

---

## 6. Operational Readiness

### Strengths

**Comprehensive Prometheus instrumentation.** `pkg/telemetry/metrics.go` defines ~30 metric families covering every pipeline stage: banner renders, tier latencies, event bus throughput, worker cycles, HTTP requests, ingestion polling, and provider-side actions. Metric labels are deliberately low-cardinality (e.g., `tier2OutcomeLabel` bucketing to "ok"/"flagged" instead of raw category strings — `evaluator.go:381-393`).

**Health and readiness probes.** `/healthz` (liveness) and `/readyz` (readiness with per-dependency checks for NATS, Redis, Postgres) are standard Kubernetes-compatible probes. The readiness probe returns 503 when any required dependency is unavailable — deployments behind a load balancer automatically drain unhealthy instances.

**Structured logging with slog.** The entire codebase uses `log/slog` with JSON format in production. 185 warn/error log sites across non-test code. Context keys (`slog.String("message_id", ...)`, `slog.String("worker", name)`) are consistent. The privacy `Sanitizer` scrubs PII before log emission.

**OpenAPI spec maintained in sync.** `make openapi-check` (called by `make lint`) enforces that `api/openapi.yaml` and the embedded `internal/handler/openapi.yaml` are identical. The 842-line spec covers all 7 endpoint groups with schemas and examples.

### Concerns

**OpenTelemetry tracing is minimal.** Only 12 references to OTel/tracing in non-test code — mostly in `pkg/telemetry/tracer.go` and middleware. The evaluation pipeline (the most latency-sensitive path) doesn't create spans for Tier 0 → Tier 1 → Tier 2 → Rspamd fanout. Without distributed tracing, debugging slow evaluations in production requires correlating log timestamps manually.

*Recommendation*: Instrument the `Evaluate()` method with child spans for each tier, including the parallel Rspamd/Tier 1 fanout. The correlation ID already propagates through the pipeline — it just needs to be wired to OTel context.

**No CI pipeline in the repository.** No `.github/workflows/`, no `.gitlab-ci.yml`, no `Jenkinsfile`. Tests, lint, and builds rely on the developer running `make all` locally. This means there's no automated gate on PRs, no test-on-merge, and no published test results.

**No Helm chart or Kubernetes manifests.** The repo has a `Dockerfile` and `docker-compose.yml` (dev infra only), but no production deployment manifests. NATS, Redis, and Postgres are assumed to exist; there's no documentation on how to provision them or what NATS stream configuration is required (replication, retention, max-age).

---

## 7. Dependency Management

### Strengths

**go.mod is clean.** 89 lines, well-organized. Key dependencies are modern and maintained:
- `nats.go` v1.52.0 (latest stable)
- `pgx` v5.9.2 (the recommended Postgres driver)
- `redis/go-redis` v9.19.0
- `prometheus/client_golang` v1.23.2
- `testcontainers-go` for integration tests

**No vendored dependencies.** The repo uses Go modules without a `vendor/` directory, which is the standard Go approach. `make tidy` is available.

**Python encoder dependencies are minimal.** FastAPI, ONNX Runtime, transformers (tokenizer only), numpy, Prometheus client, Pydantic — all standard ML serving stack components.

### Concerns

**Python dependencies are not pinned.** `deployments/encoder/` has no `requirements.txt`, `pyproject.toml`, or `poetry.lock` visible in the tree. The Dockerfile for the encoder presumably installs dependencies, but without pinned versions, builds are non-reproducible.

*Recommendation*: Add a `requirements.txt` or `pyproject.toml` with pinned versions (including hashes for `pip install --require-hashes`).

**`go.sum` is referenced in Dockerfile `COPY go.mod go.sum* ./` with a glob.** The wildcard means a missing `go.sum` won't fail the build — `go mod download` will regenerate it, but the result may differ from what was tested locally.

---

## 8. Design Patterns — Notable & Unusual

**Provider registry with RWMutex hot-swap.** `providers.go` implements a thread-safe registry that can hot-reload Gmail/Outlook provider clients at runtime (e.g., when OAuth tokens are refreshed). The `providerKey{tenantID, kind}` tuple ensures multi-tenant isolation. Degraded fallback providers return empty results rather than errors, so the poller always makes progress.

**Optimistic concurrency on CommunicationHistory.** `UpdateCountsIfFresh` uses a compare-and-swap on `UpdatedAt` — if ingestion has written to the row since the worker loaded its snapshot, the worker's update is silently dropped. This avoids distributed locks on hot rows while ensuring the worker doesn't overwrite fresher ingestion data. The docstring explains the design explicitly, which is excellent.

**Envelope encryption with in-memory DEK cache.** Rather than calling KMS per-encrypt (expensive, adds latency), the encryptor caches unwrapped DEKs and embeds the wrapped DEK in the ciphertext blob. This means decryption only needs KMS on cache-miss. The tradeoff (memory-resident plaintext key material) is appropriate for a server-side service with good process isolation (distroless container, nonroot user).

**Label retry queue with exponential backoff.** Failed label applications (Gmail/Outlook API errors) are published as retry events with `backoff = 2^attempt * 30s`. The retry consumer checks `NextRetryAt` and nacks with delay if not ready. Max retries are bounded. This is a proper implementation of retry-with-backoff over an event bus, not a naive loop.

---

## 9. Summary of Key Recommendations

| Priority | Area | Recommendation |
|----------|------|----------------|
| **High** | Architecture | Split `main.go` (~4.2K lines) into focused wiring files |
| **High** | Testing | Add CI pipeline (GitHub Actions) with test/lint/coverage gates |
| **High** | Testing | Add pytest suite for the Python encoder |
| **Medium** | Code Quality | Unify the 3 keyword classification paths behind a shared ruleset |
| **Medium** | Scalability | Wire backpressure from evaluation lag to ingestion polling |
| **Medium** | Security | Add TTL/LRU eviction to the DEK cache |
| **Medium** | Ops | Instrument the evaluation pipeline with OTel spans |
| **Medium** | Dependencies | Pin Python encoder dependencies |
| **Low** | Security | Tighten `.env.example` defaults (CORS origins, banner secret) |
| **Low** | Code Quality | Group `RiskSignals` fields into sub-structs |
| **Low** | Scalability | Configure `http.Transport` pool settings for Tier 1 client |
| **Low** | Ops | Add Kubernetes deployment manifests / Helm chart |

---

## 10. Overall Assessment

This is a well-architected system with genuine engineering depth. The privacy layer, degradation model, circuit breakers, and interface-driven design reflect mature thinking about production email security systems. The multi-tier detection pipeline is the right abstraction for balancing cost, latency, and accuracy.

The main risks are operational: no CI, no deployment manifests, and limited distributed tracing will create friction as the team scales. The `main.go` monolith and the triplicated keyword logic are the two code-quality items most likely to cause bugs in future development.

The codebase is in strong shape for a system at this stage — the foundations (event bus abstraction, privacy primitives, configuration management, interface design) are all built to grow.
