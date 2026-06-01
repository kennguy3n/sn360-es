# tests/load

End-to-end load harness for sn360-es. Implements WS-6a (see
`internal/docs/PRODUCT_PLAN.md` §6a).

The harness exercises the ingest → JetStream → consumer → Tier 0/1/2 → action
pipeline at three traffic profiles drawn from the cost-model
(`scripts/cost_model/project.py`):

| Scenario   | Cost-model profile | Tenants × msgs/tenant/day | Sustained rate | Expected p99 | NATS lag bound |
|------------|--------------------|---------------------------|----------------|--------------|----------------|
| `baseline` | `low`              | 5,000 × 200               | ≈ 11.6 msg/s   | 2.0 s        | 200 pending    |
| `typical`  | `medium`           | 5,000 × 1,200             | ≈ 69.4 msg/s   | 2.5 s        | 1,500 pending  |
| `peak`     | `high`             | 5,000 × 8,500             | ≈ 491.9 msg/s  | 4.0 s        | 10,000 pending |

`smoke` is a tightened-envelope variant of `baseline` (2 minutes, 32 tenants,
fixed seed) used for CI gating on every PR. `soak` is a 30-minute hold of the
`typical` profile gated to manual `workflow_dispatch` triggers in
`.github/workflows/load.yml`.

## What gets captured

Per the WS-6a brief every run captures six metric families and persists them
into `tests/load/results/<scenario>-<unix_ts>.json` alongside the k6 summary:

1. **End-to-end latency p50 / p95 / p99** — `loadgen_publish_latency_ms`
   trend recorded by k6 (publisher round-trip), plus the `http_req_duration`
   default histogram. The full pipeline latency is captured by the
   `sn360_es_evaluate_latency_seconds` histogram (visible in the Grafana
   dashboard's "Evaluate" row).
2. **NATS JetStream consumer lag** — queried two ways: first via Prometheus
   (`nats_jetstream_consumer_num_pending`), then via NATS' own `/jsz`
   monitoring endpoint as a fallback if the Prometheus exporter has not yet
   scraped. The expected bound per scenario is in the table above.
3. **Postgres connection count** — both PgBouncer client-side and server-side
   pools (`pgbouncer_client_connections`, `pgbouncer_server_connections`).
   Falls back to `pg_stat_activity_count` if PgBouncer's exporter is not
   deployed (the dev stack).
4. **Redis memory usage** — `redis_memory_used_bytes`.
5. **Tier 1 / Tier 2 queue depth** — `nats_jetstream_consumer_num_pending`
   filtered by consumer-name label (`consumer_name=~".*tier1.*"` and
   `tier2.*`).
6. **Tier 2 SLM call concurrency** — `sn360_es_tier2_inflight_requests`,
   the gauge introduced in this PR (see `pkg/telemetry/metrics.go`). Counts
   in-flight Tier 2 calls; a sustained high value is the canonical signal
   that the SLM is the pipeline bottleneck.

Each metric family records `value`, `source` (the Prometheus query string or
fallback URL), and series count, so a reader can tell "no data" from
"actually zero". Missing infrastructure is recorded as `value: null` plus an
entry in `metrics_snapshot.errors`.

### Prometheus reachability is best-effort

Every artefact carries a top-level `metrics_collection_status` field
(mirrored on `metrics_snapshot.prometheus_status`) with one of three values:

* `available` — every Prometheus query returned a usable response.
* `partial` — some Prometheus queries succeeded, some did not.
* `unreachable` — zero Prometheus queries succeeded; usually means
  `$LOAD_PROM_URL` is offline.

The schema is stable in all three cases: every family key is present on
`metrics_snapshot.families`, either with a captured object or with `null`.
This is what lets CI smoke (which intentionally runs without a Prometheus
backend) still produce a valid artefact and pass the workflow's shape
check.

The `soak` target requires a populated metrics backend, since a 30-minute
soak with all-null metrics is not useful for the "did we leak?" question it
exists to answer. Enforcement is split across two layers so the artefact is
never lost:

* `soak.js` itself prints a loud stderr warning when status is
  `unreachable` but still writes the full artefact (the k6-side
  publish counts, latency, throughput drift are valuable for diagnosing
  *why* Prom is unreachable).
* The `.github/workflows/load.yml` scenario job's `Validate artefact`
  step fails the workflow when soak's `metrics_collection_status` is
  not `available`. The artefact is uploaded before this step decides
  pass/fail (the upload uses `if: always()`), so a flaky-Prom soak
  still leaves a downloadable artefact for offline analysis.

Set `LOAD_SOAK_ALLOW_NO_PROM=1` as an escape hatch in both layers when
intentionally exercising the harness without Prometheus. `smoke`,
`baseline`, `typical`, and `peak` do not enforce this — they record the
status for diagnostic purposes and otherwise continue.

## How to run a scenario

### Prerequisites

* `make docker-up` to launch NATS, Postgres, Redis, Rspamd, Unbound, ClamAV.
* `make migrate-up` to apply schema.
* `make build` (or `bin/sn360-es`) to compile the main API server.
* `make loadgen-build` to compile `sn360-es-loadgen` (HTTP→NATS shim +
  bootstrap subcommand).

### Pre-provision tenants

```bash
make load-bootstrap                       # full 5,000-tenant pool
LOAD_TENANTS=200 make load-bootstrap      # smaller pool for local exploration
```

Bootstrap is idempotent: rerunning with the same `-prefix` (default
`00000000-0000-0000-0000-`) is a no-op via `ON CONFLICT DO NOTHING`. The
manifest at `tests/load/results/tenants.json` is what the k6 scripts read
to address tenants; the file is regenerated on every bootstrap.

### Launch the publisher

k6 can't speak NATS directly, so we run a small HTTP→JetStream shim in
front of NATS:

```bash
./bin/sn360-es-loadgen publisher \
  -nats-url=nats://127.0.0.1:4222 \
  -bind=127.0.0.1:9099
```

The publisher exposes:

* `POST /publish` — accepts one `dto.EvaluateRequest` JSON body.
* `POST /publish/batch` — accepts an array of `dto.EvaluateRequest`.
* `GET /healthz` — returns 200 once the NATS connection is established.
* `GET /stats` — counters of publish OK / err / last error.

Every publish uses `WithMsgID(message_id)`, so JetStream-side dedupe handles
retries cleanly. The publisher is the only piece of the harness that talks
to NATS; everything else (k6, the metrics queries, the Grafana dashboard)
runs against HTTP endpoints.

### Run a scenario

```bash
make load-smoke      # 2 min baseline-profile smoke against 32 tenants
make load-baseline   # 10 min, 5,000 tenants × 200 msgs/tenant/day
make load-typical    # 10 min, 5,000 tenants × 1,200
make load-peak       # 10 min, 5,000 tenants × 8,500 (batched ×4)
make load-soak       # 30 min, sustained typical profile
```

Every target writes `tests/load/results/<scenario>-<unix_ts>.json`. The
`results/` directory is `.gitignore`d for `.json` artefacts (including the
bootstrap manifest, which is regenerated locally); only `.gitkeep` is
checked in.

### Tunable env vars

The Makefile passes these through to k6 (and to the bootstrap subcommand
where applicable). All are optional; leaving them unset uses the scenario's
default.

| Variable                  | Default                                   | Notes                                            |
|---------------------------|-------------------------------------------|--------------------------------------------------|
| `LOAD_DURATION_MIN`       | scenario-specific (2 / 10 / 30)           | Override the hold duration.                      |
| `LOAD_TENANTS`            | 5000 (32 for smoke)                       | Tenant pool size; affects bootstrap + scripts.   |
| `LOAD_SEED`               | scenario-specific (42 / 7)                | Seeds PRNG for corpus + tenant rotation.         |
| `LOAD_BATCH_SIZE`         | 1 (4 for peak)                            | `POST /publish` vs `POST /publish/batch`.        |
| `LOAD_TENANTS_PATH`       | `tests/load/results/tenants.json`         | Bootstrap manifest the scripts read.             |
| `LOAD_CORPUS_PATH`        | `scripts/corpus/loadtest/all.json`        | WS-4b corpus path (mini-corpus fallback).        |
| `LOAD_PROM_URL`           | `http://127.0.0.1:9090`                   | Prometheus for metric snapshots.                 |
| `LOAD_NATS_MON_URL`       | `http://127.0.0.1:8222`                   | NATS monitoring endpoint fallback.               |
| `LOADGEN_PUBLISHER_URL`   | `http://127.0.0.1:9099`                   | The HTTP→NATS shim.                              |
| `LOADGEN_POSTGRES_URL`    | dev-stack default DSN                     | Bootstrap target Postgres.                       |

## Parameterisation choice (one script per scenario)

The harness uses **one k6 script per scenario** (`baseline.js`, `typical.js`,
`peak.js`) rather than one script with an env-var switch. Each script is a
~25-line wrapper around the shared `runScenario({...})` helper in
`tests/load/lib/scenario.js`. Reasons:

1. The k6 `options` object has to be set at module top-level so VU allocation
   happens before any code runs — an env-var switch would force every script
   to hand-roll the option plumbing.
2. Each scenario has its own threshold ceiling (`expectedP99Ms`); declaring
   them inline keeps the contract per-scenario obvious.
3. WS-6b (chaos engineering) imports `runScenario({...})` to compose its
   chaos-aware variant — one file per scenario keeps the variant point
   small.

`smoke.js` and `soak.js` follow the same pattern, just with a tighter
duration / wider tenant pool respectively.

## Reusable scenario runner

`tests/load/lib/scenario.js` exposes a `runScenario({...})` factory so other
workstreams (notably WS-6b) can compose against the same scenario shape
without copy-pasting plumbing:

```js
import { runScenario } from "../load/lib/scenario.js";

const s = runScenario({ name: "baseline", durationMin: 5, seed: 42 });
export const options = s.options;
export default s.iter;
export function handleSummary(data) {
  return { "result.json": JSON.stringify(s.summary(data), null, 2) };
}
```

`runScenario` accepts `name` (one of `baseline` / `typical` / `peak`), and
optional overrides for `msgsPerSecond`, `durationMin`, `tenants`, `seed`, and
`optionsOverrides`. WS-6b should layer its chaos-injection helpers around
`s.iter` (e.g. wrap it in a function that sometimes simulates a NATS
disconnect) so the scenario shape stays identical between the load harness
and the chaos regression suite.

## Grafana dashboard

`tests/load/grafana/sn360-es-load.json` is a self-contained dashboard with
six rows (Ingest, Evaluate, Tier 2, Postgres, Redis, NATS) and a `$scenario`
template variable that flips between `baseline` / `typical` / `peak`.

Import:

1. Grafana → Dashboards → New → Import → Upload JSON.
2. Pick your Prometheus datasource (the variable is named `$datasource`).
3. Set `$scenario` from the dropdown.

The dashboard is intentionally pinned to the metric families WS-6a captures;
adding new panels should normally be paired with a new family in
`tests/load/lib/metrics.js` so the persisted artefact stays in sync with the
dashboard.

## Release-over-release comparison

Each scenario writes a stable JSON shape to `tests/load/results/`. A typical
release diff looks like:

```bash
# Compare yesterday's typical scenario against today's
PREV=$(ls -1t tests/load/results/typical-*.json | sed -n '2p')
CURR=$(ls -1t tests/load/results/typical-*.json | head -n1)
jq '{
  scenario,
  p99_ms: .k6_summary.loadgen_publish_latency_ms.p99,
  publish_errs: .k6_summary.loadgen_publish_errors.count,
  tier2_inflight: .metrics_snapshot.families.tier2_inflight_requests.value,
  nats_lag: .metrics_snapshot.families.nats_consumer_lag.value
}' "$PREV" "$CURR"
```

Look for:

* **p99 latency regression** — > 10% increase on the same scenario is a
  release-blocker. Smaller drifts indicate Tier 1 / Tier 2 latency shifts.
* **publish_errs** — should stay at 0 across runs; non-zero means the
  publisher is back-pressuring k6, which means JetStream is unhealthy.
* **tier2_inflight** — gauge value should match the configured Tier 2
  concurrency ceiling (default 8). Persistently higher means the gauge is
  not balanced (file a bug); persistently at the ceiling means SLM is the
  bottleneck.
* **nats_consumer_lag** — must stay below the per-scenario bound in the
  table at the top of this README. KEDA should be scaling consumer workers
  to absorb spikes; a flat-line lag means autoscaling isn't reacting.

For trend analysis across many releases, drop the artefacts into a
spreadsheet keyed by `(scenario, started_at)` — the JSON shape is stable so
`jq -s '.[] | {...}'` produces a flat table.

## CI integration

* `.github/workflows/load.yml` job `smoke` runs `make load-smoke` on every
  PR touching `cmd/sn360-es-loadgen/**`, `tests/load/**`, or the metrics
  files that the harness depends on. The job validates the artefact has
  all six families and uploads it as a workflow artifact.
* The same workflow exposes a manual `workflow_dispatch` with a scenario
  dropdown — pick `baseline` / `typical` / `peak` / `soak` from the
  Actions tab to run a heavyweight scenario against a hosted runner. Soak
  is what catches slow leaks; baseline/typical/peak are the release-train
  characterisation runs.

## Bootstrap citation

The bootstrap subcommand lives at `cmd/sn360-es-loadgen/bootstrap.go`. It
generates deterministic tenant UUIDs via a prefix + zero-padded index
(`<prefix><index_as_12_hex>`), batches inserts at 2,000 rows / statement to
stay under Postgres' 65,535 parameter limit, and writes a JSON manifest the
k6 scripts read at init time. Tests under `cmd/sn360-es-loadgen/loadgen_test.go`
cover the `tenantID` generator and the bootstrap edge cases (zero count,
duplicate runs, invalid DSN).

## File layout

```
tests/load/
├── README.md                 # this file
├── smoke.js                  # 2-min baseline smoke (CI gate)
├── soak.js                   # 30-min typical soak (manual)
├── baseline.js               # 10-min, 11.6 msg/s
├── typical.js                # 10-min, 69 msg/s
├── peak.js                   # 10-min, 492 msg/s (batched ×4)
├── grafana/
│   └── sn360-es-load.json    # 6-row dashboard (Ingest / Evaluate / Tier 2 / PG / Redis / NATS)
├── lib/
│   ├── config.js             # SCENARIOS + loadConfig()
│   ├── corpus.js             # WS-4b corpus loader + envelope builder
│   ├── metrics.js            # captureMetrics() — six metric families
│   ├── scenario.js           # buildOptions / runIteration / runScenario / summarise
│   └── seed.js               # deterministic PRNG
└── results/                  # *.json artefacts (gitignored except tenants.json)
```
