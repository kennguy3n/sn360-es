# sn360-es Cost Model

> **Recalibrated 2026-06-01** after WS-2a (read-replica routing,
> PR #57) and WS-2b (HASH partitioning of `communication_histories`,
> PR #58) shipped. The numerical cells in the headline table and
> the 5 000-tenant enterprise anchor moved; the methodology, lever
> taxonomy, and Tier 0 / 1 / 2 routing model are unchanged. See
> `scripts/cost_model/project.py` header comment for the source
> URLs of every AWS list price the table is computed against.

This document captures the per-tenant cost projection that the
sn360-es review plan calibrated against the cost levers landed
in PR #44 (tenant-isolation hardening), PR #45 (worker pagination
+ Redis rate limiter + Tier 1 batch default-on + native PG
partitioning), PR #46 (role-split + KEDA on consumer lag +
PgBouncer sidecar), PR #57 (WS-2a read-replica routing), and
PR #58 (WS-2b HASH partitioning of `communication_histories`).

The model is intentionally simple and reproducible. A single
Python script — `scripts/cost_model/project.py` — emits a JSON
record per (traffic profile, lever set) combination. The script
has zero external dependencies, no network calls, and is
deterministic, so the figures below can be regenerated at any
time by:

```sh
python3 scripts/cost_model/project.py --profile all --out benchmarks/cost_model.json
```

The regression test suite at `scripts/cost_model/test_project.py`
pins the structural invariants (lever-on cheaper than baseline,
savings scale with traffic, every cost lever moves the right
component) so a future cloud-price refresh or lever rework
can't quietly shift the numbers without the diff updating both
the script and the tests.

## Headline numbers

USD per tenant per month at three representative traffic
profiles, with all WS-2-era levers active versus a pre-PR #44
baseline.

| Profile    | Messages / tenant / day | Baseline (pre-PR #44) | All levers on (post-WS-2b) | $/tenant/mo saving | % saving |
| ---        | --: | --: | --: | --: | --: |
| low        |     200 | $0.641   | $0.416   | $0.225   | 35.1% |
| medium     |   1 200 | $3.772   | $2.412   | $1.360   | 36.0% |
| high       |   8 500 | $45.490  | $31.566  | $13.924  | 30.6% |
| enterprise |  15 000 | $148.839 | $104.237 | $44.601  | 30.0% |

Percentage savings peak at the `medium` cohort (36.0 %) and
descend from there toward the high / enterprise cohorts (30.6 %
and 30.0 %). Two effects compose to produce that shape:

1. From `low` (35.1 %) upward, raising message volume engages
   the variable-cost levers — Tier 1 batching efficiency,
   PG partitioning storage / write multipliers, and the
   role-split + KEDA-on-lag compute floor — against a larger
   denominator, so the % savings grows.
2. Once message volume crosses into the `high` and
   `enterprise` cohorts, the Bedrock Tier 2 token cost
   (proportional to escalated messages and not affected by
   *any* compute / storage lever) starts to dominate the
   total, so the levers amortise less aggressively against
   that token line and the % savings descends.

Those high-volume cohorts still gain the largest *absolute*
dollar savings per tenant — $13.92 (high) and $44.60
(enterprise) versus $1.36 (medium) and $0.23 (low) — they just
trade them off against a larger Tier 2 token baseline. Prior
to the WS-2c recalibration the savings curve was monotonically
descending (33.7 % → 32.6 % → 25.1 % → 22.6 %); the WS-2b HASH
partitioning consumer-CPU drop and the tightened
`partitioning_active` multipliers compounded against the
`medium` cohort's profile mix in a way that nudged it above
`low`. Both shapes are consistent with the model's
architecture — high-volume cohorts always pay a larger share
of their total in Tier 2 tokens — the WS-2c numbers just make
the inflection visible on the headline table.

The `enterprise` row is the 5 000-tenant scale-out anchor: the
load tests in `tests/load/` drive this same 15 000 msg / tenant /
day workload, and the `test_5000_tenant_density` regression in
`scripts/cost_model/test_project.py` pins the structural
invariants (lever savings ≥ 20 %, density amortisation in the
right direction, Tier 1+2 inference budget bounded). When the
density is 5 000 tenants per deployment (vs the 1 000-tenant
default the table is computed against), shared Redis / PG /
NAT GW lines amortise across more tenants, dropping the
enterprise per-tenant figure to roughly **$104.07 / month** —
down from **$115.12 / month** before the WS-2c recalibration
(a 9.6 % reduction). The `test_post_ws2_density_delta`
regression in `scripts/cost_model/test_project.py` pins this
improvement at ≥ 8 %; see the WS-2c calibration notes below for
the coefficient / multiplier evidence the figure rests on.

Both columns use the architecturally-bounded Tier 0 bypass model
(post-2026-05 PR #47 refinement): the lever's hit rate is capped
by the profile's structural eligibility ceiling
(`pct_internal + pct_known_partner`) so cold-call external mail
can never be bypassed regardless of cache health. High-traffic
tenants therefore get a smaller absolute bypass benefit than low-
traffic tenants — they have proportionally more cold-call mail to
begin with.

## How to read each component

Every record in `benchmarks/cost_model.json` carries a `breakdown`
(USD by component) and a `telemetry` block (the underlying
message-routing numbers the breakdown was derived from). The
components, in order of contribution to the high-cohort total:

1. **tier2** — Bedrock token cost for Tier 2 escalations.
   Proportional to `messages × (1 - tier0_bypass) × tier2_pct`.
   The Tier 0 bypass lever (post-PR #44 AI cache, tenant-scoped)
   cuts this directly.
2. **postgres** — RDS instance + gp3 storage. PgBouncer cuts the
   shared-instance baseline by ~60% on idle connection budget;
   native partitioning takes 20% off the write I/O budget by
   eliminating the full-table cleanup-worker scan.
3. **s3** — Object storage for raw email blobs. Lever-independent
   in this model (no PR #44–#46 lever changes the retention
   curve), but a large absolute line item at high traffic. A
   future PR could add Glacier tiering past 90 days; not in the
   current backlog because the operational complexity isn't
   worth the marginal saving at single-digit-dollar-per-tenant
   cohorts.
4. **tier1** — Tier 1 encoder cost. The batch lever
   (`TIER1_BATCH_ENABLED=true`, default-on as of PR #45) drops
   amortised per-message cost to 30% of the per-message inference
   cost, as validated in `benchmarks/BASELINE.md`.
5. **kms** — Decrypt requests for per-tenant envelope encryption.
   Proportional to message volume; no lever affects it.
6. **redis** — ElastiCache for AI cache + rate limiter buckets.
   Shared shape, amortised across the deployment's tenant count
   (default 1000). The Redis rate-limiter backend lever
   (`RATE_LIMIT_BACKEND=redis`, PR #45) doesn't change Redis
   cost — the win is on the compute side via tighter API role
   autoscaling.
7. **compute** — Container vCPU + memory. Role split + KEDA on
   NATS lag together drop consumer-role replica-seconds by ~15%
   at steady state versus CPU-target HPA.

   **Caveat — role-split alone increases compute on a small
   deployment.** Three separate Deployments (api / consumers /
   workers) each carry their own `minReplicas` floor, so a
   stand-alone role split adds at minimum 2 extra replicas of
   baseline runtime versus the previous monolith Deployment.
   The ~15% net saving comes from KEDA scaling the `consumers`
   Deployment _down_ to its floor (1 replica) when NATS lag is
   zero — the monolithic Deployment couldn't do that because
   API liveness traffic kept the whole pod set above CPU-target.
   Role-split and KEDA-on-lag are therefore claimed as a single
   *combined* lever; the baseline-off snapshot in
   `scripts/cost_model/project.py` toggles them together.

   At the per-tenant unit-economics level the levers-on profile
   is still strictly cheaper than baseline-off — the regression
   suite pins this invariant via
   `test_levers_on_strictly_cheaper` in
   `scripts/cost_model/test_project.py`. The reason is that
   savings from Tier 0 bypass (tenant-scoped cache hit-rate),
   Tier 1 batch amortisation, native PG partitioning, and
   PgBouncer connection multiplexing outweigh the extra replica
   floor at the 1000-tenant density the chart is designed for.
   See "Tenant density" further down for how the breakeven moves
   with `tenants_per_deployment`.
8. **egress** — NAT GW egress + hourly NAT GW shape. The hourly
   shape is shared across tenants; egress scales with outbound
   webhook + Bedrock invocation volume.

## What each lever does

| Lever | PR | Effect on cost model | Effect on prod |
| --- | --- | --- | --- |
| Tenant-scoped AI cache | PR #44 | `tier0_bypass_hit_rate` 0.10 → 0.68 | Two tenants no longer share verdicts; closes cross-tenant correctness + cost-side-channel |
| Tier 1 batch default-on | PR #45 | `tier1_batch_efficiency` 1.00 → 0.30 | Encoder amortises across a 64-message batch; per-message cost drops to ~30% |
| Worker keyset pagination | PR #45 | (Not a direct cost lever — survives 10k+ tenants without OOM.) | `Tenants.IterateActive` instead of `Tenants.List(ctx,0)`; bounded batches of 256 |
| Native PG partitioning + WS-2b HASH | PR #45 + PR #58 | `partitioning_active` → 0.72x storage + 0.70x write I/O | DROP PARTITION at O(1) vs row-by-row DELETE on the append-only tables (PR #45); HASH partitioning of `communication_histories` by `tenant_id` into 32 partitions keeps per-partition heaps small so autovacuum keeps up and tenant-scoped DML prunes to one partition (PR #58) |
| Redis cluster rate limiter | PR #45 | `rate_limiter_backend` redis → tighter API-role autoscale | Cluster-wide buckets; replicas can scale to floor without bucket-eviction concern |
| Role-split + KEDA on lag | PR #46 | `role_split_active` + `keda_on_lag` → 0.85x consumer compute | Slow Tier-2 SLM call no longer stalls API request handlers; consumer autoscale tracks actual queue depth |
| PgBouncer sidecar | PR #46 | `pgbouncer_active` → 0.40x shared idle connection budget | 50:1 transaction-pooled multiplexing; smaller RDS shape supports same fleet |
| Postgres read-replica routing | PR #57 | API role coefficient 0.05 → 0.04 vCPU-hr / month / kmsg / day | Dashboard list-queries route to a Postgres replica via `PG_READ_HOST`; tenant-scoped reads stay on the writer for RLS; writer no longer contends with management read traffic so the API HPA scales tighter |

## Calibration & assumptions

**Prices** are 2026-05 AWS us-east-1 list prices, re-verified
against the AWS public pricing API on 2026-06-01 as part of the
WS-2c recalibration. Every per-instance, per-GB-month, per-request,
and per-1k-token list price was unchanged from the 2026-01
snapshot — the WS-2c diff therefore touches only the source-URL
citations in `project.py` for prices, while the architectural
coefficients moved to absorb the WS-2a / WS-2b shipping (see
below). The full source-URL block (with offer publication dates)
lives at the top of `project.py`. We use:

- EC2 c7g.xlarge per-vCPU on-demand (publication 2026-05-29)
- RDS db.r7g.large per-vCPU (publication 2026-05-31)
- ElastiCache cache.r7g.large per-GB (publication 2026-05-30)
- NAT GW per-GB + hourly (publication 2026-05-29)
- S3 gp3 storage + PUT-per-1k (publication 2026-05-28)
- Bedrock Claude 3 Haiku input / output per 1k tokens
  (publication 2026-05-29; output rate cited against the
  AWS Bedrock pricing page directly since the output SKU is
  not surfaced via the us-east-1 pricing API offer)
- KMS request per 10k (publication 2025-08-28; the symmetric
  request rate has been stable since)

**WS-2c coefficient recalibration.** WS-2a (PR #57) and WS-2b
(PR #58) shipped between the 2026-01 baseline and the 2026-06-01
refresh. The per-role compute coefficients in `project.py`
absorb both changes:

- `API_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY`: 0.05 → 0.04. The
  read-replica routing in PR #57 (commit 5604788) moves unbound
  management read traffic off the writer pool, so each API
  replica services more requests at the same wall-clock CPU
  budget. The 20 % reduction tracks the writer-pool-contention
  analysis in the PR (`pkg/storage/postgres/postgres.go`
  routing matrix); the single-tenant microbenchmarks in
  `benchmarks/bench_20260517.txt` continue to anchor the
  pre-recalibration 0.05 figure.
- `CONSUMER_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY`: 0.18 → 0.135.
  HASH partitioning of `communication_histories` by `tenant_id`
  into 32 partitions (PR #58 migration 0019, commit b637bf7)
  prunes tenant-scoped DML to a single partition and keeps
  per-partition B-trees small enough that index lookups remain
  hot in cache at 5 000 tenants. The 25 % reduction tracks the
  partition-pruning analysis in the migration's header comment.
- `WORKER_VCPU_HOURS_PER_MONTH`: 0.02 (unchanged). The singleton
  worker performs partition maintenance, retention sweeps, and
  DLQ replay — none of which are read- or write-pool contention
  sensitive at the WS-2 traffic shape.
- `partitioning_active` storage multiplier: 0.85 → 0.72. PR #45's
  tighter-retention multiplier (0.85) compounds with WS-2b's
  per-partition bloat reduction (~0.85): autovacuum keeps up
  with dead tuples on the smaller per-partition heap of
  `communication_histories` instead of falling behind on one
  giant heap. See the `cost_postgres` docstring for the
  decomposition.
- `partitioning_active` write-CPU multiplier: 0.80 → 0.70.
  PR #45's cleanup-worker no-longer-scans-the-entire-table
  effect (0.80) compounds with WS-2b's HASH-pruning + index-
  depth reduction (~0.875): each Upsert touches a 32x smaller
  per-partition B-tree, so the read side of the upsert round-
  trip stays in cache far more often than against the
  un-partitioned heap.

The combined effect on the 5 000-tenant enterprise anchor is a
9.6 % per-tenant cost reduction ($115.12 → $104.07 / month).
The `test_post_ws2_density_delta` regression in
`scripts/cost_model/test_project.py` floors this at 8 %; a
future cloud-price refresh that compresses the delta below 8 %
must update the floor (and the comment trail at the top of
`test_project.py`) deliberately, not silently.

**Tenant density**: shared infrastructure (Redis, PG instance
baseline, NAT GW) is amortised across a default 1 000 tenants
per deployment. This is the tier we've designed the role-split
Helm chart for. The model exposes `tenants_per_deployment` as
a parameter — re-run the script with a different `--tenants`
arg if you're sizing a smaller or larger pod.

**Traffic profiles** are calibrated against the per-tenant
average for representative customer cohorts: 200 msgs/day for
SMB pilots, 1 200 for production SMB, 8 500 for mid-market.
Enterprise-scale (10k+) tenants typically run on a dedicated
deployment shape and aren't modelled here.

**What the model does NOT cover**:
- Cross-region replication cost (DR / data residency).
- AI agent inference (LLM tool-using agents in
  `internal/service/agent/`) — these run on a separate cost
  surface from Tier 0/1/2 evaluation.
- Engineer-on-call cost; the autonomous-ops PrometheusRule + AI
  agent surface is designed to keep that at zero.
- Glacier tiering for raw email past retention; a future model
  refresh could add this for the high cohort.

## Reproducibility checks

```sh
# Regenerate the JSON output
python3 scripts/cost_model/project.py --profile all --out benchmarks/cost_model.json

# Run the regression tests (file-path form matches CI in
# .github/workflows/ci.yml and avoids relying on PEP 420 namespace
# package discovery, which depends on cwd being a parent of
# `scripts/`).
python3 -m unittest scripts/cost_model/test_project.py -v

# Render the headline table from the JSON
python3 -c '
import json
d = json.load(open("benchmarks/cost_model.json"))
for r in d["records"]:
    print(f"{r[\"profile\"]:6s} | {r[\"levers\"]:28s} | total ${r[\"total_per_tenant_month_usd\"]:7.3f}")
'
```

The script is deterministic — the same inputs always produce
the same outputs. The regression tests pin both structural
invariants (every lever-on projection strictly cheaper than its
baseline-off peer; savings monotone in traffic; per-component
levers move the right components) and the message-routing
invariant (`bypassed + tier1 == total`).
