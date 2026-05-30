# sn360-es Cost Model

This document captures the per-tenant cost projection that the
sn360-es review plan calibrated against the cost levers landed
in PR #44 (tenant-isolation hardening), PR #45 (worker pagination
+ Redis rate limiter + Tier 1 batch default-on + native PG
partitioning), and PR #46 (role-split + KEDA on consumer lag +
PgBouncer sidecar).

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
profiles, with all PR #44–#46 levers active versus a pre-PR #44
baseline.

| Profile | Messages / tenant / day | Baseline (pre-PR #44) | All levers on (post-PR #46) | $/tenant/mo saving | % saving |
| --- | --: | --: | --: | --: | --: |
| low    |   200 | $0.641  | $0.425  | $0.216  | 33.7% |
| medium | 1 200 | $3.774  | $2.545  | $1.230  | 32.6% |
| high   | 8 500 | $45.509 | $34.065 | $11.445 | 25.1% |

Percentage savings descend with traffic because the Bedrock Tier 2
token cost — proportional to escalated messages and not affected
by any compute / storage lever — dominates the high cohort's
total. The high cohort still gains the largest *absolute* dollar
saving per tenant, but levers like Tier 1 batching and PG
partitioning amortise less aggressively against the Tier 2 token
line at that scale.

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
| Native PG partitioning | PR #45 | `partitioning_active` → 0.85x storage + 0.80x write I/O | DROP PARTITION at O(1) vs row-by-row DELETE; cleanup-worker fallback for partition-worker failures |
| Redis cluster rate limiter | PR #45 | `rate_limiter_backend` redis → tighter API-role autoscale | Cluster-wide buckets; replicas can scale to floor without bucket-eviction concern |
| Role-split + KEDA on lag | PR #46 | `role_split_active` + `keda_on_lag` → 0.85x consumer compute | Slow Tier-2 SLM call no longer stalls API request handlers; consumer autoscale tracks actual queue depth |
| PgBouncer sidecar | PR #46 | `pgbouncer_active` → 0.40x shared idle connection budget | 50:1 transaction-pooled multiplexing; smaller RDS shape supports same fleet |

## Calibration & assumptions

**Prices** are 2026-01 AWS us-east-1 list prices, captured as
constants at the top of `project.py`. A future cloud-price
refresh is a single-file diff and the regression tests catch
the recompute. We use:

- EC2 c7g.xlarge per-vCPU on-demand
- RDS db.r7g.large per-vCPU
- ElastiCache cache.r7g.large per-GB
- NAT GW per-GB + hourly
- S3 gp3 storage + PUT-per-1k
- Bedrock Claude 3 Haiku input / output per 1k tokens
- KMS request per 10k

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
