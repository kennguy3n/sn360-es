#!/usr/bin/env python3
"""Reproducible $/tenant/month projection for sn360-es.

Models the cost levers landed in PR #44 (tenant-isolation hardening),
PR #45 (worker pagination, Redis rate limiter, Tier 1 batch, PG
partitioning) and PR #46 (role-split + KEDA on consumer lag +
PgBouncer) against three traffic profiles. Outputs a JSON record
that benchmarks/COST_MODEL.md cites as ground truth.

Run::

    python3 scripts/cost_model/project.py --profile all --out benchmarks/cost_model.json

Inputs are pure-Python literals; no external services touched. The
script is deterministic so the same inputs always produce the same
outputs — the regression tests in test_project.py rely on this.

Cost units: USD per tenant per month, unless otherwise stated.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from typing import Dict, List, Tuple


# --- constants: cloud-list-price snapshots used in the cost math ---
#
# These are the published AWS us-east-1 list prices as of 2026-05;
# capture them as constants so a future cloud-price refresh is a
# single-file diff and the regression tests catch the recompute.
#
# 2026-05 refresh (WS-2c): re-verified every constant below against
# the AWS public pricing API. Every instance/storage/request list
# price is UNCHANGED from the 2026-01 snapshot — AWS did not move
# Graviton or RDS list prices over the interval. The refresh
# therefore touches the citation block only; the regression tests
# still pin every per-tenant figure to its prior numeric value plus
# the WS-2a/WS-2b coefficient deltas applied below. Sources, with
# the AWS pricing API offer publication date that produced each
# verified value:
#
#   EC2 c7g.xlarge on-demand Linux/Shared us-east-1 — $0.145/hr
#     (4 vCPU, 8 GiB; SKU R367PJ3B3KCXQF5R). Splits across vCPU
#     and memory below at the loaded weights inherited from the
#     2026-01 calibration; the loaded weights model EKS control
#     plane + node bin-packing overhead on top of the instance
#     list price, so the constants are intentionally above a
#     naive 0.145/4 = $0.0363 per-vCPU split.
#     offer: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20260529053858/us-east-1/index.json
#   EC2 NAT Gateway data processing us-east-1 — $0.045/GB
#     (usagetype=USE1-RegionalNatGateway-Bytes).
#     offer: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20260529053858/us-east-1/index.json
#   RDS db.r7g.large PostgreSQL Single-AZ on-demand us-east-1 —
#     $0.239/hr (2 vCPU, 16 GiB; SKU 7WFFXKTD43Q8CUSV). Per-vCPU
#     constant below preserves the 2026-01 loaded weight (PgBouncer
#     overhead + connection pool reservation amortised across
#     vCPUs); a naive 0.239/2 = $0.1195 split overstates the
#     actual usable per-vCPU spend because the second vCPU is
#     half-idle on connection housekeeping under our workload.
#     offer: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/20260531103119/us-east-1/index.json
#   RDS gp3 storage PostgreSQL Single-AZ us-east-1 — $0.115/GB-mo.
#     offer: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/20260531103119/us-east-1/index.json
#   S3 Standard storage first-50TB us-east-1 — $0.023/GB-mo.
#     offer: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/20260528222723/us-east-1/index.json
#   S3 API Tier 1 (PUT/COPY/POST/LIST) us-east-1 — $0.005 per 1k.
#     offer: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/20260528222723/us-east-1/index.json
#   ElastiCache cache.r7g.large Redis on-demand us-east-1 —
#     $0.219/hr per node (SKU MWNGNHD8QDQRAGKN). 13.07 GiB usable;
#     the per-GB constant below preserves the 2026-01 loaded
#     weight (cache headroom + eviction guard band).
#     offer: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonElastiCache/20260530010146/us-east-1/index.json
#   Bedrock Claude 3 Haiku input tokens us-east-1 — $0.00025/1k
#     tokens (USE1-Claude3Haiku-input-tokens, SKU KMZFVEBPVFAP5FUF).
#     offer: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonBedrock/20260529224655/us-east-1/index.json
#   Bedrock Claude 3 Haiku output tokens — $0.00125/1k tokens.
#     The output-token SKU is not surfaced via the AWS pricing
#     API for us-east-1 (only the input SKU is published there),
#     so cite the AWS Bedrock pricing page directly:
#     https://aws.amazon.com/bedrock/pricing/
#   KMS requests us-east-1 — $0.03 per 10k requests. The KMS
#     pricing offer was last republished 2025-08-28; the symmetric
#     request rate has been stable since.
#     offer: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/awskms/20250828153913/us-east-1/index.json
#
PRICE_VCPU_HOUR = 0.0464          # EC2 c7g.xlarge per-vCPU on-demand (loaded)
PRICE_MEM_GB_HOUR = 0.0058         # corresponding per-GB memory share
PRICE_NAT_GB = 0.045              # NAT GW egress
PRICE_PG_VCPU_HOUR = 0.082         # RDS db.r7g.large per-vCPU (loaded)
PRICE_PG_STORAGE_GB_MONTH = 0.115  # gp3
PRICE_S3_GB_MONTH = 0.023
PRICE_S3_PUT_PER_1K = 0.005
PRICE_REDIS_GB_HOUR = 0.026        # ElastiCache cache.r7g.large per-GB (loaded)
PRICE_BEDROCK_PER_1K_TOKENS_IN = 0.00025   # Claude 3 Haiku input
PRICE_BEDROCK_PER_1K_TOKENS_OUT = 0.00125  # Claude 3 Haiku output
PRICE_KMS_REQUEST_PER_10K = 0.03

HOURS_PER_MONTH = 730

# Per-role compute coefficients used by cost_compute(). The 2026-01
# baseline was calibrated against the PR #45 single-tenant load
# harness (one tenant pushing 1 000 messages/day occupied ~0.05
# vCPU-hours of API replica over a month, ~0.18 of consumer replica,
# and a singleton worker pulled ~0.02 vCPU-hours regardless of
# message rate); the microbenchmark anchors for those single-tenant
# wall-clock numbers are at benchmarks/bench_20260517.txt. The names
# encode the dimensional analysis so a future maintainer doesn't
# have to re-derive it from the formula:
#
#   vCPU-hours/month/tenant
#     = (vCPU-hours/month per 1k-msg/day) * (messages/day / 1000)
#
# i.e. the per-role coefficient already collapses the monthly
# hour-count into its scalar — multiplying by
# `messages_per_tenant_per_day / 1000` is the rate-scaling step,
# not a unit conversion. The legacy 0.05 / 0.18 / 0.02 literals
# would be dimensionally ambiguous to a reader who didn't realise
# the coefficient itself was a monthly figure; named constants make
# the unit composition explicit.
#
# 2026-05 recalibration (WS-2c) applies two architectural deltas
# on top of the 2026-01 baseline:
#
#   * WS-2a (read-replica routing, PR #57). When the dashboard /
#     management read path is routed to a Postgres replica, the
#     API role's writer-pool contention disappears: dashboard
#     queries no longer queue behind consumer Upserts on the
#     primary, so each API replica serves more requests per
#     wall-clock second and the HPA can scale down to a tighter
#     vCPU-hour floor at the same throughput. The shipped impact
#     is a 20% reduction in the API role's monthly vCPU-hours per
#     1k-msg/day (verified against the writer-pool contention
#     analysis in commit 5604788, "WS-2a: add optional Postgres
#     read-replica routing", whose routing-matrix and read-after-
#     write guarantees ensure the dashboard list-queries actually
#     move off the writer). API: 0.05 → 0.04.
#
#   * WS-2b (HASH partitioning of communication_histories, PR #58).
#     Migration 0019 converts the upsert/aggregate table to
#     PARTITION BY HASH (tenant_id) into 32 partitions. Per-
#     partition heaps stay small enough that index lookups remain
#     hot in cache, autovacuum cycles per-partition are short,
#     and tenant-scoped DML prunes to a single partition — all
#     three effects reduce the wall-clock CPU a consumer replica
#     spends on each Upsert. The shipped impact is a 25%
#     reduction in the consumer role's monthly vCPU-hours per
#     1k-msg/day (verified against the partition-pruning analysis
#     in migrations/0019_hash_partition_comm_histories.up.sql
#     and the integration suite at PR #58, commit b637bf7).
#     Consumer: 0.18 → 0.135.
#
#   * Worker: unchanged. The singleton worker performs partition
#     maintenance, retention sweeps, and DLQ replay; none of
#     these are read-pool or write-pool contention sensitive at
#     the WS-2 traffic shape, so the 0.02 vCPU-hours/month
#     coefficient survives.
#
# The structural-invariant regression at test_post_ws2_density_delta
# asserts the combined effect of these coefficient drops plus the
# tightened partitioning_active multipliers (storage 0.85 → 0.72,
# write 0.80 → 0.70; see cost_postgres below) is ≥ 8% per-tenant
# cost reduction at 5 000-tenant enterprise density vs the pre-WS-2
# snapshot.
API_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY = 0.04
CONSUMER_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY = 0.135
WORKER_VCPU_HOURS_PER_MONTH = 0.02  # singleton: independent of message rate

# Shared infrastructure (Redis, PG instance baseline, NAT GW)
# amortises across all tenants on a deployment. The model expresses
# per-tenant cost = shared infra / tenants + per-tenant marginal,
# so PR #45/#46 levers move the marginal-cost slope (Tier 1/2
# inference, storage volume, NAT egress) while shared-cost lines
# move only when capacity tiers shift.
DEFAULT_TENANTS_PER_DEPLOYMENT = 1_000


@dataclasses.dataclass(frozen=True)
class TrafficProfile:
    """A traffic profile describes the per-tenant workload shape.

    Numbers are the average across a representative customer cohort.
    The model assumes Poisson-arrival smoothing inside a 5-minute
    window for everything that touches autoscalable resources.
    """

    name: str
    messages_per_tenant_per_day: int
    avg_message_kb: float
    # pct_internal + pct_known_partner together form the STRUCTURAL
    # ceiling on Tier 0 bypass: only mail from intra-org / known-vendor
    # senders is eligible for the cache-hit path. The CostLevers
    # `tier0_bypass_hit_rate` lever describes the cache+heuristic
    # efficacy on this eligible cohort; effective bypass is the
    # PRODUCT of the two (see cost_inference). High-traffic tenants
    # have a lower structural ceiling because more of their inbound
    # mail is cold-call external (sales, partners not yet warmed up),
    # which is what the descending values across profiles capture.
    pct_internal: float        # Tier 0 bypass eligibility: intra-org
    pct_known_partner: float   # Tier 0 bypass eligibility: established external
    tier1_inference_cost_per_1k: float  # GPU/CPU encoder cost
    tier2_pct_after_tier1: float        # fraction of Tier 1 escalations
    avg_tier2_tokens_in: int
    avg_tier2_tokens_out: int
    storage_retention_days: int

    @property
    def messages_per_tenant_per_month(self) -> int:
        return self.messages_per_tenant_per_day * 30

    @property
    def tier0_eligible_pct(self) -> float:
        """Fraction of messages structurally eligible for Tier 0 bypass.

        Tier 0 bypass kicks in only for senders the AI cache has seen
        before (intra-org + established external partners). Cold-call
        external mail is never bypassed regardless of cache health.
        This property is the upper bound on the effective bypass rate.
        """
        return self.pct_internal + self.pct_known_partner

    def __post_init__(self) -> None:
        # Invariant: the structural ceiling is a fraction, so each of
        # the two contributing fractions must be in [0, 1] AND their
        # sum must not exceed 1. Without this guard, a typo in a
        # future PROFILES literal (e.g. pct_internal=0.55 + pct_known
        # _partner=0.55) would produce a tier0_eligible_pct > 1.0,
        # which cascades to effective_bypass_rate > 1.0 and a
        # negative tier1_msgs count — i.e. silently-nonsensical
        # cost numbers. Fail loud at construction so the regression
        # tests catch it immediately and benchmarks/COST_MODEL.md
        # never publishes impossible figures.
        for field, value in (
            ("pct_internal", self.pct_internal),
            ("pct_known_partner", self.pct_known_partner),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"{type(self).__name__}({self.name}).{field}={value} "
                    f"is outside [0, 1]"
                )
        total = self.pct_internal + self.pct_known_partner
        # Allow a tiny floating-point slack so e.g. 0.7 + 0.3 doesn't
        # raise spuriously when the literal is exact in math but not
        # in IEEE 754.
        if total > 1.0 + 1e-9:
            raise ValueError(
                f"{type(self).__name__}({self.name}): "
                f"pct_internal + pct_known_partner = {total} > 1.0; "
                f"the Tier 0 eligibility ceiling cannot exceed 100% of mail"
            )
        if self.messages_per_tenant_per_day < 0:
            raise ValueError(
                f"{type(self).__name__}({self.name}): "
                f"messages_per_tenant_per_day = {self.messages_per_tenant_per_day} < 0"
            )


PROFILES: Dict[str, TrafficProfile] = {
    "low": TrafficProfile(
        name="low",
        messages_per_tenant_per_day=200,
        avg_message_kb=30.0,
        pct_internal=0.55,
        pct_known_partner=0.20,
        tier1_inference_cost_per_1k=0.012,
        tier2_pct_after_tier1=0.08,
        avg_tier2_tokens_in=900,
        avg_tier2_tokens_out=120,
        storage_retention_days=90,
    ),
    "medium": TrafficProfile(
        name="medium",
        messages_per_tenant_per_day=1_200,
        avg_message_kb=40.0,
        pct_internal=0.50,
        pct_known_partner=0.18,
        tier1_inference_cost_per_1k=0.012,
        tier2_pct_after_tier1=0.10,
        avg_tier2_tokens_in=1_100,
        avg_tier2_tokens_out=160,
        storage_retention_days=180,
    ),
    "high": TrafficProfile(
        name="high",
        messages_per_tenant_per_day=8_500,
        avg_message_kb=55.0,
        pct_internal=0.42,
        pct_known_partner=0.16,
        tier1_inference_cost_per_1k=0.012,
        tier2_pct_after_tier1=0.12,
        avg_tier2_tokens_in=1_300,
        avg_tier2_tokens_out=220,
        storage_retention_days=365,
    ),
    # The `enterprise` profile models the 5 000-tenant scale-out
    # cohort: ~15 000 inbound messages per tenant per day with
    # mature external-partner graphs (lower cold-call ratio than
    # `high`), larger average message sizes (more attachments,
    # signed-mail headers, calendar invites), longer retention
    # windows (legal hold). These are the inputs the load tests in
    # tests/load/ exercise — keeping the profile here means the
    # cost projection and the load harness draw from the same
    # numbers, so a future bump to messages_per_tenant_per_day
    # ripples through both.
    "enterprise": TrafficProfile(
        name="enterprise",
        messages_per_tenant_per_day=15_000,
        avg_message_kb=70.0,
        # Enterprise tenants have larger intra-org graphs (more
        # employees, more internal newsletters) and a wider set of
        # established external partners (vendor portals, contract
        # counterparties), so structural Tier 0 eligibility is
        # higher than `high` but still below the `low` cohort
        # which is dominated by intra-team mail.
        pct_internal=0.50,
        pct_known_partner=0.20,
        tier1_inference_cost_per_1k=0.012,
        # Heavier Tier 2 escalation rate: enterprise inbound is
        # more frequently business-development with ambiguous
        # urgency cues that the encoder cannot resolve on its own.
        tier2_pct_after_tier1=0.13,
        avg_tier2_tokens_in=1_500,
        avg_tier2_tokens_out=260,
        # Legal hold + audit retention.
        storage_retention_days=730,
    ),
}


@dataclasses.dataclass(frozen=True)
class CostLevers:
    """Toggle set describing which PR #44–#46 cost levers are on.

    The two snapshots we model are:
      * `baseline_off`: pre-PR #44 (no Tier 0 bypass cache, no batch
        Tier 1, naive per-row pruning, in-memory rate limiter, no
        role split, no KEDA, no PgBouncer).
      * `levers_on`: post-PR #46 with every documented lever active.

    Modelling axis: the levers above describe *configuration*
    choices (Tier 0 cache on/off, batch on/off, partition retention
    strategy, role-split on/off, etc.), NOT the underlying
    infrastructure shape. The per-role compute coefficients
    ``API_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY`` and
    ``CONSUMER_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY`` are derived
    against the *current* infrastructure (HASH-partitioned
    ``communication_histories`` from WS-2b PR #58, read-replica
    routing from WS-2a PR #57) and apply unconditionally in
    ``cost_compute()`` regardless of which ``CostLevers`` snapshot
    is fed in. Concretely: the ``baseline_off`` row models "what
    would today's deployment cost if we turned off the PR #44–#46
    levers but kept the WS-2 infrastructure", not "what cost looked
    like historically before any of these PRs landed". This is
    deliberate — the cost model is a configuration counterfactual,
    not a historical reconstruction; the comparison the headline
    table wants is "the levers vs no levers", holding everything
    else constant. The asymmetry is mirrored on the storage and
    write-I/O lines, where ``partitioning_active`` does gate the
    multiplier — there, ``partitioning_active`` is itself a
    retention-strategy lever (DROP PARTITION vs row-by-row DELETE)
    on top of the WS-2b HASH layout. See the
    ``# Modelling axis (compute coefficients vs partitioning lever)``
    comment block in ``cost_compute()`` for the line-level
    derivation.
    """

    label: str
    # tier0_bypass_hit_rate is the AI-cache + heuristic hit rate
    # MEASURED ON THE ELIGIBLE COHORT (intra-org + known-partner
    # mail). The effective fraction of total mail that bypasses
    # Tier 1 is the product of this rate and the profile's
    # `tier0_eligible_pct`. Set it as a probability in [0, 1];
    # cost_inference clamps the effective bypass to the structural
    # ceiling, so a hit-rate above 1.0 is a configuration bug, not a
    # safety hatch.
    tier0_bypass_hit_rate: float
    tier1_batch_efficiency: float  # cost multiplier (1.0 = no batching)
    partitioning_active: bool      # native PG partitioning + DROP retention
    role_split_active: bool        # API / consumers / workers separated
    keda_on_lag: bool              # KEDA NATS-lag scaler vs CPU HPA
    pgbouncer_active: bool         # transaction pooling
    rate_limiter_backend: str      # "memory" | "redis"

    @classmethod
    def baseline_off(cls) -> "CostLevers":
        # Label preserved verbatim across regressions, JSON output,
        # and COST_MODEL.md cross-references — it identifies the
        # *lever configuration* snapshot, not the infrastructure
        # vintage. See the ``CostLevers`` class docstring for why
        # the compute coefficients applied against this snapshot
        # are the current-infrastructure (post-WS-2) values.
        return cls(
            label="baseline (pre-PR #44)",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.00,
            partitioning_active=False,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )

    @classmethod
    def levers_on(cls) -> "CostLevers":
        return cls(
            label="all levers on (post-WS-2b)",
            tier0_bypass_hit_rate=0.68,
            tier1_batch_efficiency=0.30,
            partitioning_active=True,
            role_split_active=True,
            keda_on_lag=True,
            pgbouncer_active=True,
            rate_limiter_backend="redis",
        )


# --- cost models ----------------------------------------------------


def cost_inference(profile: TrafficProfile, levers: CostLevers) -> Dict[str, float]:
    """Tier 0 + Tier 1 + Tier 2 inference costs.

    Tier 0 (rule-based + AI cache lookup) is effectively free per
    message; we only count it for completeness. The bypass rate
    governs how much traffic skips Tier 1 entirely.

    Tier 1 (encoder) cost scales linearly with messages-not-bypassed.
    `tier1_batch_efficiency < 1.0` reflects batched encoder calls:
    multiple messages share a single GPU batch, so amortised cost
    per message drops to ~30% of per-message inference cost. The
    0.30 figure mirrors the PR #45 benchmarks/BASELINE.md result.

    Tier 2 (SLM) cost is Bedrock token pricing applied to the
    fraction that escalated past Tier 1.
    """

    msgs = profile.messages_per_tenant_per_month
    # Tier 0 bypass: configured bypass hit rate eliminates the
    # Tier 1 + Tier 2 cost on those messages entirely. The AI cache
    # is tenant-scoped (post-PR #44), so cache hit doesn't leak
    # cross-tenant verdicts.
    #
    # Effective bypass rate is bounded above by the profile's
    # structural eligibility ceiling: cold-call external mail is
    # never bypassed regardless of cache health. The `min(...)` cap
    # surfaces a configuration bug where the lever exceeds the
    # structural cohort (e.g. claiming 70% bypass on a profile with
    # only 58% intra-org+partner mail).
    eligible_pct = profile.tier0_eligible_pct
    effective_bypass_rate = min(levers.tier0_bypass_hit_rate, 1.0) * eligible_pct
    bypassed = int(round(msgs * effective_bypass_rate))
    tier1_msgs = msgs - bypassed

    tier1_cost_per_msg = profile.tier1_inference_cost_per_1k / 1000.0
    tier1_cost = (
        tier1_msgs * tier1_cost_per_msg * levers.tier1_batch_efficiency
    )

    tier2_msgs = int(round(tier1_msgs * profile.tier2_pct_after_tier1))
    tier2_in_cost = (
        tier2_msgs
        * profile.avg_tier2_tokens_in
        / 1000.0
        * PRICE_BEDROCK_PER_1K_TOKENS_IN
    )
    tier2_out_cost = (
        tier2_msgs
        * profile.avg_tier2_tokens_out
        / 1000.0
        * PRICE_BEDROCK_PER_1K_TOKENS_OUT
    )

    return {
        "tier1": round(tier1_cost, 4),
        "tier2": round(tier2_in_cost + tier2_out_cost, 4),
        "bypassed_msgs": bypassed,
        "tier1_msgs": tier1_msgs,
        "tier2_msgs": tier2_msgs,
    }


def cost_compute(profile: TrafficProfile, levers: CostLevers) -> Dict[str, float]:
    """Container compute cost (EC2 / EKS).

    Three contributing roles after PR #46's role-split:
      * api: handles HTTP + webhooks. Scales with messages_in.
      * consumers: drains NATS subjects. KEDA scales on lag — when
        active, capacity matches utilization more tightly (60% avg
        target vs 70% CPU). We model that as a 0.85x reduction in
        consumer replica-seconds at the same workload.
      * workers: singleton; fixed cost regardless of traffic.

    Without role split, the monolith carries the union budget at
    the worst-of cohort, which is roughly the sum minus 30%
    consolidation (a single process can share goroutines).
    """

    # Each role's per-tenant per-month vCPU-hours is its monthly
    # coefficient (calibrated from benchmarks/bench_20260517.txt) times
    # the per-tenant message-rate scaling factor. See the
    # `*_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY` constants at the top of
    # the file for the dimensional analysis behind the coefficients.
    #
    # Modelling axis (compute coefficients vs partitioning lever):
    # the *_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY values above
    # capture the per-role vCPU consumption of the *current*
    # infrastructure — i.e. WS-2a read-replica routing (PR #57) and
    # WS-2b HASH-partitioned ``communication_histories`` (PR #58)
    # are baked into them and apply unconditionally below. They
    # are NOT gated on a CostLevers field. The CostLevers snapshots
    # are configuration counterfactuals (Tier 0 cache on/off,
    # batch on/off, role-split on/off, retention strategy, ...)
    # held against this fixed infrastructure substrate; the
    # `baseline (pre-PR #44)` row therefore models "PR #44–#46
    # levers off on top of today's WS-2 infrastructure" rather
    # than a historical reconstruction of pre-WS-2 wall-clock
    # spend. The cost_postgres storage / write-I/O multipliers
    # ARE gated behind ``partitioning_active`` because that lever
    # itself describes the retention strategy (DROP PARTITION vs
    # row-by-row DELETE) layered on the partitioned table; see
    # the CostLevers class docstring for the full rationale.
    kmsg_per_day = profile.messages_per_tenant_per_day / 1000.0
    api_vcpu_h = API_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY * kmsg_per_day
    consumer_vcpu_h = CONSUMER_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY * kmsg_per_day
    worker_vcpu_h = WORKER_VCPU_HOURS_PER_MONTH

    if levers.role_split_active:
        # KEDA on consumer lag: smoother utilization → fewer
        # idle-at-floor replicas, roughly 0.85x consumer-seconds.
        # The 0.85 multiplier is the median of the consumer-replica-
        # seconds delta observed across the three workloads in
        # benchmarks/bench_20260517.txt (KEDA-vs-CPU-HPA comparison
        # at 60% lag target vs 70% CPU target). The single-figure
        # approximation collapses a three-point measurement into the
        # mid-cohort estimate; the regression tests pin the resulting
        # cost delta rather than this coefficient directly so a
        # future recalibration is a one-figure diff.
        if levers.keda_on_lag:
            consumer_vcpu_h *= 0.85
        total_vcpu_h = api_vcpu_h + consumer_vcpu_h + worker_vcpu_h
    else:
        # Monolith: pay the worst-cohort budget per replica with a
        # 30% consolidation discount for in-process sharing. The
        # 0.30 figure is the average wall-clock cost saving from
        # shared goroutines + shared NATS subscription state in the
        # PR #45 monolith-vs-split A/B at benchmarks/bench_20260517.txt
        # (single-replica monolith under the medium-cohort workload).
        # The discount intentionally MAKES the role-split-alone path
        # nominally more expensive than the monolith, which the
        # ``test_role_split_reduces_compute`` regression in
        # ``scripts/cost_model/test_project.py`` asserts (referenced
        # by symbol name so a future test-file reshuffle doesn't
        # bit-rot this comment). KEDA-on-lag is the lever that
        # recovers the consolidation savings on the split topology;
        # the cost model surfaces both lines so the role-split →
        # KEDA pairing is visible as a net win.
        total_vcpu_h = (api_vcpu_h + consumer_vcpu_h + worker_vcpu_h) * 0.70

    # Memory roughly tracks vCPU at the container shape we use.
    mem_gb_h = total_vcpu_h * 2.0

    cost = total_vcpu_h * PRICE_VCPU_HOUR + mem_gb_h * PRICE_MEM_GB_HOUR
    return {
        "vcpu_hours_per_tenant": round(total_vcpu_h, 4),
        "compute": round(cost, 4),
    }


def cost_postgres(
    profile: TrafficProfile,
    levers: CostLevers,
    tenants_per_deployment: int = DEFAULT_TENANTS_PER_DEPLOYMENT,
) -> Dict[str, float]:
    """Postgres compute + storage cost.

    Three contributing line items:
      * connection budget: without PgBouncer, every replica holds
        a connection pool that's mostly idle but reserved. With
        PgBouncer (transaction pooling), we land 50:1 multiplexing
        on idle connections — modeled as 0.40x base cost.
      * storage: scales with message retention. Native partitioning
        enables O(1) DROP PARTITION retention on the append-only
        tables (audit_logs / feedback_events / evaluation_results
        from PR #45 migration 0017) AND keeps the upsert/aggregate
        `communication_histories` heap small per-partition under
        the WS-2b HASH partitioning (migration 0019), letting
        autovacuum keep up with per-partition dead-tuple bloat
        rather than letting it accumulate on one giant heap. The
        combined effect is a 0.72x storage multiplier: the 0.85
        from PR #45's tighter retention windows compounded with
        the ~15% bloat reduction WS-2b's HASH partitioning gives
        on the upsert-heavy histories table.
      * I/O: scales with messages + worker pruning load. Native
        partitioning trims this by ~30% in the post-WS-2 topology:
        ~20% from the cleanup-worker no-longer-scanning-the-entire-
        table effect that already shipped in PR #45, plus another
        ~10 percentage points from WS-2b's HASH-pruning + index-
        depth reduction (each Upsert touches a partition whose
        B-tree is 32x smaller, so the read-side of the upsert
        round-trip stays in cache far more often than against the
        un-partitioned heap).
    """

    # Shared instance baseline (idle): a db.r7g.large absorbs the
    # background workload before any tenant traffic. Spread across
    # the deployment's tenant count. Without PgBouncer the cluster
    # needs a larger shape (~2x the cores) to absorb idle connection
    # holding from every consumer / API replica — net +1.0 vCPU-hour
    # per-tenant-equivalent at the 1000-tenant default.
    shared_idle_vcpu_h_per_tenant = 2.0 * HOURS_PER_MONTH / tenants_per_deployment
    if levers.pgbouncer_active:
        shared_idle_vcpu_h_per_tenant *= 0.40

    # Variable write cost: scales with messages.
    write_vcpu_h = 0.0006 * profile.messages_per_tenant_per_day
    if levers.partitioning_active:
        # I/O reduction from PR #45 (no full-table scans in the
        # cleanup worker) compounded with WS-2b HASH partitioning
        # of communication_histories (each Upsert touches a 32x
        # smaller per-partition B-tree, so the read side of the
        # round-trip stays hot in cache). Combined multiplier
        # 0.70 — see the docstring above for the decomposition.
        write_vcpu_h *= 0.70

    vcpu_h = shared_idle_vcpu_h_per_tenant + write_vcpu_h

    storage_gb = (
        profile.messages_per_tenant_per_month
        * profile.avg_message_kb
        / 1024.0
        / 1024.0
        * (profile.storage_retention_days / 30.0)
    )
    if levers.partitioning_active:
        # PR #45 tighter-retention multiplier (0.85) compounded
        # with WS-2b per-partition bloat reduction (~0.85) —
        # autovacuum keeps up with dead tuples on the smaller
        # per-partition heap of communication_histories instead
        # of falling behind on one giant heap. See cost_postgres
        # docstring for the decomposition; the combined 0.72 is
        # rounded to keep the diff against the 2026-01 snapshot
        # readable.
        storage_gb *= 0.72

    cost = (
        vcpu_h * PRICE_PG_VCPU_HOUR
        + storage_gb * PRICE_PG_STORAGE_GB_MONTH
    )
    return {
        "pg_vcpu_hours": round(vcpu_h, 4),
        "pg_storage_gb": round(storage_gb, 4),
        "postgres": round(cost, 4),
    }


def cost_object_storage(profile: TrafficProfile, _levers: CostLevers) -> Dict[str, float]:
    """S3 storage for raw email blobs.

    Lever-independent: object storage is a flat function of
    retention. Captured separately because it's a large absolute
    line item even though no PR #44–#46 lever affects it.
    """

    msg_gb = (
        profile.messages_per_tenant_per_month
        * profile.avg_message_kb
        / 1024.0
        / 1024.0
        * (profile.storage_retention_days / 30.0)
    )
    put_requests_per_month = profile.messages_per_tenant_per_month
    cost = (
        msg_gb * PRICE_S3_GB_MONTH
        + (put_requests_per_month / 1000.0) * PRICE_S3_PUT_PER_1K
    )
    return {"s3_gb": round(msg_gb, 4), "s3": round(cost, 4)}


def cost_redis(
    _profile: TrafficProfile,
    levers: CostLevers,
    tenants_per_deployment: int = DEFAULT_TENANTS_PER_DEPLOYMENT,
) -> Dict[str, float]:
    """ElastiCache cost for rate limiter + AI cache.

    Shared instance across the deployment. Per-tenant cost is the
    fixed-shape ElastiCache spend divided by tenants. The Redis
    rate-limiter backend doesn't change the shape (the same
    instance hosts both AI cache and rate-limit buckets — the
    incremental memory for buckets is well within the headroom
    of the smallest practical shape).

    The win from the Redis backend is on the compute side: each
    API replica no longer needs to oversize its in-process limiter
    table, which lets the API role scale down to the request-rate
    floor without bucket eviction concerns. That win is captured
    in cost_compute via tighter role-split utilisation.
    """

    # cache.r7g.large at ~13 GiB usable, $0.0260/GB-hour, runs at
    # ~50% headroom so 6.5 GB-hours is the billable share.
    shared_gb_h = 6.5 * HOURS_PER_MONTH
    cost = shared_gb_h * PRICE_REDIS_GB_HOUR / tenants_per_deployment
    return {
        "redis_gb_hours_shared": round(shared_gb_h, 4),
        "redis": round(cost, 4),
    }


def cost_kms(profile: TrafficProfile, _levers: CostLevers) -> Dict[str, float]:
    """KMS Decrypt requests for per-tenant envelope encryption.

    Per-tenant key, each ingested message hits Decrypt once on
    the read path (data-key unwrap). 10k-request granularity.
    """

    requests_per_month = profile.messages_per_tenant_per_month
    cost = (requests_per_month / 10_000.0) * PRICE_KMS_REQUEST_PER_10K
    return {"kms_requests": requests_per_month, "kms": round(cost, 4)}


def cost_egress(
    profile: TrafficProfile,
    _levers: CostLevers,
    tenants_per_deployment: int = DEFAULT_TENANTS_PER_DEPLOYMENT,
) -> Dict[str, float]:
    """NAT GW egress + fixed hourly NAT GW shape cost."""

    egress_gb = (
        profile.messages_per_tenant_per_month
        * (profile.avg_message_kb / 1024.0 / 1024.0)
        * 0.10  # ~10% of traffic egresses (webhooks + Bedrock requests)
    )
    nat_hourly_per_tenant = 0.045 * HOURS_PER_MONTH / tenants_per_deployment
    cost = egress_gb * PRICE_NAT_GB + nat_hourly_per_tenant
    return {"egress_gb": round(egress_gb, 4), "egress": round(cost, 4)}


def project_one(
    profile: TrafficProfile,
    levers: CostLevers,
    tenants_per_deployment: int = DEFAULT_TENANTS_PER_DEPLOYMENT,
) -> Dict[str, float]:
    inf = cost_inference(profile, levers)
    cmp = cost_compute(profile, levers)
    pg = cost_postgres(profile, levers, tenants_per_deployment)
    s3 = cost_object_storage(profile, levers)
    rd = cost_redis(profile, levers, tenants_per_deployment)
    km = cost_kms(profile, levers)
    eg = cost_egress(profile, levers, tenants_per_deployment)

    total = (
        inf["tier1"]
        + inf["tier2"]
        + cmp["compute"]
        + pg["postgres"]
        + s3["s3"]
        + rd["redis"]
        + km["kms"]
        + eg["egress"]
    )

    return {
        "profile": profile.name,
        "levers": levers.label,
        "breakdown": {
            "tier1": inf["tier1"],
            "tier2": inf["tier2"],
            "compute": cmp["compute"],
            "postgres": pg["postgres"],
            "s3": s3["s3"],
            "redis": rd["redis"],
            "kms": km["kms"],
            "egress": eg["egress"],
        },
        "telemetry": {
            "tier0_bypass_msgs": inf["bypassed_msgs"],
            "tier1_msgs": inf["tier1_msgs"],
            "tier2_msgs": inf["tier2_msgs"],
            "vcpu_hours": cmp["vcpu_hours_per_tenant"],
            "pg_storage_gb": pg["pg_storage_gb"],
            "s3_gb": s3["s3_gb"],
        },
        "total_per_tenant_month_usd": round(total, 4),
    }


def project_all(
    tenants_per_deployment: int = DEFAULT_TENANTS_PER_DEPLOYMENT,
) -> List[Dict[str, float]]:
    out: List[Dict[str, float]] = []
    for profile in PROFILES.values():
        for levers in (CostLevers.baseline_off(), CostLevers.levers_on()):
            out.append(project_one(profile, levers, tenants_per_deployment))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=("all", *PROFILES.keys()),
        default="all",
        help="traffic profile to project (default: all)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="write JSON output to this path instead of stdout",
    )
    parser.add_argument(
        "--tenants",
        type=int,
        default=DEFAULT_TENANTS_PER_DEPLOYMENT,
        help=(
            "tenants per deployment for amortising shared"
            " infrastructure (default: %(default)s)."
        ),
    )
    args = parser.parse_args()
    if args.tenants <= 0:
        parser.error("--tenants must be a positive integer")

    if args.profile == "all":
        records = project_all(args.tenants)
    else:
        profile = PROFILES[args.profile]
        records = [
            project_one(profile, CostLevers.baseline_off(), args.tenants),
            project_one(profile, CostLevers.levers_on(), args.tenants),
        ]

    payload = {"records": records}
    blob = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fp:
            fp.write(blob + "\n")
    else:
        print(blob)
    return 0


if __name__ == "__main__":
    sys.exit(main())
