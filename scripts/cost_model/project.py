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
# These are the published AWS us-east-1 list prices as of 2026-01;
# capture them as constants so a future cloud-price refresh is a
# single-file diff and the regression tests catch the recompute.
PRICE_VCPU_HOUR = 0.0464          # EC2 c7g.xlarge per-vCPU on-demand
PRICE_MEM_GB_HOUR = 0.0058         # corresponding per-GB memory share
PRICE_NAT_GB = 0.045              # NAT GW egress
PRICE_PG_VCPU_HOUR = 0.082         # RDS db.r7g.large per-vCPU
PRICE_PG_STORAGE_GB_MONTH = 0.115  # gp3
PRICE_S3_GB_MONTH = 0.023
PRICE_S3_PUT_PER_1K = 0.005
PRICE_REDIS_GB_HOUR = 0.026        # ElastiCache cache.r7g.large per-GB
PRICE_BEDROCK_PER_1K_TOKENS_IN = 0.00025   # Claude 3 Haiku input
PRICE_BEDROCK_PER_1K_TOKENS_OUT = 0.00125  # Claude 3 Haiku output
PRICE_KMS_REQUEST_PER_10K = 0.03

HOURS_PER_MONTH = 730

# Per-role compute coefficients used by cost_compute(). Each coefficient
# is calibrated against the PR #45 benchmarks/bench_20260517.txt
# single-tenant baseline (one tenant pushing 1 000 messages/day occupies
# ~0.05 vCPU-hours of API replica over a month, ~0.18 of consumer
# replica, and a singleton worker pulls ~0.02 vCPU-hours regardless of
# message rate). The names encode the dimensional analysis so a future
# maintainer doesn't have to re-derive it from the formula:
#
#   vCPU-hours/month/tenant
#     = (vCPU-hours/month per 1k-msg/day) * (messages/day / 1000)
#
# i.e. the per-role coefficient already collapses the monthly hour-count
# into its scalar — multiplying by `messages_per_tenant_per_day / 1000`
# is the rate-scaling step, not a unit conversion. The legacy 0.05 /
# 0.18 / 0.02 literals would be dimensionally ambiguous to a reader who
# didn't realise the coefficient itself was a monthly figure; named
# constants make the unit composition explicit.
API_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY = 0.05
CONSUMER_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY = 0.18
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
            label="all levers on (post-PR #46)",
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
        # regression test at test_project.py:207 asserts. KEDA-on-lag
        # is the lever that recovers the consolidation savings on
        # the split topology; the cost model surfaces both lines so
        # the role-split → KEDA pairing is visible as a net win.
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
        (PR #45) doesn't reduce storage but enables O(1) DROP
        PARTITION retention, which the cleanup-worker fallback
        can't match. We model that as a 0.85x storage multiplier
        because partitioned tables can run with tighter retention
        without operational risk.
      * I/O: scales with messages + worker pruning load. Native
        partitioning trims this by ~20% because the cleanup worker
        no longer scans the entire table for stale rows.
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
        # I/O reduction from no full-table scan in the cleanup
        # worker: ~20% off the write budget.
        write_vcpu_h *= 0.80

    vcpu_h = shared_idle_vcpu_h_per_tenant + write_vcpu_h

    storage_gb = (
        profile.messages_per_tenant_per_month
        * profile.avg_message_kb
        / 1024.0
        / 1024.0
        * (profile.storage_retention_days / 30.0)
    )
    if levers.partitioning_active:
        storage_gb *= 0.85

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
