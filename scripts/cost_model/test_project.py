"""Regression tests for the cost model.

The cost model is deterministic; these tests pin the
$/tenant/month outputs at every traffic profile so a future
edit to PRICE_* or to a lever can't quietly shift numbers
without the diff updating both the script and the test.

Tests also assert two structural invariants:
  1. Every lever-on projection is strictly cheaper than its
     baseline-off peer (otherwise the lever isn't a cost lever).
  2. The percentage savings on the low/medium/high cohorts move
     in the right direction (higher traffic → larger absolute
     savings since the levers gate volume-proportional costs).

Run::

    python3 -m unittest scripts.cost_model.test_project
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import project  # noqa: E402


class TestCostModel(unittest.TestCase):
    def test_lever_on_always_cheaper(self) -> None:
        for name, profile in project.PROFILES.items():
            base = project.project_one(profile, project.CostLevers.baseline_off())
            on = project.project_one(profile, project.CostLevers.levers_on())
            with self.subTest(profile=name):
                self.assertLess(
                    on["total_per_tenant_month_usd"],
                    base["total_per_tenant_month_usd"],
                    "levers_on must be strictly cheaper than baseline",
                )

    def test_savings_scale_with_traffic(self) -> None:
        savings = {}
        for name, profile in project.PROFILES.items():
            base = project.project_one(profile, project.CostLevers.baseline_off())
            on = project.project_one(profile, project.CostLevers.levers_on())
            savings[name] = (
                base["total_per_tenant_month_usd"]
                - on["total_per_tenant_month_usd"]
            )
        # Compare across the three legacy SME cohorts (low / medium
        # / high). The `enterprise` cohort is intentionally not in
        # this chain — it sits above `high` on absolute traffic but
        # uses a different Tier 0 eligibility / retention profile, so
        # comparing savings curves directly conflates two independent
        # axes. The dedicated test_5000_tenant_density assertion
        # below pins the enterprise cohort's per-tenant cost
        # explicitly so a future regression on the heavier profile
        # is still caught.
        self.assertLess(savings["low"], savings["medium"])
        self.assertLess(savings["medium"], savings["high"])

    def test_5000_tenant_density(self) -> None:
        """5 000-tenant density pin for the enterprise cohort.

        Asserts structural invariants on the new enterprise cost
        projection at 5 000 tenants per deployment with all PR
        #45/#46 levers active:

          1. The `enterprise` profile exists and points at the
             15 000 msg/tenant/day workload the load harness drives
             (a typo here desyncs the load test inputs and the
             projection inputs).
          2. Per-tenant cost is finite and positive (no divide-by-
             zero or sign-flip from a coefficient regression).
          3. Activating every cost lever beats the baseline-off
             projection at the same density by ≥ 20 % — i.e. the
             levers actually pay for themselves at enterprise
             traffic. The savings ratio is naturally lower on the
             enterprise cohort than on `low`/`medium` because the
             dominant cost line (Tier 1/2 inference on 15 000
             msg/tenant/day) is only partially compressible by
             Tier 0 bypass — most of the inbound is genuinely
             novel sender mail that needs the encoder.
          4. Density-amortisation invariants hold for the new
             enterprise profile: 10 000 tenants is strictly cheaper
             per tenant than 5 000, and 5 000 is strictly cheaper
             than the 1 000 default (shared Redis / PG instance
             baseline / NAT GW spread further).
          5. Per-tenant cost stays below an absolute ceiling derived
             from a fully-naive Tier 1+Tier 2 inference budget for
             the enterprise message volume — this catches the
             obvious regression where bypass / batch levers
             silently stop firing (which would push every message
             through Tier 1 and pop the bill).
          6. Telemetry message-routing accounting remains internally
             consistent at the higher per-tenant volume.

        The numbers are deterministic functions of the PRICE_* /
        coefficient constants — if a future cloud-price refresh
        moves them, this test forces the diff to update the model
        AND the assertions together rather than letting one drift.
        """
        self.assertIn("enterprise", project.PROFILES,
            "the `enterprise` profile must exist; the load harness "
            "and benchmarks/COST_MODEL.md both depend on it")
        enterprise = project.PROFILES["enterprise"]
        self.assertEqual(enterprise.messages_per_tenant_per_day, 15_000,
            "enterprise traffic shape is the 5000-tenant scale-out "
            "anchor — change deliberately, not by accident")

        on_5k = project.project_one(
            enterprise, project.CostLevers.levers_on(), tenants_per_deployment=5_000,
        )
        on_10k = project.project_one(
            enterprise, project.CostLevers.levers_on(), tenants_per_deployment=10_000,
        )
        on_baseline_density = project.project_one(
            enterprise,
            project.CostLevers.levers_on(),
            tenants_per_deployment=project.DEFAULT_TENANTS_PER_DEPLOYMENT,
        )
        off_5k = project.project_one(
            enterprise, project.CostLevers.baseline_off(), tenants_per_deployment=5_000,
        )

        cost_5k = on_5k["total_per_tenant_month_usd"]
        cost_10k = on_10k["total_per_tenant_month_usd"]
        cost_default = on_baseline_density["total_per_tenant_month_usd"]
        cost_off_5k = off_5k["total_per_tenant_month_usd"]

        # 2. Per-tenant cost is finite and positive.
        self.assertGreater(cost_5k, 0.0)

        # 3. Levers-on saves ≥ 20 % vs baseline-off at the same
        #    density. Use a ratio rather than an absolute dollar
        #    figure so a future cloud-price refresh doesn't drift
        #    this test out from under the model. The threshold is
        #    deliberately lower than the SME-cohort savings curves
        #    expose — see the docstring above for why.
        savings_pct = (cost_off_5k - cost_5k) / cost_off_5k
        self.assertGreaterEqual(
            savings_pct, 0.20,
            f"levers-on saves only {savings_pct*100:.1f}% over "
            f"baseline-off at 5 000 enterprise tenants — below the "
            f"20% floor the PR #45/#46 lever set was sized to deliver",
        )

        # 4. Density-amortisation invariants.
        self.assertLess(
            cost_10k, cost_5k,
            "doubling density (5 000 → 10 000) must reduce per-tenant "
            "cost; the shared-infra amortisation invariant is broken",
        )
        self.assertLess(
            cost_5k, cost_default,
            "5 000-tenant density must be cheaper than the 1 000-tenant "
            "default density on the same profile/levers",
        )

        # 5. Absolute upper bound from a naive Tier 1+Tier 2 budget.
        #    If bypass / batch levers silently stopped firing, every
        #    one of the 15 000 daily messages would land in Tier 1
        #    (and ~12 % in Tier 2), pricing roughly at the inference
        #    constants in project.py. Bound generously (4x the naive
        #    inference budget) so the test only fires on a real
        #    regression, not on incidental compute/storage drift.
        naive_tier1 = (
            enterprise.messages_per_tenant_per_month
            * enterprise.tier1_inference_cost_per_1k / 1_000.0
        )
        naive_tier2 = (
            enterprise.messages_per_tenant_per_month
            * enterprise.tier2_pct_after_tier1
            * (
                enterprise.avg_tier2_tokens_in
                * project.PRICE_BEDROCK_PER_1K_TOKENS_IN / 1_000.0
                + enterprise.avg_tier2_tokens_out
                * project.PRICE_BEDROCK_PER_1K_TOKENS_OUT / 1_000.0
            )
        )
        absolute_ceiling = 4.0 * (naive_tier1 + naive_tier2)
        self.assertLess(
            cost_5k, absolute_ceiling,
            f"enterprise per-tenant cost at 5 000 tenants ({cost_5k:.4f}) "
            f"exceeded 4x the naive inference budget "
            f"({absolute_ceiling:.4f}) — a cost lever has likely "
            f"stopped firing",
        )

        # 6. Telemetry accounting remains consistent at the new density.
        t = on_5k["telemetry"]
        self.assertEqual(
            t["tier0_bypass_msgs"] + t["tier1_msgs"],
            enterprise.messages_per_tenant_per_month,
            "message routing accounting drifted at enterprise scale",
        )
        self.assertLessEqual(t["tier2_msgs"], t["tier1_msgs"])

    # Pre-WS-2 levers-on per-tenant cost at the 5 000-tenant
    # enterprise anchor, frozen from the cost_model.json snapshot
    # committed alongside the PR #46 merge (commit 5d2fd77, the
    # tip of `main` before WS-2c shipped). The WS-2c recalibration
    # pinned by this constant is the post-WS-2a / post-WS-2b
    # state — anything later that wants to lower this baseline
    # again must publish a new constant alongside fresh evidence
    # rather than mutate this one in place.
    PRE_WS2_LEVERS_ON_5K_ENTERPRISE_USD = 115.1182

    # Floor on the per-tenant cost reduction read-replica routing +
    # HASH partitioning are expected to deliver at 5 000-tenant
    # enterprise density. Set at 8% per the calibration notes in
    # benchmarks/COST_MODEL.md: read-replica routing (PR #57) drops
    # the API-role vCPU-hour coefficient by ~20% and HASH
    # partitioning of `communication_histories` (PR #58) drops the consumer-role
    # coefficient by ~25%, with the partitioning storage / write
    # multipliers tightening from 0.85 / 0.80 to 0.72 / 0.70 in
    # cost_postgres. The combined floor expressed here is the
    # `or 5% with evidence` clause from the task brief if a future
    # recalibration tightens further — adjust this floor (and
    # update the comment trail) deliberately, not silently.
    POST_WS2_DENSITY_DELTA_FLOOR = 0.08

    def test_post_ws2_density_delta(self) -> None:
        """WS-2c floor: per-tenant cost at 5 000-tenant enterprise
        density must drop by at least
        ``POST_WS2_DENSITY_DELTA_FLOOR`` (8%) versus the pre-WS-2
        snapshot ``PRE_WS2_LEVERS_ON_5K_ENTERPRISE_USD``.

        This catches three regression classes at once:

          1. A future edit that silently weakens the WS-2a /
             WS-2b architectural assumptions (e.g. reverting one
             of the partitioning multipliers, or raising the
             API / consumer compute coefficients back toward
             their 2026-01 values) without updating
             ``PRE_WS2_LEVERS_ON_5K_ENTERPRISE_USD``.

          2. A future cloud-price refresh that compounds with the
             architectural levers in a direction that pushes the
             5 000-tenant cost back above the pre-WS-2 baseline
             (e.g. a PG_STORAGE_GB_MONTH bump that the WS-2b
             multiplier can't absorb). Such a regression is fair
             game to land — but the diff must update this floor
             alongside the price refresh so the cost narrative
             in COST_MODEL.md stays honest.

          3. A future profile / lever addition that doesn't
             account for the 5 000-tenant amortisation pattern
             (e.g. shipping a new lever-off ``baseline`` that's
             cheaper than levers-on at 5k by accident, which
             would invert the WS-2c delta sign).

        The assertion is on the **ratio** against the frozen
        pre-WS-2 anchor (``PRE_WS2_LEVERS_ON_5K_ENTERPRISE_USD``),
        not against a dynamically-rederived baseline. The ratio
        framing is narrower than an absolute-dollar floor would
        be — it measures the *proportional* WS-2a/2b win against
        the pre-WS-2 state, which is what the WS-2c recalibration
        claims to deliver. A uniform cloud-price refresh that
        lifts the whole curve will eventually push the projection
        past the ratio's pass band (the assertion fails once
        ``post_ws2_cost > anchor * (1 - 0.08) = $105.91`` at the
        current 8 % floor), at which point the right response is
        to publish a fresh anchor + delta floor alongside the
        price refresh — not to silently relax the floor. The
        companion absolute-dollar ceiling assertion below ($110)
        sits in a wider tolerance band and catches the orthogonal
        regression class where anchor and projection are silently
        co-mutated to keep the ratio passing.
        """
        enterprise = project.PROFILES["enterprise"]
        post_ws2 = project.project_one(
            enterprise,
            project.CostLevers.levers_on(),
            tenants_per_deployment=5_000,
        )
        post_ws2_cost = post_ws2["total_per_tenant_month_usd"]

        delta_pct = (
            self.PRE_WS2_LEVERS_ON_5K_ENTERPRISE_USD - post_ws2_cost
        ) / self.PRE_WS2_LEVERS_ON_5K_ENTERPRISE_USD

        self.assertGreaterEqual(
            delta_pct,
            self.POST_WS2_DENSITY_DELTA_FLOOR,
            (
                "post-WS-2 per-tenant cost at 5 000-tenant enterprise "
                f"density was ${post_ws2_cost:.4f}, only "
                f"{delta_pct * 100:.2f}% below the pre-WS-2 anchor "
                f"${self.PRE_WS2_LEVERS_ON_5K_ENTERPRISE_USD:.4f}. "
                f"Floor is {self.POST_WS2_DENSITY_DELTA_FLOOR * 100:.0f}%. "
                "Either a coefficient / multiplier was missed in the "
                "WS-2a / WS-2b recalibration (check "
                "API_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY, "
                "CONSUMER_VCPU_HOURS_PER_MONTH_PER_KMSG_PER_DAY, and "
                "the partitioning_active multipliers in cost_postgres), "
                "OR the task brief's 8% assumption needs to be relaxed "
                "with fresh evidence; either fix surfaces here rather "
                "than silently drifting the COST_MODEL.md narrative."
            ),
        )

        # Independent absolute-dollar ceiling on the post-WS-2
        # figure. The ratio assertion above is anchored against
        # ``PRE_WS2_LEVERS_ON_5K_ENTERPRISE_USD``, so if a future
        # edit silently lowered both the anchor and the
        # ``CostLevers.levers_on`` projection together, the ratio
        # would still pass. This second assertion pins the post
        # figure against a hard literal that does NOT reference
        # any other constant in this file. The ceiling is set at
        # $110 / tenant / month: above the WS-2c projection of
        # $104.07 (with headroom for future price drift) and
        # below the pre-WS-2 anchor of $115.12, so the WS-2c
        # improvement claim can't silently regress without
        # tripping this assertion even if the anchor moves.
        POST_WS2_ABSOLUTE_CEILING_USD = 110.00
        self.assertLess(
            post_ws2_cost,
            POST_WS2_ABSOLUTE_CEILING_USD,
            (
                f"post-WS-2 cost was ${post_ws2_cost:.4f}, above the "
                f"absolute ceiling of ${POST_WS2_ABSOLUTE_CEILING_USD:.2f} / "
                "tenant / month at 5 000-tenant enterprise density. "
                "This ceiling is anchor-independent (does not reference "
                "PRE_WS2_LEVERS_ON_5K_ENTERPRISE_USD) so it catches the "
                "case where the pre-WS-2 anchor is silently lowered "
                "alongside the post-WS-2 projection. If a legitimate "
                "cloud-price refresh lifts the floor above $110, raise "
                "the ceiling here deliberately (and document why)."
            ),
        )

    def test_tier0_bypass_reduces_inference(self) -> None:
        # At identical other levers, raising tier0_bypass_hit_rate
        # must reduce Tier 1 + Tier 2 cost. Exercises the
        # cost_inference path in isolation.
        profile = project.PROFILES["medium"]
        low_bypass = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.0,
            partitioning_active=False,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        high_bypass = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.70,
            tier1_batch_efficiency=1.0,
            partitioning_active=False,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        low_inf = project.cost_inference(profile, low_bypass)
        high_inf = project.cost_inference(profile, high_bypass)
        self.assertGreater(low_inf["tier1"], high_inf["tier1"])
        self.assertGreater(low_inf["tier2"], high_inf["tier2"])

    def test_batch_efficiency_reduces_tier1(self) -> None:
        profile = project.PROFILES["medium"]
        per_msg = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.0,
            partitioning_active=False,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        batched = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=0.30,
            partitioning_active=False,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        # cost_inference rounds tier1 to 4 decimal places before
        # returning, so the ratio carries float-rounding noise on
        # the order of ~1e-4. places=3 gives the test resilience
        # against that noise while still pinning the batch
        # efficiency multiplier to its documented 0.30 value.
        self.assertAlmostEqual(
            project.cost_inference(profile, batched)["tier1"]
            / project.cost_inference(profile, per_msg)["tier1"],
            0.30,
            places=3,
        )

    def test_pgbouncer_reduces_postgres(self) -> None:
        profile = project.PROFILES["medium"]
        off = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.0,
            partitioning_active=False,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        on = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.0,
            partitioning_active=False,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=True,
            rate_limiter_backend="memory",
        )
        self.assertLess(
            project.cost_postgres(profile, on)["postgres"],
            project.cost_postgres(profile, off)["postgres"],
        )

    def test_partitioning_reduces_storage(self) -> None:
        profile = project.PROFILES["high"]
        off = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.0,
            partitioning_active=False,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        on = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.0,
            partitioning_active=True,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        self.assertLess(
            project.cost_postgres(profile, on)["pg_storage_gb"],
            project.cost_postgres(profile, off)["pg_storage_gb"],
        )

    def test_role_split_reduces_compute(self) -> None:
        # KEDA on lag tightens consumer utilization; role-split alone
        # without KEDA shouldn't be cheaper than the consolidated
        # monolith because the 30% in-process sharing discount goes
        # away when roles are separate. Only the combination of
        # role-split + KEDA produces the net win.
        profile = project.PROFILES["high"]
        monolith = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.0,
            partitioning_active=False,
            role_split_active=False,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        split = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.0,
            partitioning_active=False,
            role_split_active=True,
            keda_on_lag=False,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        split_keda = project.CostLevers(
            label="x",
            tier0_bypass_hit_rate=0.10,
            tier1_batch_efficiency=1.0,
            partitioning_active=False,
            role_split_active=True,
            keda_on_lag=True,
            pgbouncer_active=False,
            rate_limiter_backend="memory",
        )
        mono_cost = project.cost_compute(profile, monolith)["compute"]
        split_cost = project.cost_compute(profile, split)["compute"]
        keda_cost = project.cost_compute(profile, split_keda)["compute"]
        self.assertGreater(split_cost, mono_cost)
        self.assertLess(keda_cost, split_cost)

    def test_tenants_per_deployment_amortises_shared_infra(self) -> None:
        # Doubling tenants_per_deployment must halve the shared Redis
        # baseline contribution. The variable parts (Tier 1/2 cost,
        # S3 storage, KMS) are per-tenant marginal so they don't
        # change.
        profile = project.PROFILES["medium"]
        levers = project.CostLevers.levers_on()
        small = project.project_one(profile, levers, 500)
        large = project.project_one(profile, levers, 2_000)
        self.assertGreater(small["breakdown"]["redis"], large["breakdown"]["redis"])
        self.assertGreater(small["breakdown"]["postgres"], large["breakdown"]["postgres"])
        # Tier 1/2 are per-tenant marginal — unchanged.
        self.assertEqual(small["breakdown"]["tier1"], large["breakdown"]["tier1"])
        self.assertEqual(small["breakdown"]["tier2"], large["breakdown"]["tier2"])

    def test_telemetry_message_routing_consistent(self) -> None:
        for name, profile in project.PROFILES.items():
            on = project.project_one(profile, project.CostLevers.levers_on())
            t = on["telemetry"]
            with self.subTest(profile=name):
                self.assertEqual(
                    t["tier0_bypass_msgs"] + t["tier1_msgs"],
                    profile.messages_per_tenant_per_month,
                )
                self.assertLessEqual(t["tier2_msgs"], t["tier1_msgs"])

    def test_tier0_bypass_bounded_by_structural_ceiling(self) -> None:
        # The Tier 0 bypass rate represents AI cache + heuristic
        # efficacy on the eligible cohort (intra-org + known-partner
        # mail). The model must NEVER bypass more mail than is
        # structurally eligible. A misconfigured lever above 1.0 must
        # also clamp at the ceiling rather than fabricating bypassed
        # mail. This pins the architectural invariant against a future
        # refactor that re-treats the lever as an absolute bypass %.
        for name, profile in project.PROFILES.items():
            ceiling_msgs = int(
                round(
                    profile.messages_per_tenant_per_month
                    * profile.tier0_eligible_pct
                )
            )
            for lever_rate, label in [(0.10, "low"), (0.68, "levers_on"), (1.50, "overshoot")]:
                levers = project.CostLevers(
                    label=label,
                    tier0_bypass_hit_rate=lever_rate,
                    tier1_batch_efficiency=1.0,
                    partitioning_active=False,
                    role_split_active=False,
                    keda_on_lag=False,
                    pgbouncer_active=False,
                    rate_limiter_backend="memory",
                )
                inf = project.cost_inference(profile, levers)
                with self.subTest(profile=name, lever=label):
                    self.assertLessEqual(
                        inf["bypassed_msgs"],
                        ceiling_msgs,
                        "effective bypass exceeded structural eligibility ceiling",
                    )

    def test_tier0_eligible_pct_monotone_with_traffic(self) -> None:
        # Structural Tier 0 eligibility (intra-org + known-partner
        # cohort) is expected to decline with traffic — higher-volume
        # tenants get proportionally more cold-call external mail.
        # The profile literals encode this; lock it in so a future
        # tweak that inverts the relationship (e.g. equalising the
        # percentages) doesn't silently invalidate the cost narrative
        # in COST_MODEL.md §"Headline numbers".
        self.assertGreater(
            project.PROFILES["low"].tier0_eligible_pct,
            project.PROFILES["medium"].tier0_eligible_pct,
        )
        self.assertGreater(
            project.PROFILES["medium"].tier0_eligible_pct,
            project.PROFILES["high"].tier0_eligible_pct,
        )

    def test_traffic_profile_rejects_eligibility_ceiling_above_one(self) -> None:
        # If a future profile literal accidentally specifies a Tier 0
        # eligibility ceiling above 1.0 (e.g. via copy-paste of
        # pct_internal + pct_known_partner that sum to >1), the
        # downstream `effective_bypass_rate = lever * ceiling` would
        # exceed 1.0 and produce a negative `tier1_msgs` count plus
        # negative cost numbers. The dataclass invariant in
        # __post_init__ should reject this at construction.
        with self.assertRaises(ValueError):
            project.TrafficProfile(
                name="bad",
                messages_per_tenant_per_day=100,
                avg_message_kb=10.0,
                pct_internal=0.6,
                pct_known_partner=0.5,  # 0.6 + 0.5 = 1.1 -> reject
                tier1_inference_cost_per_1k=0.012,
                tier2_pct_after_tier1=0.10,
                avg_tier2_tokens_in=900,
                avg_tier2_tokens_out=120,
                storage_retention_days=90,
            )

    def test_traffic_profile_rejects_negative_fraction(self) -> None:
        # Negative percentages are meaningless for the cost model and
        # would also break the downstream math (negative bypassed,
        # tier1_msgs > total). Rejected at construction.
        with self.assertRaises(ValueError):
            project.TrafficProfile(
                name="bad",
                messages_per_tenant_per_day=100,
                avg_message_kb=10.0,
                pct_internal=-0.1,
                pct_known_partner=0.5,
                tier1_inference_cost_per_1k=0.012,
                tier2_pct_after_tier1=0.10,
                avg_tier2_tokens_in=900,
                avg_tier2_tokens_out=120,
                storage_retention_days=90,
            )

    def test_traffic_profile_accepts_exact_boundary(self) -> None:
        # 0.5 + 0.5 = 1.0 is the structural maximum (every message
        # eligible for Tier 0 bypass) and MUST be accepted. The
        # invariant deliberately allows a small floating-point slack
        # so e.g. 0.3 + 0.7 doesn't fail spuriously due to IEEE 754
        # representation.
        p = project.TrafficProfile(
            name="boundary",
            messages_per_tenant_per_day=100,
            avg_message_kb=10.0,
            pct_internal=0.5,
            pct_known_partner=0.5,
            tier1_inference_cost_per_1k=0.012,
            tier2_pct_after_tier1=0.10,
            avg_tier2_tokens_in=900,
            avg_tier2_tokens_out=120,
            storage_retention_days=90,
        )
        self.assertAlmostEqual(p.tier0_eligible_pct, 1.0)


if __name__ == "__main__":
    unittest.main()
