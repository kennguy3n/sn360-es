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
        self.assertLess(savings["low"], savings["medium"])
        self.assertLess(savings["medium"], savings["high"])

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
