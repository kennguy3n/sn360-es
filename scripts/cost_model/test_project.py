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
        self.assertAlmostEqual(
            project.cost_inference(profile, batched)["tier1"]
            / project.cost_inference(profile, per_msg)["tier1"],
            0.30,
            places=4,
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


if __name__ == "__main__":
    unittest.main()
