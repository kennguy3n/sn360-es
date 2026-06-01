// tests/load/soak.js
//
// Long-running soak variant of the typical scenario. Holds 5,000
// tenants × 1,200 msgs/tenant/day (~69 msg/s sustained) for 30
// minutes — long enough to flush a leak in the JetStream
// consumer, the management Postgres pool, or the Tier 2 client.
//
// Soaks are NOT gated on every PR. The CI workflow only invokes
// this file via the manual `workflow_dispatch` trigger.

import { runScenario } from "./lib/scenario.js";

const scenario = runScenario({
  name: "typical",
  durationMin: Number(__ENV.LOAD_DURATION_MIN || 30),
  // Default to the full 5000-tenant pool for soak — anyone who
  // wants to soak against a smaller pool can override via the
  // LOAD_TENANTS env var.
  seed: 7,
});

export const options = scenario.options;
export default scenario.iter;

export function handleSummary(data) {
  const out = scenario.summary(data);
  const ts = Math.floor(Date.now() / 1000);
  const path = `tests/load/results/soak-${ts}.json`;
  return {
    [path]: JSON.stringify(out, null, 2),
    stdout: JSON.stringify(out.k6_summary, null, 2),
  };
}
