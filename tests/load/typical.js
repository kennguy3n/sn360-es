// tests/load/typical.js
//
// Full WS-6a typical scenario:
// 5,000 tenants × 1,200 msgs/tenant/day -> ~69.4 msg/s sustained.
//
// Equivalent to scripts/cost_model/project.py's "medium" profile.

import { runScenario } from "./lib/scenario.js";

// durationMin is intentionally not passed; loadConfig reads
// LOAD_DURATION_MIN itself and falls back to the per-scenario
// defaultDurationMin in SCENARIOS.
const scenario = runScenario({
  name: "typical",
  seed: 42,
});

export const options = scenario.options;
export default scenario.iter;

export function handleSummary(data) {
  const out = scenario.summary(data);
  const ts = Math.floor(Date.now() / 1000);
  return {
    [`tests/load/results/typical-${ts}.json`]: JSON.stringify(out, null, 2),
    stdout: JSON.stringify(out.k6_summary, null, 2),
  };
}
