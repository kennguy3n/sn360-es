// tests/load/baseline.js
//
// Full WS-6a baseline scenario:
// 5,000 tenants × 200 msgs/tenant/day -> ~11.6 msg/s sustained.
//
// Equivalent to scripts/cost_model/project.py's "low" profile.

import { runScenario } from "./lib/scenario.js";

const scenario = runScenario({
  name: "baseline",
  durationMin: Number(__ENV.LOAD_DURATION_MIN || 10),
  seed: 42,
});

export const options = scenario.options;
export default scenario.iter;

export function handleSummary(data) {
  const out = scenario.summary(data);
  const ts = Math.floor(Date.now() / 1000);
  return {
    [`tests/load/results/baseline-${ts}.json`]: JSON.stringify(out, null, 2),
    stdout: JSON.stringify(out.k6_summary, null, 2),
  };
}
