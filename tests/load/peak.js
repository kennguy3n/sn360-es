// tests/load/peak.js
//
// Full WS-6a peak scenario:
// 5,000 tenants × 8,500 msgs/tenant/day -> ~491.9 msg/s sustained.
//
// Equivalent to scripts/cost_model/project.py's "high" profile.
//
// Peak is the most expensive of the three; default LOAD_BATCH_SIZE
// is 4 so k6 issues ~123 HTTP requests/sec rather than ~492, which
// keeps the dev publisher's TCP allocation reasonable. Single-
// message mode is still available via LOAD_BATCH_SIZE=1.

import { runScenario } from "./lib/scenario.js";

const scenario = runScenario({
  name: "peak",
  durationMin: Number(__ENV.LOAD_DURATION_MIN || 10),
  seed: 42,
});

// Default batchSize bump for peak. Users can still override with
// LOAD_BATCH_SIZE=1 to fan out one HTTP call per message.
if (!__ENV.LOAD_BATCH_SIZE) {
  scenario.cfg.batchSize = 4;
}

export const options = scenario.options;
export default scenario.iter;

export function handleSummary(data) {
  const out = scenario.summary(data);
  const ts = Math.floor(Date.now() / 1000);
  return {
    [`tests/load/results/peak-${ts}.json`]: JSON.stringify(out, null, 2),
    stdout: JSON.stringify(out.k6_summary, null, 2),
  };
}
