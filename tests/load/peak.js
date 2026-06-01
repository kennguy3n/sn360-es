// tests/load/peak.js
//
// Full WS-6a peak scenario:
// 5,000 tenants × 8,500 msgs/tenant/day -> ~491.9 msg/s sustained.
//
// Equivalent to scripts/cost_model/project.py's "high" profile.
//
// Peak is the most expensive of the three; default batchSize is 4
// so k6 issues ~123 HTTP requests/sec rather than ~492, which keeps
// the dev publisher's TCP allocation reasonable while still
// delivering the full ~492 msg/s NATS publish rate. Single-message
// mode is still available via LOAD_BATCH_SIZE=1.

import { runScenario } from "./lib/scenario.js";

// batchSize is passed through runScenario so loadConfig picks it
// up before buildOptions computes the arrival rate. Setting it
// after runScenario() returns would be a no-op for the executor
// (it has already snapshotted the options) and would also leave
// the executor's `rate` un-divided by batchSize, producing
// 4× the intended msg/s.
const scenario = runScenario({
  name: "peak",
  durationMin: Number(__ENV.LOAD_DURATION_MIN || 10),
  seed: 42,
  // LOAD_BATCH_SIZE wins if set so an operator can fall back to
  // one-HTTP-call-per-message without editing the script.
  batchSize: Number(__ENV.LOAD_BATCH_SIZE || 4),
});

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
