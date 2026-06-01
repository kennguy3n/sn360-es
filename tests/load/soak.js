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

// Override the typical scenario's defaultDurationMin (10) to 30
// for the long-running soak. LOAD_DURATION_MIN still wins because
// loadConfig consults the env var ahead of the override, so an
// operator can stretch or shrink the soak without editing this
// file.
const scenario = runScenario({
  name: "typical",
  durationMin: 30,
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
  // Soak targets a real environment with a real metrics backend.
  // If Prometheus is unreachable, the run is not useful — abort
  // with a non-zero exit so the operator notices immediately
  // instead of silently producing a soak artefact with all-null
  // families. Smoke deliberately tolerates this; soak does not.
  // Set LOAD_SOAK_ALLOW_NO_PROM=1 only as an escape hatch when
  // intentionally exercising the harness without Prometheus.
  if (
    out.metrics_collection_status === "unreachable" &&
    __ENV.LOAD_SOAK_ALLOW_NO_PROM !== "1"
  ) {
    throw new Error(
      `soak: Prometheus at ${out.config.prom_url} was unreachable for ` +
        `every captured metric; soak runs require a populated metrics ` +
        `backend. Set LOAD_PROM_URL to a reachable Prometheus, or pass ` +
        `LOAD_SOAK_ALLOW_NO_PROM=1 to suppress this check.`,
    );
  }
  return {
    [path]: JSON.stringify(out, null, 2),
    stdout: JSON.stringify(out.k6_summary, null, 2),
  };
}
