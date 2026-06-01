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
  // If Prometheus is unreachable, the run is not useful for the
  // intended "did we leak under 30 minutes of typical load"
  // question, but the k6-side data (publish counts, latency,
  // throughput drift) is still valuable for diagnosing why and
  // for confirming the load itself ran cleanly.
  //
  // So we deliberately do *not* throw here — throwing from
  // handleSummary would discard the entire 30-minute artefact,
  // which is the opposite of what an operator wants when Prom
  // happens to be flaky. Instead we print a loud, multi-line
  // warning to stderr and let the surrounding workflow (or the
  // operator) decide whether to fail the run. The CI scenario
  // job at .github/workflows/load.yml runs a strict
  // post-validation step that enforces
  // metrics_collection_status == "available" for soak (unless
  // LOAD_SOAK_ALLOW_NO_PROM=1) and fails the workflow there,
  // outside the k6 process, so the artefact is still uploaded.
  let stderr = "";
  if (
    out.metrics_collection_status === "unreachable" &&
    __ENV.LOAD_SOAK_ALLOW_NO_PROM !== "1"
  ) {
    stderr =
      "\n" +
      "============================================================\n" +
      "WARNING: soak ran without a reachable Prometheus backend.\n" +
      `  prom_url:                      ${out.config.prom_url}\n` +
      `  metrics_collection_status:     ${out.metrics_collection_status}\n` +
      `  prom_query_successes/attempts: ${out.metrics_snapshot.prom_query_successes}/${out.metrics_snapshot.prom_query_attempts}\n` +
      "Soak runs are only meaningful against a populated metrics\n" +
      "backend — every metric family is null in this artefact.\n" +
      "Set LOAD_PROM_URL to a reachable Prometheus, or pass\n" +
      "LOAD_SOAK_ALLOW_NO_PROM=1 to suppress this warning. CI\n" +
      "will fail the workflow at the post-validation step.\n" +
      "============================================================\n";
  }
  return {
    [path]: JSON.stringify(out, null, 2),
    stdout: JSON.stringify(out.k6_summary, null, 2),
    stderr,
  };
}
