// tests/load/smoke.js
//
// 2-minute baseline-profile load smoke test against a fresh
// `make dev-up` environment plus a running `sn360-es-loadgen
// publisher`. The intent is "in under two minutes prove the
// ingest path is alive and capture all six metric families" —
// this is what CI runs on every PR.
//
// To run locally:
//
//   make dev-up                              # docker compose for NATS / PG / Redis
//   bin/sn360-es-migrate -up                 # apply schema
//   bin/sn360-es                             # run the API server (background)
//   bin/sn360-es-loadgen bootstrap -count=32 # seed a small tenant pool
//   bin/sn360-es-loadgen publisher           # start the HTTP -> NATS shim
//   make load-smoke                          # this file
//
// The result artefact lands at
// tests/load/results/smoke-<unix_ts>.json and contains the same
// k6_summary + metrics_snapshot shape as a full scenario, so the
// release-over-release comparison in tests/load/README.md works
// against smoke runs too.

import { runScenario } from "./lib/scenario.js";

const scenario = runScenario({
  name: "baseline",
  // Smoke deliberately runs short and uses a tiny tenant pool so
  // a CI runner can finish in <2 min without docker resource
  // strain. The full baseline scenario lives in baseline.js.
  durationMin: 2,
  tenants: 32,
  // Pin the seed so two consecutive smoke runs against the same
  // build produce comparable artefacts.
  seed: 42,
});

export const options = scenario.options;
export default scenario.iter;

export function handleSummary(data) {
  const out = scenario.summary(data);
  const ts = Math.floor(Date.now() / 1000);
  const path = `tests/load/results/smoke-${ts}.json`;
  return {
    [path]: JSON.stringify(out, null, 2),
    stdout: renderStdout(out),
  };
}

function renderStdout(out) {
  const lat = out.k6_summary.loadgen_publish_latency_ms || {};
  const ok = (out.k6_summary.loadgen_publish_ok || {}).count || 0;
  const err = (out.k6_summary.loadgen_publish_errors || {}).count || 0;
  return [
    "",
    `load-smoke (${out.scenario}, profile=${out.cost_model_profile})`,
    `  msgs_per_sec target = ${out.config.msgs_per_sec}`,
    `  publish ok           = ${ok}`,
    `  publish err          = ${err}`,
    `  publish_latency p50  = ${(lat.med ?? 0).toFixed(1)} ms`,
    `  publish_latency p95  = ${(lat.p95 ?? 0).toFixed(1)} ms`,
    `  publish_latency p99  = ${(lat.p99 ?? 0).toFixed(1)} ms`,
    `  metric families      = ${
      Object.keys(out.metrics_snapshot.families || {}).length
    }`,
    "",
  ].join("\n");
}
