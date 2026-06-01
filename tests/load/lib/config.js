// tests/load/lib/config.js
//
// Central source of truth for the WS-6a scenario knobs. Every other
// module in `tests/load/lib/` (scenario, corpus, metrics, ...) reads
// from this file rather than parsing __ENV themselves so it stays
// trivial to spin up a new scenario without rewriting flag plumbing.
//
// The three named profiles match `scripts/cost_model/project.py`
// (low / medium / high) — the spec calls them
// `baseline` / `typical` / `peak` so the user-facing names track
// the cost-model traffic-profile labels.
//
// All env-var overrides are documented in tests/load/README.md.

/**
 * messagesPerSecond turns a per-tenant-per-day rate plus a tenant
 * count into the steady-state messages-per-second the harness aims
 * for. We round to the nearest 0.1 msg/s so the k6 ramping curve
 * stays readable in dashboards.
 *
 * @param {number} tenants               number of pre-provisioned tenants
 * @param {number} msgsPerTenantPerDay   cost-model traffic-profile rate
 * @returns {number}                     messages-per-second target
 */
export function messagesPerSecond(tenants, msgsPerTenantPerDay) {
  const secondsInADay = 86_400;
  return Math.round(((tenants * msgsPerTenantPerDay) / secondsInADay) * 10) / 10;
}

/**
 * SCENARIOS keys map 1:1 to the names quoted in WS-6a §6a.
 *
 *   baseline  - 5,000 tenants × 200    msgs/tenant/day -> ~11.6 msg/s
 *   typical   - 5,000 tenants × 1,200  msgs/tenant/day -> ~69   msg/s
 *   peak      - 5,000 tenants × 8,500  msgs/tenant/day -> ~492  msg/s
 *
 * costModelProfile is the matching entry in
 * scripts/cost_model/project.py PROFILES (`low`/`medium`/`high`).
 * It is recorded into the result artefact so a reader can re-derive
 * the upstream economics.
 */
export const SCENARIOS = {
  baseline: {
    name: "baseline",
    costModelProfile: "low",
    msgsPerTenantPerDay: 200,
    defaultTenants: 5000,
    // Reasonable bounds for release-over-release comparison; CI
    // sanity-checks against these in the smoke job, the soak job
    // logs them for context.
    expectedP99Ms: 2000,
    expectedNATSLagBound: 200,
  },
  typical: {
    name: "typical",
    costModelProfile: "medium",
    msgsPerTenantPerDay: 1200,
    defaultTenants: 5000,
    expectedP99Ms: 2500,
    expectedNATSLagBound: 1500,
  },
  peak: {
    name: "peak",
    costModelProfile: "high",
    msgsPerTenantPerDay: 8500,
    defaultTenants: 5000,
    expectedP99Ms: 4000,
    expectedNATSLagBound: 10000,
  },
};

/**
 * loadConfig builds the runtime configuration the scenario runner
 * consumes. It accepts an overrides object (used by the smoke /
 * soak scripts that hard-code a tighter envelope) and reads
 * supplemental knobs from __ENV.
 *
 * Env vars consulted, all optional:
 *
 *   LOADGEN_PUBLISHER_URL   default http://127.0.0.1:9099
 *   LOAD_TENANTS_PATH       default tests/load/results/tenants.json
 *   LOAD_CORPUS_PATH        default scripts/corpus/loadtest/all.json
 *   LOAD_PROM_URL           default http://127.0.0.1:9090
 *   LOAD_NATS_MON_URL       default http://127.0.0.1:8222
 *   LOAD_SEED               default 42  (numeric, parsed via Number)
 *   LOAD_DURATION_MIN       default — scenario-supplied
 *   LOAD_BATCH_SIZE         default 1 (single-message mode)
 *
 * The function never throws; missing fields fall back to scenario
 * defaults so a fresh `make load-smoke` works without env-var setup.
 */
export function loadConfig(scenarioKey, overrides = {}) {
  const base = SCENARIOS[scenarioKey];
  if (!base) {
    throw new Error(
      `loadConfig: unknown scenario ${JSON.stringify(scenarioKey)}; ` +
        `expected one of ${Object.keys(SCENARIOS).join(", ")}`,
    );
  }
  const tenants = numEnv("LOAD_TENANTS", overrides.tenants ?? base.defaultTenants);
  const msgsPerTenantPerDay = numEnv(
    "LOAD_MSGS_PER_TENANT_PER_DAY",
    overrides.msgsPerTenantPerDay ?? base.msgsPerTenantPerDay,
  );
  const msgsPerSec = messagesPerSecond(tenants, msgsPerTenantPerDay);
  const durationMin = numEnv("LOAD_DURATION_MIN", overrides.durationMin ?? 2);
  return {
    scenario: base.name,
    costModelProfile: base.costModelProfile,
    tenants,
    msgsPerTenantPerDay,
    msgsPerSec,
    durationMin,
    seed: numEnv("LOAD_SEED", overrides.seed ?? 42),
    batchSize: numEnv("LOAD_BATCH_SIZE", overrides.batchSize ?? 1),
    publisherURL: __ENV.LOADGEN_PUBLISHER_URL || "http://127.0.0.1:9099",
    // Paths are resolved by k6 relative to the open()-calling
    // module file (tests/load/lib/scenario.js + corpus.js), so
    // the defaults walk up two directories to the repo root.
    // Absolute paths from the env override are honoured as-is.
    tenantsPath:
      __ENV.LOAD_TENANTS_PATH || "../../tests/load/results/tenants.json",
    corpusPath:
      __ENV.LOAD_CORPUS_PATH || "../../scripts/corpus/loadtest/all.json",
    promURL: __ENV.LOAD_PROM_URL || "http://127.0.0.1:9090",
    natsMonURL: __ENV.LOAD_NATS_MON_URL || "http://127.0.0.1:8222",
    expectedP99Ms: base.expectedP99Ms,
    expectedNATSLagBound: base.expectedNATSLagBound,
    appURL: __ENV.K6_TARGET || "http://127.0.0.1:8080",
  };
}

function numEnv(name, fallback) {
  const raw = __ENV[name];
  if (raw === undefined || raw === null || raw === "") {
    return fallback;
  }
  const n = Number(raw);
  if (!Number.isFinite(n)) {
    throw new Error(
      `loadConfig: env var ${name}=${JSON.stringify(raw)} is not a finite number`,
    );
  }
  return n;
}
