// tests/load/lib/scenario.js
//
// WS-6a scenario runner. Every k6 script under tests/load/ ends in
// `export const options = buildOptions(...);` and an `export default`
// that delegates to `runIteration()` here. WS-6b will import the
// same building blocks to compose its chaos-aware variant — see
// the brief.
//
// Why two exports (`buildOptions` + `runIteration`) instead of a
// single `runScenario({...})` wrapper? k6 requires the scenarios
// object to be set on a top-level `export const options` literal
// at module-init time so VU allocation happens before any code
// runs. A runScenario({...}) call that returned options would not
// satisfy that constraint, so we expose the two halves separately.

import http from "k6/http";
import { check } from "k6";
import { Counter, Trend } from "k6/metrics";
import { loadConfig, SCENARIOS } from "./config.js";
import { loadCorpus, pickEmail, buildPayload, verifyCorpus } from "./corpus.js";
import { captureMetrics } from "./metrics.js";
import { mulberry32 } from "./seed.js";

// Custom k6 metrics. We track these in addition to the default
// http_req_duration so the result artefact gets a clean
// per-scenario projection.
export const publishOK = new Counter("loadgen_publish_ok");
export const publishErrors = new Counter("loadgen_publish_errors");
export const publishLatency = new Trend("loadgen_publish_latency_ms", true);

/**
 * buildOptions returns the k6 `options` object for a scenario. It
 * derives the constant-arrival-rate parameters from the scenario's
 * cost-model profile so all three scenarios use the same shape.
 *
 *   const cfg = loadConfig("typical");
 *   export const options = buildOptions(cfg);
 *
 * @param {object} cfg                 loadConfig(...) output
 * @param {object} [overrides]         optional override for thresholds / VUs
 * @returns {object}                   k6 options object
 */
export function buildOptions(cfg, overrides = {}) {
  // Cap the pre-allocated VU pool so a runaway scenario does not
  // open thousands of TCP connections against the dev publisher.
  // The peak scenario at ~492 msg/s with one HTTP call per message
  // and a 100 ms p95 round-trip needs ~50 VUs; we keep headroom.
  const baseVUs = Math.max(20, Math.ceil(cfg.msgsPerSec * 0.5));
  const maxVUs = Math.max(baseVUs, Math.ceil(cfg.msgsPerSec * 2));
  // k6's constant-arrival-rate `rate` must be a positive integer.
  // For the smoke profile (32 tenants × 200/day -> 0.07 msg/s)
  // that rounds to zero, so we floor at 1 msg/s. The real
  // per-scenario rates (>= 11 for baseline at 5,000 tenants) are
  // already integers after the ceil, so this only affects smoke.
  const ratePerSec = Math.max(1, Math.ceil(cfg.msgsPerSec));
  return {
    discardResponseBodies: true,
    // WS-6a captures p50/p95/p99 explicitly. k6's default trend
    // stats only include avg / min / med / max / p(90) / p(95);
    // we add p(50) and p(99) so the artefact has the
    // canonical brief-spec percentiles available for
    // release-over-release comparison.
    summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
    scenarios: {
      [cfg.scenario]: {
        executor: "constant-arrival-rate",
        rate: ratePerSec,
        timeUnit: "1s",
        duration: `${cfg.durationMin}m`,
        preAllocatedVUs: overrides.preAllocatedVUs ?? baseVUs,
        maxVUs: overrides.maxVUs ?? maxVUs,
        gracefulStop: "30s",
      },
    },
    thresholds: {
      // Use the publisher round-trip as a proxy for the ingest
      // p99 — the publisher returns 200 once JetStream Publish()
      // returns, so the timing closely tracks ingest-to-NATS.
      loadgen_publish_latency_ms: [`p(99)<${cfg.expectedP99Ms}`],
      loadgen_publish_errors: ["count<10"],
      // Default k6 metric: total HTTP failure rate over the run.
      http_req_failed: ["rate<0.01"],
    },
  };
}

/**
 * loadHarness wires up the per-VU shared state. Call it once in
 * the script's init context.
 *
 *   const cfg = loadConfig("baseline");
 *   const harness = loadHarness(cfg);
 *   export default function () { runIteration(cfg, harness); }
 *
 * @param {object} cfg                 loadConfig(...) output
 * @returns {{corpus: Array, tenants: Array, rand: () => number}}
 */
export function loadHarness(cfg) {
  // The corpus + tenant manifest are loaded once per VU init.
  // Any fall-back diagnostics (e.g. "corpus file missing, using
  // inline mini-corpus") are captured into `cfg.harnessNotes`
  // instead of console.warn'd — that way a 20-VU smoke run does
  // not print 20 identical warnings, and the artefact records
  // the substitution unambiguously.
  cfg.harnessNotes = cfg.harnessNotes || [];
  const corpus = loadCorpus(cfg.corpusPath, cfg.harnessNotes);
  verifyCorpus(corpus);
  const tenants = loadTenants(cfg, cfg.harnessNotes);
  // Seed deterministically off (scenario, seed) so two scenarios
  // running back-to-back don't pick identical corpus rows; this is
  // the same seed echoed into the result artefact.
  const compositeSeed = (cfg.seed * 1103515245 + hashStr(cfg.scenario)) | 0;
  const rand = mulberry32(compositeSeed);
  return { corpus, tenants, rand };
}

/**
 * runIteration publishes one (or, when cfg.batchSize > 1, a small
 * batch of) EvaluateRequest messages and records the round-trip
 * timing. The default export of every scenario script calls this
 * with the matching cfg + harness.
 */
export function runIteration(cfg, harness) {
  const iter = __ITER || 0;
  const tenant = harness.tenants[iter % harness.tenants.length];
  if (cfg.batchSize <= 1) {
    publishSingle(cfg, tenant, harness, iter);
    return;
  }
  publishBatch(cfg, tenant, harness, iter);
}

function publishSingle(cfg, tenant, harness, iter) {
  const env = pickEmail(harness.corpus, harness.rand);
  const payload = buildPayload(cfg, tenant.tenant_id, env, iter);
  const url = `${cfg.publisherURL}/publish`;
  const t0 = Date.now();
  const res = http.post(url, JSON.stringify(payload), {
    headers: { "Content-Type": "application/json" },
    timeout: "10s",
    tags: { scenario: cfg.scenario, attack_type: env.attackType || "unknown" },
  });
  publishLatency.add(Date.now() - t0);
  const ok = check(res, {
    "publisher 200": (r) => r.status === 200,
  });
  if (ok) {
    publishOK.add(1);
  } else {
    publishErrors.add(1);
  }
}

function publishBatch(cfg, tenant, harness, iter) {
  const payloads = [];
  for (let i = 0; i < cfg.batchSize; i++) {
    const env = pickEmail(harness.corpus, harness.rand);
    payloads.push(buildPayload(cfg, tenant.tenant_id, env, iter * cfg.batchSize + i));
  }
  const url = `${cfg.publisherURL}/publish/batch`;
  const t0 = Date.now();
  const res = http.post(url, JSON.stringify(payloads), {
    headers: { "Content-Type": "application/json" },
    timeout: "15s",
    tags: { scenario: cfg.scenario, batch: String(cfg.batchSize) },
  });
  publishLatency.add(Date.now() - t0);
  const ok = check(res, {
    "publisher 200 (batch)": (r) => r.status === 200,
  });
  if (ok) {
    publishOK.add(cfg.batchSize);
  } else {
    publishErrors.add(cfg.batchSize);
  }
}

/**
 * loadTenants reads the bootstrap manifest written by
 * `sn360-es-loadgen bootstrap`. Each entry is `{index, tenant_id,
 * name, provider}`. If the manifest is missing we synthesise a
 * smaller pool so smoke tests still run; the synthesised pool
 * tries to address tenants that bootstrap WOULD have created so a
 * subsequent real bootstrap rewards repeat runs.
 */
function loadTenants(cfg, notes) {
  try {
    const raw = open(cfg.tenantsPath);
    const parsed = JSON.parse(raw);
    if (
      parsed &&
      Array.isArray(parsed.tenants) &&
      parsed.tenants.length > 0
    ) {
      return parsed.tenants;
    }
  } catch (e) {
    if (notes && notes.indexOf("tenants-fallback") === -1) {
      notes.push(
        `tenants-fallback: ${cfg.tenantsPath} not found (${e}); ` +
          `synthesising deterministic 32-tenant pool. ` +
          `Run \`make load-bootstrap\` for the real 5000-tenant pool.`,
      );
      notes.push("tenants-fallback");
    }
  }
  const fallback = [];
  const want = Math.min(32, cfg.tenants);
  for (let i = 0; i < want; i++) {
    fallback.push({
      index: i,
      tenant_id: `00000000-0000-0000-0000-${i.toString(16).padStart(12, "0")}`,
      name: `loadgen-tenant-${i.toString().padStart(4, "0")}`,
      provider: "gws",
    });
  }
  return fallback;
}

/**
 * summarise builds the result artefact handleSummary() writes to
 * tests/load/results/. The shape is intentionally stable so a
 * release-over-release diff is trivial.
 *
 * @param {object} cfg     loadConfig(...) output
 * @param {object} data    k6's handleSummary `data` argument
 * @returns {object}
 */
export function summarise(cfg, data) {
  const metricsSnap = safeCaptureMetrics(cfg);
  return {
    scenario: cfg.scenario,
    cost_model_profile: cfg.costModelProfile,
    harness_notes: (cfg.harnessNotes || []).filter(
      (n) => n !== "corpus-fallback" && n !== "tenants-fallback",
    ),
    started_at: new Date(
      Date.now() - (data.state ? data.state.testRunDurationMs : 0),
    ).toISOString(),
    finished_at: new Date().toISOString(),
    elapsed_ms:
      (data.state && data.state.testRunDurationMs) ||
      cfg.durationMin * 60 * 1000,
    config: {
      tenants: cfg.tenants,
      msgs_per_tenant_per_day: cfg.msgsPerTenantPerDay,
      msgs_per_sec: cfg.msgsPerSec,
      duration_min: cfg.durationMin,
      seed: cfg.seed,
      batch_size: cfg.batchSize,
      publisher_url: cfg.publisherURL,
      prom_url: cfg.promURL,
      nats_mon_url: cfg.natsMonURL,
      expected_p99_ms: cfg.expectedP99Ms,
      expected_nats_lag_bound: cfg.expectedNATSLagBound,
    },
    k6_summary: {
      http_req_duration: extractTrend(data, "http_req_duration"),
      loadgen_publish_latency_ms: extractTrend(
        data,
        "loadgen_publish_latency_ms",
      ),
      loadgen_publish_ok: extractCounter(data, "loadgen_publish_ok"),
      loadgen_publish_errors: extractCounter(data, "loadgen_publish_errors"),
      iterations: extractCounter(data, "iterations"),
      vus_max: extractGauge(data, "vus_max"),
    },
    metrics_snapshot: metricsSnap,
  };
}

function extractTrend(data, name) {
  const m = data.metrics && data.metrics[name];
  if (!m) return null;
  return {
    avg: m.values && m.values.avg,
    med: m.values && m.values.med,
    p50: m.values && m.values["p(50)"],
    p90: m.values && m.values["p(90)"],
    p95: m.values && m.values["p(95)"],
    p99: m.values && m.values["p(99)"],
    max: m.values && m.values.max,
    count: m.values && m.values.count,
  };
}

function extractCounter(data, name) {
  const m = data.metrics && data.metrics[name];
  if (!m) return null;
  return {
    count: m.values && m.values.count,
    rate: m.values && m.values.rate,
  };
}

function extractGauge(data, name) {
  const m = data.metrics && data.metrics[name];
  if (!m) return null;
  return { value: m.values && m.values.value };
}

function safeCaptureMetrics(cfg) {
  try {
    return captureMetrics(cfg);
  } catch (e) {
    return {
      captured_at: new Date().toISOString(),
      errors: [{ metric: "captureMetrics", error: String(e) }],
      families: {},
    };
  }
}

function hashStr(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) | 0;
  }
  return h;
}

/**
 * runScenario is the small wrapper the WS-6a brief asks us to
 * expose so WS-6b (chaos regressions) can compose against the
 * same scenario shape without copy-pasting the option / harness
 * plumbing. It bundles {options, iter, summary} so a consumer
 * can write:
 *
 *   import { runScenario } from "../load/lib/scenario.js";
 *   const s = runScenario({ name: "baseline", durationMin: 2 });
 *   export const options = s.options;
 *   export default s.iter;
 *   export function handleSummary(data) {
 *     return { "summary.json": JSON.stringify(s.summary(data)) };
 *   }
 *
 * @param {object} args
 * @param {string} args.name            one of SCENARIOS keys
 *                                       (baseline / typical / peak)
 * @param {number} [args.msgsPerSecond] override the scenario's
 *                                       computed arrival rate; useful
 *                                       for chaos sweeps
 * @param {number} [args.durationMin]   minutes to hold the load
 * @param {number} [args.tenants]       override tenant count
 * @param {number} [args.seed]          override the seed
 * @param {object} [args.optionsOverrides] passed to buildOptions
 */
export function runScenario(args) {
  if (!args || !SCENARIOS[args.name]) {
    throw new Error(
      `runScenario: name must be one of ${Object.keys(SCENARIOS).join(
        ", ",
      )}, got ${JSON.stringify(args && args.name)}`,
    );
  }
  const overrides = {};
  if (args.tenants !== undefined) overrides.tenants = args.tenants;
  if (args.durationMin !== undefined) overrides.durationMin = args.durationMin;
  if (args.seed !== undefined) overrides.seed = args.seed;
  const cfg = loadConfig(args.name, overrides);
  if (args.msgsPerSecond !== undefined) {
    cfg.msgsPerSec = args.msgsPerSecond;
  }
  const options = buildOptions(cfg, args.optionsOverrides || {});
  const harness = loadHarness(cfg);
  return {
    cfg,
    options,
    iter: () => runIteration(cfg, harness),
    summary: (data) => summarise(cfg, data),
  };
}
