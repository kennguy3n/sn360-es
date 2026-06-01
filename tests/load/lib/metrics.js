// tests/load/lib/metrics.js
//
// Capture the six metric families WS-6a requires from a running
// scenario. Two upstream sources are involved:
//
//   * Prometheus at $LOAD_PROM_URL (default 127.0.0.1:9090).
//     Holds sn360-es application metrics (tier2_inflight_requests,
//     evaluate_latency, queue depths) plus exporter-sourced infra
//     metrics (PgBouncer pool, Redis memory).
//
//   * NATS monitoring endpoint at $LOAD_NATS_MON_URL/jsz (default
//     127.0.0.1:8222). Reports JetStream consumer lag directly,
//     in case Prometheus scraping has not yet caught up.
//
// Each query is best-effort: a missing exporter returns null
// rather than failing the run. The result artefact records the
// success / failure of each captured metric so a reader can tell
// "infra was unavailable" from "infra was at 0".

import http from "k6/http";

/**
 * REQUIRED_FAMILIES lists every metric family WS-6a §6a requires
 * the result artefact to carry. The shape is stable across runs
 * regardless of which exporters are reachable: each key always
 * lands on `snap.families`, either with a captured object or
 * null. This is what lets the CI artefact validation, the
 * Grafana dashboard, and release-over-release diffs all assume
 * a fixed schema.
 */
export const REQUIRED_FAMILIES = [
  "e2e_latency_expected_p99_ms",
  "nats_consumer_lag",
  "nats_consumer_lag_bound",
  "pg_client_connections",
  "pg_server_connections",
  "redis_memory_bytes",
  "tier1_queue_depth",
  "tier2_queue_depth",
  "tier2_inflight_requests",
];

/**
 * captureMetrics runs every captured query, returns a single
 * snapshot object the scenario embeds in the run artefact. Safe
 * to call from teardown(); does not depend on VU state.
 *
 * The capture is *best-effort*: any unreachable exporter records
 * null for the affected family rather than failing the run. The
 * outer status field (`prometheus_status`) summarises what got
 * captured so a downstream consumer (CI validation, soak runner)
 * can branch on it.
 *
 * @param {object} cfg  loadConfig() output
 * @returns {object}
 */
export function captureMetrics(cfg) {
  const snap = {
    captured_at: new Date().toISOString(),
    prom_url: cfg.promURL,
    nats_mon_url: cfg.natsMonURL,
    families: {},
    errors: [],
    // Pre-populate every required key with null so the artefact
    // schema is stable even when every exporter is down (e.g. CI
    // smoke runs without Prometheus). Real values overwrite these
    // below.
    prom_query_attempts: 0,
    prom_query_successes: 0,
  };
  for (const key of REQUIRED_FAMILIES) {
    snap.families[key] = null;
  }

  // 1. End-to-end latency (already collected by k6 client-side
  //    via http_req_duration; we record the configured expected
  //    p99 here so the artefact is self-describing without joining
  //    the k6 summary).
  snap.families.e2e_latency_expected_p99_ms = {
    value: cfg.expectedP99Ms,
    source: "config",
  };

  // 2. NATS consumer lag (KEDA scaler input). We read it from
  //    Prometheus first (preferred — already smoothed), then
  //    fall back to the NATS /jsz endpoint.
  snap.families.nats_consumer_lag = readPromVector(
    snap,
    cfg.promURL,
    'sum(nats_jetstream_consumer_num_pending)',
    "prometheus.sum(nats_jetstream_consumer_num_pending)",
  );
  if (snap.families.nats_consumer_lag == null) {
    snap.families.nats_consumer_lag = readNATSJSZ(snap, cfg.natsMonURL);
  }
  snap.families.nats_consumer_lag_bound = {
    value: cfg.expectedNATSLagBound,
    source: "config",
  };

  // 3. Postgres connection count: PgBouncer client + server side.
  //    The metrics exporter exposes pgbouncer_client_connections
  //    and pgbouncer_server_connections; if the exporter is not
  //    deployed we fall back to a basic pg_stat_activity gauge so
  //    smoke runs against a plain Postgres still capture something.
  snap.families.pg_client_connections = readPromVector(
    snap,
    cfg.promURL,
    'sum(pgbouncer_client_connections)',
    "prometheus.sum(pgbouncer_client_connections)",
  );
  if (snap.families.pg_client_connections == null) {
    snap.families.pg_client_connections = readPromVector(
      snap,
      cfg.promURL,
      'sum(pg_stat_activity_count)',
      "prometheus.sum(pg_stat_activity_count)",
    );
  }
  snap.families.pg_server_connections = readPromVector(
    snap,
    cfg.promURL,
    'sum(pgbouncer_server_connections)',
    "prometheus.sum(pgbouncer_server_connections)",
  );

  // 4. Redis memory usage.
  snap.families.redis_memory_bytes = readPromVector(
    snap,
    cfg.promURL,
    'redis_memory_used_bytes',
    "prometheus.redis_memory_used_bytes",
  );

  // 5. Tier 1 / Tier 2 queue depth. The application exposes per-
  //    tier consumer streams under the same num_pending family;
  //    we filter via the consumer_name label.
  snap.families.tier1_queue_depth = readPromVector(
    snap,
    cfg.promURL,
    'sum(nats_jetstream_consumer_num_pending{consumer_name=~".*tier1.*"})',
    "prometheus.tier1.consumer_num_pending",
  );
  snap.families.tier2_queue_depth = readPromVector(
    snap,
    cfg.promURL,
    'sum(nats_jetstream_consumer_num_pending{consumer_name=~".*tier2.*"})',
    "prometheus.tier2.consumer_num_pending",
  );

  // 6. Tier 2 SLM call concurrency — gauge introduced in this PR.
  snap.families.tier2_inflight_requests = readPromVector(
    snap,
    cfg.promURL,
    'sum(sn360_es_tier2_inflight_requests)',
    "prometheus.sn360_es_tier2_inflight_requests",
  );

  // Summarise Prometheus reachability so callers don't have to
  // walk snap.errors. Three states:
  //   - "available"   every Prom query returned a usable response
  //   - "partial"     some queries succeeded, some failed
  //   - "unreachable" zero Prom queries succeeded; usually means
  //                   $LOAD_PROM_URL is offline (CI smoke runs
  //                   without Prom by design)
  // The NATS /jsz fallback for nats_consumer_lag is *not* counted
  // as a Prom success — `prometheus_status` exclusively tracks
  // Prometheus reachability.
  snap.prometheus_status = summarisePromStatus(snap);

  return snap;
}

function summarisePromStatus(snap) {
  if (snap.prom_query_attempts === 0) {
    return "unreachable";
  }
  if (snap.prom_query_successes === 0) {
    return "unreachable";
  }
  if (snap.prom_query_successes < snap.prom_query_attempts) {
    return "partial";
  }
  return "available";
}

/**
 * readPromVector hits Prometheus' instant-query API and returns
 * {value, source} or null if the query failed / matched no series.
 * Errors are recorded in snap.errors for the result artefact.
 */
function readPromVector(snap, promURL, query, label) {
  snap.prom_query_attempts += 1;
  const url = `${promURL}/api/v1/query?query=${encodeURIComponent(query)}`;
  let res;
  try {
    res = http.get(url, { timeout: "5s", tags: { metric: label } });
  } catch (e) {
    snap.errors.push({ metric: label, error: `request failed: ${e}` });
    return null;
  }
  if (res.status !== 200) {
    snap.errors.push({ metric: label, error: `http ${res.status}` });
    return null;
  }
  let body;
  try {
    body = res.json();
  } catch (e) {
    snap.errors.push({ metric: label, error: `parse: ${e}` });
    return null;
  }
  if (!body || body.status !== "success") {
    snap.errors.push({
      metric: label,
      error: `prom status=${body && body.status}`,
    });
    return null;
  }
  // From here down, Prometheus answered cleanly — even an empty
  // vector counts as a success for the reachability tally.
  snap.prom_query_successes += 1;
  const result = (body.data && body.data.result) || [];
  if (result.length === 0) {
    // Empty result is a real signal — "no series matched". Record
    // it as null rather than 0 so we don't conflate "scraper
    // hasn't seen the metric yet" with "metric was actually zero".
    return { value: null, source: label, empty: true };
  }
  // Sum all returned series. For the typical sum() queries we
  // already issue, this collapses to a single number.
  let total = 0;
  for (const r of result) {
    const v = parseFloat(r.value && r.value[1]);
    if (Number.isFinite(v)) {
      total += v;
    }
  }
  return { value: total, source: label, series_count: result.length };
}

/**
 * readNATSJSZ pulls consumer-pending counts straight from NATS'
 * /jsz?consumers=1 endpoint. Returns the sum across every
 * consumer on every stream so the metric matches the Prometheus
 * fallback exactly.
 */
function readNATSJSZ(snap, natsMonURL) {
  const url = `${natsMonURL}/jsz?consumers=1`;
  let res;
  try {
    res = http.get(url, { timeout: "5s", tags: { metric: "nats.jsz" } });
  } catch (e) {
    snap.errors.push({ metric: "nats.jsz", error: `request: ${e}` });
    return null;
  }
  if (res.status !== 200) {
    snap.errors.push({ metric: "nats.jsz", error: `http ${res.status}` });
    return null;
  }
  let body;
  try {
    body = res.json();
  } catch (e) {
    snap.errors.push({ metric: "nats.jsz", error: `parse: ${e}` });
    return null;
  }
  let total = 0;
  let consumerCount = 0;
  const accounts = (body && body.account_details) || [];
  for (const acc of accounts) {
    const streams = acc.stream_detail || [];
    for (const s of streams) {
      const consumers = s.consumer_detail || [];
      for (const c of consumers) {
        consumerCount += 1;
        if (typeof c.num_pending === "number") {
          total += c.num_pending;
        }
      }
    }
  }
  return {
    value: total,
    source: "nats.jsz.num_pending",
    consumer_count: consumerCount,
  };
}
