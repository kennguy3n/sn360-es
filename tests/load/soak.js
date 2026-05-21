/**
 * k6 soak test for sn360-es.
 *
 * Runs at a moderate, sustained rate over 5 minutes to surface memory
 * leaks, connection-pool exhaustion, or slow-growing latency drift
 * that the 30-second smoke test cannot catch.
 *
 * Targets (same as smoke.js):
 *   - /healthz  (GET)
 *   - /v1/banner/action (POST with invalid token)
 *
 * Thresholds:
 *   - p(95) latency < 800 ms (relaxed vs smoke because 5m soak can
 *     accumulate GC pauses)
 *   - p(99) latency < 1500 ms
 *   - error rate < 0.5 %
 *
 * Usage:
 *   K6_TARGET=http://localhost:8080 k6 run tests/load/soak.js
 */

import http from "k6/http";
import { check, sleep } from "k6";

const BASE = __ENV.K6_TARGET || "http://localhost:8080";

export const options = {
  vus: 10,
  duration: "5m",
  thresholds: {
    http_req_duration: ["p(95)<800", "p(99)<1500"],
    http_req_failed: ["rate<0.005"],
  },
};

export default function () {
  const healthRes = http.get(`${BASE}/healthz`);
  check(healthRes, {
    "healthz 200": (r) => r.status === 200,
  });

  const payload = JSON.stringify({
    token: "soak-test-token-invalid",
    action: "trust",
  });
  const params = { headers: { "Content-Type": "application/json" } };
  const actionRes = http.post(`${BASE}/v1/banner/action`, payload, params);
  check(actionRes, {
    "banner/action responds": (r) =>
      r.status === 400 || r.status === 401 || r.status === 200,
  });

  // Steady pacing — one iteration every ~0.5–0.8 s per VU.
  sleep(0.5 + Math.random() * 0.3);
}
