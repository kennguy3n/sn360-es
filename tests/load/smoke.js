/**
 * k6 smoke load test for sn360-es.
 *
 * Targets:
 *   - /healthz  (GET) – availability probe
 *   - /v1/banner/action (POST) – exercises the JSON decode + signed-
 *     token-validation path (the cheapest authenticated production
 *     endpoint)
 *
 * Thresholds:
 *   - p(95) latency < 500 ms
 *   - error rate < 1 %
 *
 * Usage:
 *   K6_TARGET=http://localhost:8080 k6 run tests/load/smoke.js
 */

import http from "k6/http";
import { check, sleep } from "k6";

// Allow the target to be passed in as an env var (Makefile /
// CI action set K6_TARGET when the app is running).
const BASE = __ENV.K6_TARGET || "http://localhost:8080";

export const options = {
  vus: 50,
  duration: "30s",
  thresholds: {
    http_req_duration: ["p(95)<500"],
    http_req_failed: ["rate<0.01"],
  },
};

export default function () {
  // 1. Health probe — lightweight GET.
  const healthRes = http.get(`${BASE}/healthz`);
  check(healthRes, {
    "healthz 200": (r) => r.status === 200,
  });

  // 2. Banner-action POST — hits the JSON decoding, token
  //    validation, and feedback service. The token is intentionally
  //    invalid (random string); the handler rejects it quickly with
  //    400/401 but still exercises the hot path through middleware,
  //    JSON decoder, and feedback.FeedbackService.HandleAction.
  const payload = JSON.stringify({
    token: "smoke-test-token-invalid",
    action: "report",
  });
  const params = { headers: { "Content-Type": "application/json" } };
  const actionRes = http.post(`${BASE}/v1/banner/action`, payload, params);
  check(actionRes, {
    // 400 or 401 is expected because the token is not a valid JWT.
    "banner/action responds": (r) =>
      r.status === 400 || r.status === 401 || r.status === 200,
  });

  // Small random sleep to avoid perfectly synchronised bursts.
  sleep(0.1 + Math.random() * 0.2);
}
