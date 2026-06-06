//go:build chaos
// +build chaos

// Tier 1 encoder OOM chaos scenario.
//
// Failure injected.
//
//	The Tier 1 encoder is the Python ONNX inference service
//	(internal/service/tier1 talks to it over HTTP at TIER1_URL).
//	Under load — large message bodies, a burst of concurrent
//	inferences, or a model-rollout memory leak — the encoder
//	process can exhaust its memory cgroup and be OOM-killed, or a
//	memory guard in front of the model can start shedding load.
//	Either way the inference endpoint stops returning 2xx.
//
//	This test points sn360-es at a controllable Tier 1 mock that
//	speaks the canonical /predict + /predict/batch contract, drives
//	a baseline phishing message through to confirm Tier 1 is wired
//	and contributing a score, then flips the encoder into an "OOM"
//	state where every inference request returns 503. Tier 2 and
//	Rspamd stay healthy throughout, so the only variable is the
//	encoder.
//
// Behaviour pinned by this test (the production contract,
// DEGRADATION_MODES.md §Tier 1 encoder unreachable).
//
//  1. No verdict is silently downgraded — when the encoder is
//     OOM-killed, a message that scored Blocked/HighRisk with Tier 1
//     present must still escalate above Trusted/Informational via
//     Tier 0 + Tier 2 + Rspamd reasoning. Losing the ML score must
//     never make a phishing message look safe.
//  2. The Tier 1 outcome is dropped, not faked: res.Tier1 is nil on
//     every degraded verdict (the evaluator at
//     internal/service/evaluate/evaluator.go:388-395 leaves it unset
//     and appends "tier1" to DegradedServices) and res.Degraded is
//     true.
//  3. The operator-visible counters move: the Tier 1 inference
//     counter increments with verdict="error"
//     (sn360_es_tier1_inferences_total{verdict="error"}) and
//     sn360_es_evaluate_degraded_total{service="tier1"} climbs by at
//     least one per affected verdict.
//  4. No false success: the healthy-verdict label of
//     sn360_es_tier1_inferences_total must NOT climb once the encoder
//     is dead — a short-circuited / errored inference may never be
//     recorded as a successful one.
//
// Cross-references.
//
//   - Tier 1 client:     internal/service/tier1/encoder.go (doSingle
//     returns an error on any non-2xx, which is what surfaces the OOM
//     503 to the evaluator)
//   - Degraded wiring:   internal/service/evaluate/evaluator.go:388-395
//   - Metrics:           pkg/telemetry/metrics.go::Tier1Inferences,
//     EvaluateDegraded
//   - Degradation doc:   docs/DEGRADATION_MODES.md
package chaos_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// chaosTier1TenantID is a deterministic UUID (encoding "Chaos
// Tier 1 #001" as 0xc1a00001) so the scenario is visually distinct
// from the Tier 2 tenant while still parsing cleanly as an RFC 4122
// UUID.
const chaosTier1TenantID = "00000000-0000-0000-0000-0000c1a00001"

// TestChaos_Tier1EncoderOOM pins the documented Tier 1 degradation
// path: when the ONNX encoder is OOM-killed mid-flight, verdicts must
// degrade gracefully (Tier 0 + Tier 2 + Rspamd carry the decision)
// rather than silently downgrading to a safe-looking tier. See the
// package-doc above for the full assertion contract.
func TestChaos_Tier1EncoderOOM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), chaosTimeout)
	defer cancel()

	repoRoot := findRepoRoot(t)
	binary := buildSn360ES(t)

	_, pgCfg := startPostgres(ctx, t)
	_, redisAddr := startRedis(ctx, t)
	_, natsURL := startNATS(ctx, t)

	applyMigrations(ctx, t, repoRoot, pgCfg)
	seedTenant(ctx, t, pgCfg, chaosTier1TenantID)

	// Tier 1 is the unit under test: a controllable mock we can
	// flip into an OOM (503) state. Tier 2 and Rspamd stay healthy
	// so the post-failure verdict can still escalate through them.
	tier1, oom := startTier1MockOOMControllable(t)
	tier2 := startTier2Mock(t)
	t.Cleanup(tier2.Close)
	rspamd := startRspamdMock(t)

	port := freePort(t)
	env := appEnv{
		pg:        pgCfg,
		redisAddr: redisAddr,
		natsURL:   natsURL,
		tier1URL:  tier1.URL,
		tier2URL:  tier2.URL,
		rspamdURL: rspamd.URL,
		httpPort:  port,
		extra: map[string]string{
			// Trip the breaker on the third consecutive failure so
			// the back half of the scenario exercises the open-breaker
			// short-circuit too (mirrors the Tier 2 scenario). The
			// production default is 5 (internal/config/scoring.go);
			// 3 keeps the run inside its time budget without changing
			// the semantics being pinned. Tier 2 + Rspamd stay healthy
			// so sharing the threshold across the BreakerSet is fine.
			"CB_FAILURE_THRESHOLD": "3",
			"CB_OPEN_TIMEOUT":      "30s",
		},
	}.build()
	app := startApp(ctx, t, binary, env)
	t.Cleanup(func() { stopApp(t, app) })

	healthURL := fmt.Sprintf("http://127.0.0.1:%d/readyz", port)
	metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	waitForHealthy(ctx, t, healthURL)

	nc, js := connectJetStream(t, natsURL)
	t.Cleanup(nc.Close)

	resultCh := subscribeResultStream(ctx, t, js, "chaos-tier1-result-watcher")

	// ----- 1. Baseline: encoder healthy, Tier 1 contributes --------
	baselineID := publishEvalReq(ctx, t, js, chaosTier1TenantID, "baseline-")
	baseline := waitForResult(ctx, t, resultCh, baselineID)
	if baseline.Tier1 == nil {
		t.Fatalf("baseline: Tier1 outcome missing — the encoder should have run")
	}
	if baseline.Tier != constant.TierBlocked && baseline.Tier != constant.TierHighRisk {
		t.Fatalf("baseline: tier = %q, want Blocked or HighRisk", baseline.Tier)
	}
	if baseline.Degraded {
		t.Fatalf("baseline: Degraded = true, want false (all tiers were healthy)")
	}

	// Sample counters so we assert increments, not absolutes.
	tier1ErrBefore := counterValue(t, metricsURL, "sn360_es_tier1_inferences_total", map[string]string{"verdict": "error"})
	degradedBefore := counterValue(t, metricsURL, "sn360_es_evaluate_degraded_total", map[string]string{"service": "tier1"})
	// The baseline inference returns score 92 → the evaluator records
	// the verdict label the categoriser derives (e.g. "escalate").
	// Whatever it is, it must not climb again once the encoder is dead.
	tier1OKBefore := tier1HealthyInferenceTotal(t, metricsURL)

	// ----- 2. Inject the OOM ---------------------------------------
	// Flip the encoder into its OOM state: every subsequent /predict
	// and /predict/batch returns 503, exactly as a memory-guard or a
	// freshly OOM-killed worker behind a ready proxy would. The Tier 1
	// client maps any non-2xx to an error (encoder.go:176), so the
	// evaluator takes its degraded path.
	oom.Store(true)

	// ----- 3. Drive enough failures to open the breaker ------------
	const followups = 5
	type seenResult struct {
		messageID string
		result    dto.EvaluateResult
	}
	results := make([]seenResult, 0, followups)
	for i := 0; i < followups; i++ {
		id := publishEvalReq(ctx, t, js, chaosTier1TenantID, fmt.Sprintf("oom-%02d-", i))
		res := waitForResult(ctx, t, resultCh, id)
		results = append(results, seenResult{messageID: id, result: res})
	}

	for _, sr := range results {
		if sr.result.Tier == constant.TierTrusted || sr.result.Tier == constant.TierInformational {
			t.Fatalf("oom %s: tier = %q — a dead encoder silently downgraded the verdict (expected Blocked or HighRisk via Tier 0 + Tier 2 + Rspamd)",
				sr.messageID, sr.result.Tier)
		}
		// The Tier 1 outcome must be absent: runTier1 returned an
		// error so the evaluator leaves res.Tier1 == nil and appends
		// "tier1" to DegradedServices. A non-nil Tier1 here would mean
		// a stale or fabricated score leaked into the verdict.
		if sr.result.Tier1 != nil {
			t.Fatalf("oom %s: Tier1 = %+v, want nil (the encoder is OOM-killed)", sr.messageID, *sr.result.Tier1)
		}
		if !sr.result.Degraded {
			t.Fatalf("oom %s: Degraded = false, want true", sr.messageID)
		}
		if !containsString(sr.result.DegradedServices, "tier1") {
			t.Fatalf("oom %s: DegradedServices = %v, want to contain \"tier1\"", sr.messageID, sr.result.DegradedServices)
		}
	}

	// ----- 4. Assert the operator-visible counters moved -----------
	eventually(t, 10*time.Second, "tier1 error counter increments", func() bool {
		cur := counterValue(t, metricsURL, "sn360_es_tier1_inferences_total", map[string]string{"verdict": "error"})
		return cur-tier1ErrBefore >= float64(followups)
	})
	eventually(t, 10*time.Second, "degraded tier1 counter increments", func() bool {
		cur := counterValue(t, metricsURL, "sn360_es_evaluate_degraded_total", map[string]string{"service": "tier1"})
		return cur-degradedBefore >= float64(followups)
	})

	// ----- 5. Sanity: no errored inference recorded as a success ---
	tier1OKAfter := tier1HealthyInferenceTotal(t, metricsURL)
	if tier1OKAfter > tier1OKBefore {
		t.Fatalf("healthy tier1_inferences_total climbed from %.0f to %.0f after the encoder was OOM-killed — an errored inference is being recorded as a success",
			tier1OKBefore, tier1OKAfter)
	}
}

// startTier1MockOOMControllable returns a Tier 1 encoder stub plus an
// atomic switch. While the switch is false the stub behaves exactly
// like startTier1Mock (a deterministic high-risk verdict on /predict
// and /predict/batch). Once the caller sets it true, every inference
// request returns 503 Service Unavailable with an OOM-style body,
// modelling an OOM-killed worker (or a memory guard shedding load)
// behind a proxy that still answers /health. /health stays ok so the
// failure is scoped to the inference path — the evaluator's degraded
// handling, not the readiness probe, is what this scenario pins.
func startTier1MockOOMControllable(t *testing.T) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var oom atomic.Bool

	writeOOM := func(w http.ResponseWriter) {
		// 503 is what a load-shedding memory guard returns; a
		// hard OOM-kill would sever the socket, but a 503 is the
		// deterministic, portable way to drive the same non-2xx
		// error path (encoder.go treats every non-2xx identically).
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  "out of memory: inference worker killed",
			"detail": "onnxruntime: failed to allocate tensor",
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "model": "xlm-roberta-chaos"})
	})
	mux.HandleFunc("/predict", func(w http.ResponseWriter, _ *http.Request) {
		if oom.Load() {
			writeOOM(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"score":        92,
			"confidence":   0.94,
			"language":     "en",
			"model_tag":    "xlm-roberta-chaos",
			"reason_codes": []string{"WIRE_REQUEST", "URGENT_TONE"},
		})
	})
	mux.HandleFunc("/predict/batch", func(w http.ResponseWriter, _ *http.Request) {
		if oom.Load() {
			writeOOM(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{{
				"score":      92,
				"confidence": 0.94,
				"language":   "en",
				"model_tag":  "xlm-roberta-chaos",
			}},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &oom
}

// tier1HealthyInferenceTotal sums sn360_es_tier1_inferences_total
// across every verdict label except "error", giving the count of
// inferences the encoder actually served successfully. Summing rather
// than reading a single label keeps the success-sanity assertion
// robust to which verdict label the categoriser assigns the baseline.
func tier1HealthyInferenceTotal(t *testing.T, metricsURL string) float64 {
	t.Helper()
	var total float64
	for _, verdict := range []string{"escalate", "flag", "pass", "ham", "phishing", "unknown"} {
		total += counterValue(t, metricsURL, "sn360_es_tier1_inferences_total", map[string]string{"verdict": verdict})
	}
	return total
}
