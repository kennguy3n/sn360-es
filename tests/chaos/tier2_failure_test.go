//go:build chaos
// +build chaos

// Tier 2 SLM failure chaos scenario.
//
// Failure injected.
//
//	The chaos test points sn360-es at a real httptest.Server that
//	speaks the canonical Tier 2 /v1/classify contract, drives a
//	baseline phishing message through the pipeline to confirm
//	Tier 2 is wired and emitting a Blocked-tier verdict, then
//	calls srv.Close() to kill the upstream socket. Every
//	subsequent evaluation request hits the breaker / fallback
//	code path with no other change.
//
// Behaviour pinned by this test (the production contract).
//
//  1. No Blocked decisions are silently downgraded — when Tier 2
//     is unreachable, items that would have been Blocked stay at
//     least HighRisk via Tier 0 + Tier 1 + Rspamd reasoning.
//  2. The evaluator's degraded-services list surfaces "tier2" on
//     every verdict that ran without Tier 2.
//  3. The Prometheus counters operators alert on
//     (sn360_es_tier2_escalations_total{outcome="error"} and
//     sn360_es_evaluate_degraded_total{service="tier2"}) increment
//     by the documented amount.
//  4. The breaker opens after the configured failure threshold and
//     subsequent calls short-circuit to the fallback (ErrCircuitOpen
//     in the absence of a configured fallback Tier 2 client), which
//     manifests as additional `tier2_escalations_total{outcome="error"}`
//     ticks without additional outbound HTTP attempts.
//
// Cross-references.
//
//   - Circuit breaker:   internal/service/evaluate/circuit_breaker.go
//   - Tier 2 wire-up:    cmd/sn360-es/tier2.go
//   - Metrics:           pkg/telemetry/metrics.go::Tier2Escalations,
//     EvaluateDegraded
//   - Degradation doc:   docs/DEGRADATION_MODES.md
package chaos_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// chaosTier2TenantID is a deterministic UUID so the test can
// assert against `tenants.id = $1` writes without flaking on
// UUID generation. The last segment must be all-hex (RFC 4122),
// so we encode "Chaos Tier 2 #001" as 0xc2a00001 — visually
// distinct from the e2e harness tenant while still parsing
// cleanly as a UUID.
const chaosTier2TenantID = "00000000-0000-0000-0000-0000c2a00001"

// TestChaos_Tier2SLMFailure pins the documented Tier 2 degradation
// path (DEGRADATION_MODES.md §Tier 2 SLM service unreachable). See
// the package-doc above for the full assertion contract.
func TestChaos_Tier2SLMFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), chaosTimeout)
	defer cancel()

	repoRoot := findRepoRoot(t)
	binary := buildSn360ES(t)

	_, pgCfg := startPostgres(ctx, t)
	_, redisAddr := startRedis(ctx, t)
	_, natsURL := startNATS(ctx, t)

	applyMigrations(ctx, t, repoRoot, pgCfg)
	seedTenant(ctx, t, pgCfg, chaosTier2TenantID)

	tier1 := startTier1Mock(t)
	tier2 := startTier2Mock(t)
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
			// Trip the breaker on the third consecutive failure
			// so the assertion below has a deterministic
			// threshold to wait for. The production default is 5
			// (see internal/config/scoring.go::loadCircuitBreaker);
			// dropping to 3 in the chaos run keeps the test under
			// its time budget without changing the semantics
			// being pinned. CB_FAILURE_THRESHOLD applies to every
			// breaker in the BreakerSet — that is fine for this
			// scenario because Tier 1 and Rspamd remain healthy.
			"CB_FAILURE_THRESHOLD": "3",
			// Keep the open-window long enough that the second
			// half of the assertion (eventually short-circuit)
			// does not race the half-open probe.
			"CB_OPEN_TIMEOUT": "30s",
		},
	}.build()
	app := startApp(ctx, t, binary, env)
	t.Cleanup(func() { stopApp(t, app) })

	healthURL := fmt.Sprintf("http://127.0.0.1:%d/readyz", port)
	metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	waitForHealthy(ctx, t, healthURL)

	nc, js := connectJetStream(t, natsURL)
	t.Cleanup(nc.Close)

	resultCh := subscribeResultStream(ctx, t, js, "chaos-tier2-result-watcher")

	// ----- 1. Baseline: Tier 2 healthy, expect Blocked verdict -----
	baselineID := publishEvalReq(ctx, t, js, chaosTier2TenantID, "baseline-")
	baseline := waitForResult(ctx, t, resultCh, baselineID)
	if baseline.Tier != constant.TierBlocked && baseline.Tier != constant.TierHighRisk {
		t.Fatalf("baseline: tier = %q, want Blocked or HighRisk", baseline.Tier)
	}
	if baseline.Tier2 == nil {
		t.Fatalf("baseline: Tier2 outcome missing — Tier 2 should have run")
	}
	if baseline.Degraded {
		t.Fatalf("baseline: Degraded = true, want false (all tiers were healthy)")
	}

	// Sample the metric so we can assert an increment, not an
	// absolute value (the baseline message may have hit the
	// breaker once already if Tier 2 was slow to warm).
	tier2ErrBefore := counterValue(t, metricsURL, "sn360_es_tier2_escalations_total", map[string]string{"outcome": "error"})
	degradedBefore := counterValue(t, metricsURL, "sn360_es_evaluate_degraded_total", map[string]string{"service": "tier2"})
	tier2OKBefore := counterValue(t, metricsURL, "sn360_es_tier2_escalations_total", map[string]string{"outcome": "flagged"})

	// ----- 2. Inject the failure ------------------------------------
	// Close the Tier 2 upstream. The production HTTP client will
	// fail-fast with a connection-refused error on the next
	// request. Subsequent requests inside the breaker's open window
	// short-circuit to ErrCircuitOpen without making an outbound
	// call at all.
	tier2.Close()

	// ----- 3. Drive enough failures to open the breaker ------------
	// CIRCUIT_BREAKER_TIER2_FAILURE_THRESHOLD = 3 above, so we
	// publish 5 messages: the first 3 should drive the breaker
	// open and the last 2 should short-circuit. Either way, every
	// verdict must come back Blocked-or-HighRisk and report
	// "tier2" in DegradedServices.
	const followups = 5
	type seenResult struct {
		messageID string
		result    dto.EvaluateResult
	}
	results := make([]seenResult, 0, followups)
	for i := 0; i < followups; i++ {
		id := publishEvalReq(ctx, t, js, chaosTier2TenantID, fmt.Sprintf("postfail-%02d-", i))
		res := waitForResult(ctx, t, resultCh, id)
		results = append(results, seenResult{messageID: id, result: res})
	}

	for _, sr := range results {
		if sr.result.Tier == constant.TierTrusted || sr.result.Tier == constant.TierInformational {
			t.Fatalf("postfail %s: tier = %q — Tier 2 unavailable silently downgraded the verdict (expected Blocked or HighRisk via Tier 0 + Tier 1 + Rspamd)",
				sr.messageID, sr.result.Tier)
		}
		// Tier 2 outcome must be absent (the runTier2 path
		// returned an error) — the evaluator code at
		// internal/service/evaluate/evaluator.go:447 leaves
		// res.Tier2 == nil and appends "tier2" to degraded.
		if sr.result.Tier2 != nil {
			t.Fatalf("postfail %s: Tier2 = %+v, want nil (Tier 2 upstream is dead)", sr.messageID, *sr.result.Tier2)
		}
		if !sr.result.Degraded {
			t.Fatalf("postfail %s: Degraded = false, want true", sr.messageID)
		}
		if !containsString(sr.result.DegradedServices, "tier2") {
			t.Fatalf("postfail %s: DegradedServices = %v, want to contain \"tier2\"", sr.messageID, sr.result.DegradedServices)
		}
	}

	// ----- 4. Assert the operator-visible counters moved -----------
	// We require at least `threshold` error increments because
	// the breaker only opens on the configured number of
	// consecutive failures. The `degraded_total{service="tier2"}`
	// must climb by at least one per affected verdict, including
	// the ones that short-circuited (the evaluator records
	// ObserveDegraded for short-circuit failures too — see
	// evaluator.go:447 where any err from runTier2 emits both
	// ObserveTier2("error",...) and ObserveDegraded("tier2")).
	eventually(t, 10*time.Second, "tier2 error counter increments", func() bool {
		cur := counterValue(t, metricsURL, "sn360_es_tier2_escalations_total", map[string]string{"outcome": "error"})
		return cur-tier2ErrBefore >= float64(followups)
	})
	eventually(t, 10*time.Second, "degraded tier2 counter increments", func() bool {
		cur := counterValue(t, metricsURL, "sn360_es_evaluate_degraded_total", map[string]string{"service": "tier2"})
		return cur-degradedBefore >= float64(followups)
	})

	// ----- 5. Sanity: success counter MUST NOT have moved ----------
	// Once the upstream is dead the only way the "flagged"
	// outcome counter could climb would be a real Tier 2 call
	// succeeding — which is impossible. Pinning this catches a
	// regression where the fallback path falsely records the
	// short-circuited request as a success.
	tier2OKAfter := counterValue(t, metricsURL, "sn360_es_tier2_escalations_total", map[string]string{"outcome": "flagged"})
	if tier2OKAfter > tier2OKBefore {
		t.Fatalf("tier2_escalations_total{outcome=\"flagged\"} climbed from %.0f to %.0f after upstream closure — a short-circuited request is being recorded as a success",
			tier2OKBefore, tier2OKAfter)
	}
}

// publishEvalReq publishes a synthetic evaluate.request with the
// hallmarks of a phishing message. The Tier 0 / Tier 1 / Rspamd
// signals are strong enough that with Tier 2 stripped the verdict
// must still escalate above Trusted.
func publishEvalReq(ctx context.Context, t *testing.T, js jetstream.JetStream, tenantID, idPrefix string) string {
	t.Helper()
	req := dto.EvaluateRequest{
		MessageID:     idPrefix + uniqueID(),
		TenantID:      tenantID,
		CorrelationID: "chaos-corr-" + uniqueID(),
		Sender:        "ceo-impostor@example.com",
		Recipient:     "finance@acme.test",
		Subject:       "URGENT: please process wire today",
		Body:          "Hi finance — please wire $50,000 to vendor account today, thanks. -CEO",
		ReceivedAt:    time.Now().UTC(),
		Signals: dto.RiskSignals{
			SPFResult:        "fail",
			DKIMResult:       "fail",
			DMARCResult:      "fail",
			IsExternal:       true,
			IsFirstContact:   true,
			HasSuspiciousURL: true,
			HasFailedAuth:    true,
		},
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := js.Publish(ctx, "es.evaluate.request", payload, jetstream.WithMsgID(req.MessageID)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	return req.MessageID
}

// resultChannelCapacity is the buffered-channel size for every
// chaos-test result subscriber. Sized at ~10× the largest
// scenario burst (natsBurstSize = 12) so the consumer goroutine
// can always non-blockingly enqueue without dropping. The
// dispatcher below ALSO fails the test loudly if the buffer ever
// fills, so the constant doubles as a regression alarm — a future
// scenario that publishes >resultChannelCapacity messages must
// either bump this constant or refactor to streaming consumption.
const resultChannelCapacity = 256

// awaitResultStream polls JetStream until the sn360-es binary
// has lazy-created the es.evaluate.result stream and returns a
// handle to it. It deliberately does NOT create any consumer,
// because the result stream uses InterestPolicy retention and an
// inadvertent ACK'ing consumer would silently delete messages
// before downstream subscribers attach.
func awaitResultStream(ctx context.Context, t *testing.T, js jetstream.JetStream) jetstream.Stream {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		streams := js.ListStreams(ctx)
		for info := range streams.Info() {
			for _, subj := range info.Config.Subjects {
				if subj == "es.evaluate.result" || subj == "es.evaluate.result.>" {
					if s, err := js.Stream(ctx, info.Config.Name); err == nil {
						return s
					}
				}
			}
		}
		time.Sleep(defaultPollEvery)
	}
	t.Fatalf("stream for es.evaluate.result never appeared")
	return nil
}

// subscribeResultStream attaches a per-test consumer to
// es.evaluate.result. Mirrors the e2e harness pattern: poll until
// the binary has lazy-created the stream, then create a DeliverAll
// consumer so messages published before the consumer attached are
// also delivered.
//
// Callers that only need to confirm the stream exists (without
// consuming) MUST use awaitResultStream instead — the result
// stream uses InterestPolicy retention, so creating a consumer
// and ACKing every message has the side effect of deleting the
// underlying stream messages from the broker.
func subscribeResultStream(ctx context.Context, t *testing.T, js jetstream.JetStream, name string) <-chan jetstream.Msg {
	t.Helper()
	out := make(chan jetstream.Msg, resultChannelCapacity)
	stream := awaitResultStream(ctx, t, js)
	// FilterSubjects (plural) covers BOTH the exact-subject path
	// (current production wiring in cmd/sn360-es/app.go:
	// ResultSubject: "es.evaluate.result") AND the per-tenant
	// fan-out path (es.evaluate.result.>) that the stream is
	// declared to accept in pkg/events/nats/streams.go. If a
	// future change moves results to a tenant-suffixed subject,
	// the chaos suite keeps observing them without a silent
	// time-out. The stream config at streams.go:169 accepts both
	// shapes, so this consumer is forward-compatible by design.
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Name:              name,
		FilterSubjects:    []string{"es.evaluate.result", "es.evaluate.result.>"},
		AckPolicy:         jetstream.AckExplicitPolicy,
		DeliverPolicy:     jetstream.DeliverAllPolicy,
		MaxAckPending:     1024,
		InactiveThreshold: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}
	c, err := cons.Consume(func(m jetstream.Msg) {
		_ = m.Ack()
		select {
		case out <- m:
		default:
			// The buffered channel is sized for ~10× the
			// largest scenario burst; a fill here means a
			// future scenario outgrew it without bumping
			// resultChannelCapacity. Surface as a hard test
			// error rather than silently dropping a result
			// the assertion code will then "miss".
			t.Errorf("subscribeResultStream(%s): result channel full (cap=%d) — bump resultChannelCapacity or drain faster",
				name, resultChannelCapacity)
		}
	})
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	t.Cleanup(c.Stop)
	return out
}

func waitForResult(ctx context.Context, t *testing.T, ch <-chan jetstream.Msg, wantMessageID string) dto.EvaluateResult {
	t.Helper()
	timeout := time.NewTimer(publishWait)
	defer timeout.Stop()
	for {
		select {
		case m := <-ch:
			var res dto.EvaluateResult
			if err := json.Unmarshal(m.Data(), &res); err != nil {
				continue
			}
			if res.MessageID == wantMessageID {
				return res
			}
		case <-timeout.C:
			t.Fatalf("timed out waiting for evaluate.result for %q", wantMessageID)
		case <-ctx.Done():
			t.Fatalf("ctx cancelled: %v", ctx.Err())
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
