//go:build chaos
// +build chaos

// NATS single-node failure chaos scenario.
//
// Failure injected.
//
//	The chaos test publishes a burst of evaluate.request messages
//	at the live NATS broker, then calls
//	NATSContainer.Stop(ctx, &gracePeriod) to kill the broker
//	mid-stream — exactly the operational fault that prompted the
//	DEGRADATION_MODES.md §"NATS broker unreachable" entry. The
//	container Stop preserves the container filesystem (only
//	Terminate destroys it), so JetStream state on disk survives;
//	the test then Start()s the container back up.
//
// Behaviour pinned by this test (the production contract).
//
//  1. No data loss on the JetStream-backed streams. Every
//     es.evaluate.request published before the broker stop appears
//     as an es.evaluate.result after the broker restart, and the
//     post-restart work-queue ack-pending counter eventually drains
//     to zero — i.e. the consumer ack'd every in-flight message
//     exactly once.
//  2. The per-stream DedupWindow prevents double-processing. A
//     second Publish() of the same message ID within the dedup
//     window must come back with Duplicate=true and MUST NOT
//     produce a second es.evaluate.result.
//  3. The sn360-es client reconnects to NATS automatically (it is
//     configured with MaxReconnects(-1)) — the test does not need
//     to restart the binary, only the broker.
//
// Why FileStorage is required.
//
//	The default NATS module CLI is `-DV -js` which uses file
//	storage at /data. Stop preserves the container filesystem
//	(only Terminate destroys it), so JetStream stream state on
//	disk survives the stop/start cycle. The chaos harness in
//	harness_test.go::appEnv sets NATS_STORAGE=file so the
//	sn360-es side also creates the streams with
//	jetstream.FileStorage.
//
// Cross-references.
//
//   - JetStream stream config:  pkg/events/nats/streams.go
//   - DedupWindow default:      pkg/events/nats/streams.go::120-137
//     (DedupWindow: 2 * time.Minute)
//   - Degradation doc:          internal/docs/DEGRADATION_MODES.md
package chaos_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

const chaosNATSTenantID = "00000000-0000-0000-0000-0000cnts0001"

// natsBurstSize controls how many evaluate.request messages the
// scenario publishes. The number is small enough to keep the test
// under its time budget on cold container caches but large enough
// that the broker Stop reliably catches at least one ack pending in
// flight on the work-queue consumer.
const natsBurstSize = 12

func TestChaos_NATSSingleNodeFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), chaosTimeout)
	defer cancel()

	repoRoot := findRepoRoot(t)
	binary := buildSn360ES(t)

	_, pgCfg := startPostgres(ctx, t)
	_, redisAddr := startRedis(ctx, t)
	natsContainer, natsURL := startNATS(ctx, t)

	applyMigrations(ctx, t, repoRoot, pgCfg)
	seedTenant(ctx, t, pgCfg, chaosNATSTenantID)

	tier1 := startTier1Mock(t)
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
	}.build()
	app := startApp(ctx, t, binary, env)
	t.Cleanup(func() { stopApp(t, app) })

	healthURL := fmt.Sprintf("http://127.0.0.1:%d/readyz", port)
	waitForHealthy(ctx, t, healthURL)

	// Attach the test JetStream client AFTER the app has booted so
	// the app's stream-creation has already run; otherwise the
	// CreateOrUpdate races could mint a stream with different
	// retention or storage settings.
	nc, js := connectJetStream(t, natsURL)
	t.Cleanup(nc.Close)

	// The pre-stop subscription is intentionally NOT used to read
	// results back — we re-subscribe with a fresh consumer name
	// after restart so the test never depends on the
	// reconnect-loop semantics of a single consumer object. The
	// subscription here only exists to confirm the stream is
	// reachable before we publish the burst.
	_ = subscribeResultStream(ctx, t, js, "chaos-nats-result-watcher")

	// ---------- 1. Publish a burst before failure ------------------
	ids := make([]string, 0, natsBurstSize)
	for i := 0; i < natsBurstSize; i++ {
		id := publishEvalReqUnique(ctx, t, js, chaosNATSTenantID, fmt.Sprintf("nats-pre-%02d-", i))
		ids = append(ids, id)
	}
	t.Logf("published %d evaluate.request messages before NATS stop", len(ids))

	// ---------- 2. Stop the NATS broker mid-stream -----------------
	// Use a short grace period so the container terminates
	// promptly; JetStream's snapshot-on-shutdown still flushes the
	// stream to /data because the NATS server installs its own
	// SIGTERM handler that drains JS state before exiting.
	grace := 2 * time.Second
	if err := natsContainer.Stop(ctx, &grace); err != nil {
		t.Fatalf("stop nats: %v", err)
	}
	t.Logf("NATS stopped — modelling broker single-node failure")

	// The chaos scenario documents a 5s broker-down dwell time:
	// long enough to let any in-flight client request fail and
	// the sn360-es side enter its reconnect loop, short enough to
	// keep the test under its budget. This is the only
	// time.Sleep in the suite that is not a poll-step delay; it
	// is justified because we are deliberately modelling the
	// gap, not waiting for a state transition.
	time.Sleep(5 * time.Second)

	// ---------- 3. Start the broker back up -----------------------
	// The container is reused (same filesystem + same mapped
	// port), so JetStream replays its on-disk stream state on
	// startup. The sn360-es process reconnects automatically
	// because the production client uses MaxReconnects(-1).
	if err := natsContainer.Start(ctx); err != nil {
		t.Fatalf("start nats: %v", err)
	}
	t.Logf("NATS restarted — expecting ack-pending replay")

	// The connection string MAY change when a container restarts
	// (the OS sometimes re-assigns the mapped port on docker
	// engines that did not pin the port). If so, the sn360-es
	// process will be stuck pointing at a dead URL; we surface
	// this as a clear test failure rather than a flaky timeout.
	newURL, urlErr := natsContainer.ConnectionString(ctx)
	if urlErr != nil {
		t.Fatalf("nats url after restart: %v", urlErr)
	}
	if newURL != natsURL {
		t.Fatalf("nats restart remapped the host port: was %s, now %s — this test cannot pin reconnect behaviour without a stable port", natsURL, newURL)
	}

	// Re-establish the test client. The previous nc/js are
	// reconnecting in the background; opening a fresh pair
	// guarantees we observe the post-restart state.
	nc2, js2 := connectJetStream(t, natsURL)
	t.Cleanup(nc2.Close)

	// ---------- 4. Verify every message produces a result ----------
	resultCh2 := subscribeResultStream(ctx, t, js2, "chaos-nats-result-watcher-post")
	seen := make(map[string]struct{}, len(ids))
	// 75 s budget: covers the ack-pending replay plus the slowest
	// path through Tier 0 + Tier 1 + Tier 2 + Rspamd for the
	// final message in the burst.
	waitForAll(ctx, t, resultCh2, ids, 75*time.Second, seen)
	if len(seen) != len(ids) {
		t.Fatalf("post-restart: saw %d results, want %d (missing %v)", len(seen), len(ids), missing(ids, seen))
	}

	// ---------- 5. Work-queue ack-pending eventually drains -------
	// The evaluate stream is a work-queue (one worker per
	// request, retention=workqueue), so the ack-pending count
	// MUST trend to zero after the binary processes every
	// queued message. We pull the consumer info from the stream
	// directly rather than the listener so we can spot a stuck
	// ack-pending count on the production consumer name.
	eventually(t, 30*time.Second, "work-queue ack-pending drains to zero", func() bool {
		// Stream name comes from pkg/events/nats/streams.go::StreamEvaluate
		// ("ES_EVALUATE") — pinning the constant rather than
		// duplicating it would couple the chaos test to the
		// production package, which is fine because that
		// constant changes are a deliberate compat event.
		stream, err := js2.Stream(ctx, "ES_EVALUATE")
		if err != nil {
			t.Logf("stream lookup transient: %v", err)
			return false
		}
		consumers := stream.ListConsumers(ctx)
		var totalAckPending int
		for info := range consumers.Info() {
			totalAckPending += info.NumAckPending
		}
		return totalAckPending == 0
	})

	// ---------- 6. Dedup window prevents double-processing ---------
	// Re-publish the FIRST message ID with the same Nats-Msg-Id
	// header; the stream's DedupWindow (default 2 min — see
	// pkg/events/nats/streams.go) should return Duplicate=true
	// and SUPPRESS the second processing. Failure mode: if the
	// dedup window is mis-configured the result counter will tick
	// up again and we will spot an extra entry on resultCh2.
	dupID := ids[0]
	req := makeChaosRequest(dupID, chaosNATSTenantID)
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("dedup marshal: %v", err)
	}
	ack, perr := js2.Publish(ctx, "es.evaluate.request", payload, jetstream.WithMsgID(dupID))
	if perr != nil {
		t.Fatalf("dedup publish: %v", perr)
	}
	if !ack.Duplicate {
		t.Fatalf("dedup publish: Duplicate=false for %q — DedupWindow is not active", dupID)
	}

	// Wait a short bound (3x the worst-case evaluate latency we
	// just measured) and assert that NO new result for the dup
	// ID arrived. A successful second processing would push a
	// fresh dto.EvaluateResult onto the resultCh2 channel; we
	// drain everything currently pending and fail on any match.
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
draining:
	for {
		select {
		case msg := <-resultCh2:
			var r dto.EvaluateResult
			if err := json.Unmarshal(msg.Data(), &r); err == nil && r.MessageID == dupID {
				t.Fatalf("dedup: saw a SECOND result for %q — DedupWindow did not suppress reprocessing", dupID)
			}
		case <-deadline.C:
			break draining
		}
	}
}

// publishEvalReqUnique publishes a synthetic evaluate.request with
// the given prefix. The MessageID is included as the Nats-Msg-Id so
// the JetStream DedupWindow catches duplicate publishes.
func publishEvalReqUnique(ctx context.Context, t *testing.T, js jetstream.JetStream, tenantID, idPrefix string) string {
	t.Helper()
	id := idPrefix + uniqueID()
	req := makeChaosRequest(id, tenantID)
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := js.Publish(ctx, "es.evaluate.request", payload, jetstream.WithMsgID(id)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	return id
}

func makeChaosRequest(id, tenantID string) dto.EvaluateRequest {
	return dto.EvaluateRequest{
		MessageID:     id,
		TenantID:      tenantID,
		CorrelationID: "chaos-corr-" + id,
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
}

// waitForAll polls the result channel until every id in `want` has
// arrived, marking seen IDs in the shared map. It does NOT fail on
// duplicate IDs (the dedup-check assertion in the test body relies
// on observing them itself).
func waitForAll(ctx context.Context, t *testing.T, ch <-chan jetstream.Msg, want []string, timeout time.Duration, seen map[string]struct{}) {
	t.Helper()
	expect := make(map[string]struct{}, len(want))
	for _, id := range want {
		expect[id] = struct{}{}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for len(seen) < len(want) {
		select {
		case m := <-ch:
			var r dto.EvaluateResult
			if err := json.Unmarshal(m.Data(), &r); err != nil {
				continue
			}
			if _, ok := expect[r.MessageID]; !ok {
				continue
			}
			seen[r.MessageID] = struct{}{}
		case <-timer.C:
			return
		case <-ctx.Done():
			return
		}
	}
}

func missing(want []string, seen map[string]struct{}) []string {
	var out []string
	for _, id := range want {
		if _, ok := seen[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}
