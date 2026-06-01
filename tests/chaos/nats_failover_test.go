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

// chaosNATSTenantID encodes "Chaos NATS #001" as hex (`ca7500001`)
// for the last segment. Must be all-hex; see chaosTier2TenantID
// for the encoding rationale.
const chaosNATSTenantID = "00000000-0000-0000-0000-000ca7500001"

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
	// Pin a fixed host port so the NATS container's Stop/Start
	// cycle preserves the host-side connection URL. Without this
	// pin, Docker re-assigns the mapped 4222/tcp host port on
	// every Start and sn360-es is left pointing at a dead URL
	// after restart.
	natsHostPort := freePort(t)
	natsContainer, natsURL := startNATSWithOptions(ctx, t, natsHostPort)

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

	// Wait for the es.evaluate.result stream to be lazy-created by
	// the binary, then attach the test's result-watcher consumer
	// BEFORE publishing the burst. This is structurally important:
	// the result stream uses InterestPolicy retention
	// (pkg/events/nats/streams.go ~L148), which means a message is
	// deleted once all durable consumers with interest have ACK'd
	// it. The production wiring has multiple durable consumers on
	// es.evaluate.result (education-trigger, management-persist,
	// ingestion-action, …) that ACK every result they process. If
	// the test consumer is created only AFTER the broker restart,
	// every pre-stop result has by then been ACK'd by all
	// production consumers and deleted from the stream — so a
	// DeliverAllPolicy post-restart consumer would observe zero
	// messages even when the production code path lost nothing.
	//
	// Creating the consumer pre-publish pins it as a durable
	// interest holder; messages remain in the stream until THIS
	// consumer ACKs them, which happens via the dispatcher in
	// subscribeResultStream as each delivery is forwarded into the
	// buffered channel. The channel is sized at resultChannelCapacity
	// (256) so all natsBurstSize (12) pre-stop deliveries land in
	// the buffer even if the test goroutine is blocked on the
	// broker-stop logic when they arrive.
	awaitResultStream(ctx, t, js)
	resultCh := subscribeResultStream(ctx, t, js, "chaos-nats-result-watcher")

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

	// Open a second JetStream client for the post-restart
	// admin-API calls (ConsumerInfo poll below). The pre-stop nc
	// is reconnecting in the background, but its high-level
	// Consume() subscription continues to drain into resultCh —
	// nats-go MaxReconnects(-1) keeps the subscription alive
	// across the gap and replays ack-pending deliveries.
	nc2, js2 := connectJetStream(t, natsURL)
	t.Cleanup(nc2.Close)

	// ---------- 4. Verify every message produces a result ----------
	// The single pre-publish subscriber continues to drain into
	// resultCh through the broker stop+start; any pre-stop
	// deliveries are buffered in the 256-slot channel and any
	// post-restart deliveries (the ack-pending replay) arrive on
	// the same channel after the reconnect completes.
	seen := make(map[string]struct{}, len(ids))
	// 75 s budget: covers the ack-pending replay plus the slowest
	// path through Tier 0 + Tier 1 + Tier 2 + Rspamd for the
	// final message in the burst.
	waitForAll(ctx, t, resultCh, ids, 75*time.Second, seen)
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
	// Publish a FRESH message (post-restart) and immediately
	// re-publish it with the same Nats-Msg-Id header. The
	// stream's DedupWindow (default 2 min — see
	// pkg/events/nats/streams.go) should return Duplicate=true
	// on the second Publish and SUPPRESS the second processing.
	//
	// We deliberately use a NEW msg ID (not one of the pre-stop
	// IDs) because the JetStream dedup map is held in memory and
	// is reset on broker restart — that is a documented NATS
	// behaviour, see nats-io/nats-server#2257. The PRODUCTION
	// invariant we are pinning is "DedupWindow suppresses
	// re-publishes within a single broker lifetime", and that is
	// what the chaos scenario must regress, not the (untrue)
	// claim that dedup state survives a server restart.
	dupID := "nats-dedup-" + uniqueID()
	req := makeChaosRequest(dupID, chaosNATSTenantID)
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("dedup marshal: %v", err)
	}
	ack1, perr := js2.Publish(ctx, "es.evaluate.request", payload, jetstream.WithMsgID(dupID))
	if perr != nil {
		t.Fatalf("dedup first publish: %v", perr)
	}
	if ack1.Duplicate {
		t.Fatalf("dedup first publish: Duplicate=true — broker considers a fresh ID a duplicate")
	}
	ack2, perr := js2.Publish(ctx, "es.evaluate.request", payload, jetstream.WithMsgID(dupID))
	if perr != nil {
		t.Fatalf("dedup second publish: %v", perr)
	}
	if !ack2.Duplicate {
		t.Fatalf("dedup second publish: Duplicate=false for %q — DedupWindow is not active", dupID)
	}

	// Wait for the FIRST publish of dupID to produce its result
	// (it should — it's a fresh message), then drain for a
	// short additional window and confirm only ONE result lands
	// for dupID. A SECOND result would mean the dedup window
	// failed to suppress the second publish despite the broker
	// returning Duplicate=true.
	//
	// Budget split (was a single 45 s fixed deadline — adopted
	// the two-phase shape so the happy path doesn't always burn
	// the full window):
	//   - 45 s arrival deadline: the first result must traverse
	//     Tier 0 → Tier 1 → Tier 2 → Rspamd and land. Matches
	//     the burst-arrival budget at line ~199.
	//   - 10 s post-arrival drain: any duplicate would be the
	//     immediate downstream effect of the broker NOT having
	//     deduped, which means the consumer would see the second
	//     publish as a fresh message. That second pass would take
	//     roughly the same end-to-end latency as the first (a few
	//     hundred ms in the chaos harness). 10 s is two orders of
	//     magnitude above the per-message latency observed in the
	//     burst phase, so a missed duplicate cannot hide inside it.
	dupSeen := 0
	arrivalDeadline := time.NewTimer(45 * time.Second)
	defer arrivalDeadline.Stop()
arrival:
	for {
		select {
		case msg := <-resultCh:
			var r dto.EvaluateResult
			if err := json.Unmarshal(msg.Data(), &r); err == nil && r.MessageID == dupID {
				dupSeen++
				break arrival
			}
		case <-arrivalDeadline.C:
			break arrival
		}
	}
	if dupSeen == 0 {
		t.Fatalf("dedup: no result observed for %q — the FIRST (non-duplicate) publish never reached the consumer", dupID)
	}
	dupDrain := time.NewTimer(10 * time.Second)
	defer dupDrain.Stop()
draining:
	for {
		select {
		case msg := <-resultCh:
			var r dto.EvaluateResult
			if err := json.Unmarshal(msg.Data(), &r); err == nil && r.MessageID == dupID {
				dupSeen++
				if dupSeen > 1 {
					t.Fatalf("dedup: saw a SECOND result for %q — DedupWindow did not suppress reprocessing", dupID)
				}
			}
		case <-dupDrain.C:
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
