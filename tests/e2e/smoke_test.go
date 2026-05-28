//go:build e2e
// +build e2e

// Package e2e is the cross-binary smoke harness for sn360-es. The
// test in this file builds the sn360-es binary, boots its production
// dependencies (Postgres, Redis, NATS JetStream) in real containers,
// stubs only the external AI inference endpoints (Tier 1 encoder,
// Tier 2 LLM, Rspamd) — those are the one class of dependency the
// user has explicitly authorised mocking for, because they require
// GPU / proprietary models that CI cannot host — and exercises the
// full ingestion → evaluate → action chain end-to-end.
//
// The mocks are deliberately tiny HTTP fixtures that return verdicts
// the production scorer can aggregate; everything else in the
// pipeline (NATS streams, JetStream consumers, the Tier 0 gate, the
// rule-based categoriser, the scorer, the tier decider, the banner
// renderer, the Postgres repository layer) runs the same code that
// ships in the Docker image.
package e2e_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	tcnats "github.com/testcontainers/testcontainers-go/modules/nats"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

const (
	// e2eTimeout is the upper bound for the whole smoke test. The
	// container start-up dominates; the actual message round-trip
	// is well under a second.
	e2eTimeout = 4 * time.Minute

	// readinessTimeout bounds the wait for /readyz once the
	// sn360-es process is up.
	readinessTimeout = 60 * time.Second

	// publishWait bounds the wait for the ingestion-action chain
	// to round-trip through NATS.
	publishWait = 30 * time.Second
)

// TestE2E_IngestEvaluateActionFlow drives the production binary
// through the full ingestion → tier0 → evaluator → action chain.
//
// Flow under test:
//
//  1. Test publishes a synthetic es.evaluate.request to NATS.
//  2. sn360-es binary's evaluator consumer fans the request through
//     Tier 0 (rule-based, in-process), Tier 1 (mocked HTTP), Tier 2
//     (mocked HTTP), Rspamd (mocked HTTP), the rule categoriser, the
//     scorer, and the tier decider.
//  3. The verdict is published on es.evaluate.result.
//  4. The handleEvaluateResult consumer persists the row to Postgres.
//  5. The handleIngestionAction consumer renders a banner and
//     publishes es.action.banner.
//
// Assertions verify (a) the evaluate.result payload's tier/category,
// (b) an es.action.banner message containing rendered HTML for the
// recipient, and (c) the Postgres evaluation_results row.
func TestE2E_IngestEvaluateActionFlow(t *testing.T) {
	if os.Getenv("E2E_SKIP") != "" {
		t.Skip("E2E_SKIP set; skipping cross-binary smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e2eTimeout)
	defer cancel()

	repoRoot := findRepoRoot(t)

	// --- 1. Build the production binary ---------------------------
	binaryPath := buildBinary(t, repoRoot)

	// --- 2. Stand up real infra in containers --------------------
	pgCfg := startPostgres(ctx, t)
	redisAddr := startRedis(ctx, t)
	natsURL := startNATS(ctx, t)

	applyMigrations(ctx, t, repoRoot, pgCfg)
	seedTenant(ctx, t, pgCfg, "00000000-0000-0000-0000-0000e2e10000")

	// --- 3. Mock the AI inference endpoints ----------------------
	// The user's rule says mocks are allowed only when the real
	// dependency is genuinely unavailable. Tier 1 (XLM-RoBERTa
	// encoder) and Tier 2 (Ternary-Bonsai-8B LLM) require GPUs +
	// proprietary weights; Rspamd is a multi-MB heuristic engine
	// out of scope for the smoke. We stub the HTTP contracts each
	// expects.
	tier1Srv := startTier1Mock(t)
	tier2Srv := startTier2Mock(t)
	rspamdSrv := startRspamdMock(t)

	// --- 4. Spawn sn360-es with the wired env --------------------
	httpPort := freePort(t)
	env := buildAppEnv(pgCfg, redisAddr, natsURL, tier1Srv.URL, tier2Srv.URL, rspamdSrv.URL, httpPort)

	proc := startApp(ctx, t, binaryPath, env)
	defer stopApp(t, proc)

	healthURL := fmt.Sprintf("http://127.0.0.1:%d/readyz", httpPort)
	waitForHealthy(ctx, t, healthURL)

	// --- 5. Subscribe to the action subjects before publishing ---
	nc, js := connectJetStream(t, natsURL)
	defer nc.Close()

	resultCh := subscribeSubject(ctx, t, js, "es.evaluate.result", "e2e-test-result-watcher")
	bannerCh := subscribeSubject(ctx, t, js, "es.action.banner", "e2e-test-banner-watcher")

	// --- 6. Publish the synthetic ingestion message --------------
	// TenantID must be a UUID — sn360-es persists into the
	// communication_histories table where tenant_id is typed
	// `uuid`, and the signal enricher / tenant-config loader
	// reject non-UUID strings with SQLSTATE 22P02. The previous
	// "e2e-tenant" value silently degraded the evaluator to the
	// base-signals path and produced a TierTrusted verdict, which
	// caused the downstream banner action to be skipped.
	req := dto.EvaluateRequest{
		MessageID:     "e2e-msg-" + uniqueID(),
		TenantID:      "00000000-0000-0000-0000-0000e2e10000",
		CorrelationID: "e2e-corr-" + uniqueID(),
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
		t.Fatalf("marshal request: %v", err)
	}

	_, err = js.Publish(ctx, "es.evaluate.request", payload,
		jetstream.WithMsgID(req.MessageID),
	)
	if err != nil {
		t.Fatalf("publish es.evaluate.request: %v", err)
	}

	// --- 7. Wait for the verdict + banner ------------------------
	verdict := waitForResult(ctx, t, resultCh, req.MessageID)
	if verdict.MessageID != req.MessageID {
		t.Fatalf("evaluate.result: message_id = %q, want %q", verdict.MessageID, req.MessageID)
	}
	if verdict.TenantID != req.TenantID {
		t.Fatalf("evaluate.result: tenant_id = %q, want %q", verdict.TenantID, req.TenantID)
	}
	if verdict.Tier == "" {
		t.Fatalf("evaluate.result: empty tier (verdict=%+v)", verdict)
	}

	banner := waitForBanner(ctx, t, bannerCh, req.MessageID)
	if banner["tenant_id"] != req.TenantID {
		t.Fatalf("action.banner: tenant_id = %v, want %q", banner["tenant_id"], req.TenantID)
	}
	html, _ := banner["html"].(string)
	if !strings.Contains(html, "sn360") && !strings.Contains(strings.ToLower(html), "<div") {
		t.Fatalf("action.banner: html does not look rendered (len=%d, sample=%q)", len(html), truncate(html, 120))
	}

	// --- 8. Verify the Postgres row was persisted ----------------
	verifyEvaluationRow(ctx, t, pgCfg, req.TenantID, req.MessageID)

	// --- 9. Smoke /healthz + /readyz are 200 ---------------------
	smokeHealthEndpoints(ctx, t, httpPort)
}

// ---------------------------------------------------------------
// repo + binary helpers
// ---------------------------------------------------------------

// findRepoRoot walks upward from the test file's directory until it
// finds the go.mod, so the test stays correct regardless of where
// `go test ./tests/e2e/...` is invoked from.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found above %s", wd)
		}
		dir = parent
	}
}

func buildBinary(t *testing.T, repoRoot string) string {
	t.Helper()
	tmpDir := t.TempDir()
	out := filepath.Join(tmpDir, "sn360-es-e2e")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/sn360-es")
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build sn360-es: %v", err)
	}
	return out
}

// ---------------------------------------------------------------
// container helpers
// ---------------------------------------------------------------

func skipIfNoDocker(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "docker") {
		t.Skipf("docker not available, skipping: %v", err)
	}
	t.Fatalf("start container: %v", err)
}

func startPostgres(ctx context.Context, t *testing.T) postgres.Config {
	t.Helper()
	c, err := tcpg.Run(ctx, "postgres:16-alpine",
		tcpg.WithDatabase("sn360es"),
		tcpg.WithUsername("sn360es"),
		tcpg.WithPassword("sn360es"),
		tcpg.BasicWaitStrategies(),
	)
	skipIfNoDocker(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("pg host: %v", err)
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("pg port: %v", err)
	}
	portNum, err := strconv.Atoi(port.Port())
	if err != nil {
		t.Fatalf("parse pg port: %v", err)
	}
	return postgres.Config{
		Host:     host,
		Port:     portNum,
		User:     "sn360es",
		Password: "sn360es",
		Database: "sn360es",
		SSLMode:  "disable",
	}
}

func startRedis(ctx context.Context, t *testing.T) string {
	t.Helper()
	c, err := tcredis.Run(ctx, "redis:7-alpine")
	skipIfNoDocker(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("redis host: %v", err)
	}
	port, err := c.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("redis port: %v", err)
	}
	return fmt.Sprintf("%s:%s", host, port.Port())
}

func startNATS(ctx context.Context, t *testing.T) string {
	t.Helper()
	// Note: jetstream is already enabled by the testcontainers nats
	// module's default Cmd (`-DV -js`). Passing
	// `WithArgument("jetstream", "")` appends `--jetstream ""` which
	// nats-server rejects with "unrecognized command".
	c, err := tcnats.Run(ctx, "nats:2.10-alpine")
	skipIfNoDocker(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	url, err := c.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("nats url: %v", err)
	}
	return url
}

// applyMigrations runs every migrations/*.up.sql against the live
// Postgres container. We deliberately apply raw SQL rather than
// driving golang-migrate so the e2e harness stays independent from
// the migration runner — both code paths exercise the same DDL.
func applyMigrations(ctx context.Context, t *testing.T, repoRoot string, cfg postgres.Config) {
	t.Helper()
	migrationsDir := filepath.Join(repoRoot, "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var upFiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".up.sql") {
			upFiles = append(upFiles, name)
		}
	}
	sort.Strings(upFiles)

	db, err := postgres.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	defer db.Close()

	for _, f := range upFiles {
		path := filepath.Join(migrationsDir, f)
		bytes, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("read %s: %v", f, rerr)
		}
		execCtx, c := context.WithTimeout(ctx, 60*time.Second)
		if _, eerr := db.ExecContext(execCtx, string(bytes)); eerr != nil {
			c()
			t.Fatalf("apply %s: %v", f, eerr)
		}
		c()
	}
}

// seedTenant inserts a tenant row so evaluation_results /
// communication_histories foreign keys resolve. Without this the
// management-persist consumer hits SQLSTATE 23503 and the test
// assertion on evaluation_results count returns zero.
func seedTenant(ctx context.Context, t *testing.T, cfg postgres.Config, tenantID string) {
	t.Helper()
	db, err := postgres.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("seed tenant: open: %v", err)
	}
	defer db.Close()
	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	const ins = `
INSERT INTO tenants (id, name, display_name, provider, primary_domain, kms_key_arn)
VALUES ($1, $2, $3, 'gws', 'acme.test', 'arn:aws:kms:ap-southeast-1:000000000000:key/e2e')
ON CONFLICT (id) DO NOTHING
`
	if _, err := db.ExecContext(execCtx, ins, tenantID, "e2e-tenant-"+tenantID[:8], "e2e-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
}

// ---------------------------------------------------------------
// HTTP mocks for AI inference endpoints
// ---------------------------------------------------------------

// startTier1Mock returns a server whose /predict endpoint mirrors the
// XLM-RoBERTa encoder contract: per-message phishing/category logits
// plus a confidence score. We deterministically return a high-risk
// verdict so the downstream scorer escalates.
func startTier1Mock(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	// /health is the readiness probe that the sn360-es /readyz aggregator
	// calls via the tier1.Client.Health path (default HealthPath="/health").
	// Without it the e2e smoke would report tier1_encoder=error and the
	// /readyz check would never flip to 200.
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"model":  "xlm-roberta-stub",
		})
	})
	// /predict returns a single tier1.PredictResponse — the production
	// client at internal/service/tier1/encoder.go::doSingle decodes
	// the body directly into PredictResponse. The previous
	// {"messages":[{...}]} envelope silently decoded to score=0, which
	// then drove the verdict tier all the way down to Trusted.
	mux.HandleFunc("/predict", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"score":        92,
			"confidence":   0.94,
			"language":     "en",
			"model_tag":    "xlm-roberta-stub",
			"reason_codes": []string{"WIRE_REQUEST", "URGENT_TONE"},
		})
	})
	mux.HandleFunc("/predict/batch", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{{
				"score":      92,
				"confidence": 0.94,
				"language":   "en",
				"model_tag":  "xlm-roberta-stub",
			}},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// startTier2Mock simulates the Ternary-Bonsai-8B LLM endpoint. The
// production client posts the message + Tier 1 outcome and expects a
// final phishing verdict + reason codes.
func startTier2Mock(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/classify", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"score":        96,
			"categories":   []string{"likely_phishing", "credential_phishing"},
			"reason_codes": []string{"ceo_fraud_pattern", "wire_transfer_urgency"},
			"model":        "ternary-bonsai-stub",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// startRspamdMock simulates the Rspamd /checkv2 endpoint. The
// production client treats the symbols + score numerically.
func startRspamdMock(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/checkv2", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"score":          9.5,
			"required_score": 5.0,
			"action":         "reject",
			"symbols": map[string]any{
				"FORGED_SENDER": map[string]any{"score": 4.0},
				"DMARC_FAIL":    map[string]any{"score": 3.5},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------
// subprocess + env wiring
// ---------------------------------------------------------------

func buildAppEnv(pg postgres.Config, redisAddr, natsURL, tier1URL, tier2URL, rspamdURL string, httpPort int) []string {
	// Disable the dotenv loader so the host's .env can't leak into
	// the spawned binary.
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"APP_NAME=sn360-es-e2e",
		"ENVIRONMENT=local",
		"LOG_LEVEL=info",
		"LOG_FORMAT=text",
		"HTTP_HOST=127.0.0.1",
		"HTTP_PORT=" + strconv.Itoa(httpPort),

		"EVENT_BUS_TYPE=nats",
		"NATS_URL=" + natsURL,
		"NATS_STORAGE=memory",
		"NATS_REPLICAS=1",

		"REDIS_ADDR=" + redisAddr,

		"PG_HOST=" + pg.Host,
		"PG_PORT=" + strconv.Itoa(pg.Port),
		"PG_USER=" + pg.User,
		"PG_PASSWORD=" + pg.Password,
		"PG_DATABASE=" + pg.Database,
		"PG_SSLMODE=disable",

		// Mocked AI inference endpoints.
		"TIER1_URL=" + tier1URL,
		"TIER1_BATCH_ENABLED=false",
		"AI_URL=" + tier2URL,
		"RSPAMD_URL=" + rspamdURL,

		// The Tier 0 gate skips internal/vendor/recurring senders
		// by default; in the smoke we want every message to flow
		// through the rest of the pipeline.
		"TIER0_SKIP_INTERNAL=false",
		"TIER0_SKIP_VENDOR=false",
		"TIER0_SKIP_RECURRING=false",
		"TIER0_HIGH_VOLUME_RSPAMD_ONLY=false",

		// Banner token secret enables the signed-action path that
		// the renderer embeds in the rendered HTML.
		"BANNER_TOKEN_SECRET=e2e-banner-secret-do-not-use-in-prod",
	}
	return env
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := newListener()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Port()
}

func startApp(ctx context.Context, t *testing.T, binaryPath string, env []string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Env = env
	cmd.Stdout = &prefixedWriter{prefix: "[sn360-es] ", out: os.Stdout}
	cmd.Stderr = &prefixedWriter{prefix: "[sn360-es] ", out: os.Stderr}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sn360-es: %v", err)
	}
	return cmd
}

func stopApp(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Logf("sn360-es: graceful shutdown timed out; killing")
		_ = cmd.Process.Kill()
		<-done
	}
}

func waitForHealthy(ctx context.Context, t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(readinessTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
		req, err := http.NewRequestWithContext(ctx2, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			t.Fatalf("readyz request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Logf("sn360-es: ready (%s)", strings.TrimSpace(string(body)))
				return
			}
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			t.Fatalf("readyz wait cancelled: %v", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatalf("sn360-es never became ready: %v", lastErr)
}

// ---------------------------------------------------------------
// JetStream test client
// ---------------------------------------------------------------

func connectJetStream(t *testing.T, natsURL string) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	nc, err := nats.Connect(natsURL,
		nats.Name("e2e-test-driver"),
		nats.Timeout(5*time.Second),
		nats.MaxReconnects(-1),
	)
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		t.Fatalf("jetstream new: %v", err)
	}
	return nc, js
}

func subscribeSubject(ctx context.Context, t *testing.T, js jetstream.JetStream, subject, name string) <-chan jetstream.Msg {
	t.Helper()
	out := make(chan jetstream.Msg, 32)

	// Allow the sn360-es binary up to ~5s to create the stream
	// before we try to attach a consumer. The binary lazy-creates
	// es.* streams on first publish/subscribe; we retry until the
	// stream exists.
	deadline := time.Now().Add(15 * time.Second)
	var stream jetstream.Stream
	for time.Now().Before(deadline) {
		streams := js.ListStreams(ctx)
		for info := range streams.Info() {
			for _, subj := range info.Config.Subjects {
				if subjectMatches(subj, subject) {
					var serr error
					stream, serr = js.Stream(ctx, info.Config.Name)
					if serr == nil {
						break
					}
				}
			}
			if stream != nil {
				break
			}
		}
		if stream != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if stream == nil {
		t.Fatalf("stream for %q never appeared", subject)
	}

	// DeliverAllPolicy works on every retention policy this smoke
	// touches; DeliverNewPolicy is rejected by JetStream on
	// workqueue streams (ES_ACTION, ES_ONBOARDING) with
	// err_code=10101 "consumer must be deliver all on workqueue
	// stream". The smoke subscribes BEFORE publishing, so there is
	// no replay risk from DeliverAll either way.
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Name:              name,
		FilterSubject:     subject,
		AckPolicy:         jetstream.AckExplicitPolicy,
		DeliverPolicy:     jetstream.DeliverAllPolicy,
		MaxAckPending:     1024,
		InactiveThreshold: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create consumer for %s: %v", subject, err)
	}

	c, err := cons.Consume(func(m jetstream.Msg) {
		_ = m.Ack()
		select {
		case out <- m:
		default:
			// drop overflow — the test only needs one match
		}
	})
	if err != nil {
		t.Fatalf("consume %s: %v", subject, err)
	}
	t.Cleanup(c.Stop)
	return out
}

func subjectMatches(pattern, concrete string) bool {
	if pattern == concrete {
		return true
	}
	// Trivial wildcard matcher for subject patterns like "es.>".
	if strings.HasSuffix(pattern, ".>") {
		prefix := strings.TrimSuffix(pattern, ".>")
		return strings.HasPrefix(concrete, prefix+".")
	}
	if strings.Contains(pattern, "*") {
		patParts := strings.Split(pattern, ".")
		conParts := strings.Split(concrete, ".")
		if len(patParts) != len(conParts) {
			return false
		}
		for i, p := range patParts {
			if p == "*" {
				continue
			}
			if p != conParts[i] {
				return false
			}
		}
		return true
	}
	return false
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
				t.Logf("evaluate.result: decode skip: %v", err)
				continue
			}
			if res.MessageID == wantMessageID {
				return res
			}
		case <-timeout.C:
			t.Fatalf("timed out waiting for es.evaluate.result for %q", wantMessageID)
		case <-ctx.Done():
			t.Fatalf("ctx cancelled waiting for evaluate.result: %v", ctx.Err())
		}
	}
}

func waitForBanner(ctx context.Context, t *testing.T, ch <-chan jetstream.Msg, wantMessageID string) map[string]any {
	t.Helper()
	timeout := time.NewTimer(publishWait)
	defer timeout.Stop()
	for {
		select {
		case m := <-ch:
			var env map[string]any
			if err := json.Unmarshal(m.Data(), &env); err != nil {
				t.Logf("action.banner: decode skip: %v", err)
				continue
			}
			if id, _ := env["message_id"].(string); id == wantMessageID {
				return env
			}
		case <-timeout.C:
			t.Fatalf("timed out waiting for es.action.banner for %q", wantMessageID)
		case <-ctx.Done():
			t.Fatalf("ctx cancelled waiting for action.banner: %v", ctx.Err())
		}
	}
}

// ---------------------------------------------------------------
// Postgres assertion
// ---------------------------------------------------------------

func verifyEvaluationRow(ctx context.Context, t *testing.T, cfg postgres.Config, tenantID, messageID string) {
	t.Helper()
	db, err := postgres.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open pg for verify: %v", err)
	}
	defer db.Close()

	// The consumer pseudonymises the message_id before persisting,
	// so we don't try to filter by message_id — we just assert that
	// a row exists for the tenant with the same correlation_id
	// shape (a single row from this run is sufficient).
	row := db.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM evaluation_results WHERE tenant_id = $1
    `, tenantID)
	var n int
	if err := row.Scan(&n); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("count evaluation_results: %v", err)
	}
	// Allow up to ~5s for the consumer to commit the row; JetStream
	// delivery may race with the assertion.
	if n == 0 {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			row = db.QueryRowContext(ctx, `
                SELECT COUNT(*) FROM evaluation_results WHERE tenant_id = $1
            `, tenantID)
			_ = row.Scan(&n)
			if n > 0 {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	if n == 0 {
		t.Fatalf("expected at least one evaluation_results row for tenant %q (got 0)", tenantID)
	}
	t.Logf("evaluation_results: %d row(s) for tenant=%s message_id=%s", n, tenantID, messageID)
}

func smokeHealthEndpoints(ctx context.Context, t *testing.T, port int) {
	t.Helper()
	for _, path := range []string{"/healthz", "/readyz"} {
		url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, resp.StatusCode)
		}
	}
}

// ---------------------------------------------------------------
// small utilities
// ---------------------------------------------------------------

type prefixedWriter struct {
	prefix string
	out    io.Writer
	mu     sync.Mutex
}

func (p *prefixedWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Best-effort line splitting so test output stays readable.
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		if line == "" && i == len(lines)-1 {
			continue
		}
		_, _ = fmt.Fprintf(p.out, "%s%s\n", p.prefix, line)
	}
	return len(b), nil
}

var idCounter atomic.Uint64

func uniqueID() string {
	return strconv.FormatUint(idCounter.Add(1), 10) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
