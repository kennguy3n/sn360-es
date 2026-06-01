//go:build chaos
// +build chaos

// Package chaos is the WS-6b chaos engineering regression suite. The
// tests in this directory exercise the four documented degradation
// paths in [`internal/docs/DEGRADATION_MODES.md`] (Tier 2 SLM failure,
// NATS single-node failure, Postgres primary failover, Redis eviction
// storm) against the real sn360-es production binary, with each
// failure injected at the actual upstream dependency (not at the
// call site).
//
// Why a separate build tag.
//
//	The chaos suite is intentionally heavyweight: each scenario
//	spins up Postgres + Redis + NATS + Tier 1 / Tier 2 / Rspamd
//	HTTP mocks + the sn360-es subprocess, then injects a real
//	failure (container Stop, server Close, key-flood, etc.) and
//	asserts the observable recovery behaviour. The whole suite is
//	gated on `-tags=chaos` so it does not run on every PR; instead
//	`make chaos` and the chaos.yml workflow (workflow_dispatch +
//	nightly schedule) drive the regressions.
//
// Determinism contract.
//
//	No scenario uses `time.Sleep` as a "wait for X to happen"
//	primitive. All waits are bounded polls (eventually-style)
//	with a documented upper bound and a clear failure mode if the
//	expected event does not arrive in time. The only `time.Sleep`
//	calls in the suite are between poll iterations (250 ms) where
//	there is no other signal to wait on, plus the documented 5 s
//	dwell time in the NATS scenario which models the in-flight
//	gap between broker stop and broker restart.
package chaos_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/testcontainers/testcontainers-go"
	tcnats "github.com/testcontainers/testcontainers-go/modules/nats"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// Tunables shared across all four scenarios. The values are sized to
// keep the full `make chaos` run under 10 minutes on a CI runner with
// cold testcontainers caches.
const (
	chaosTimeout      = 5 * time.Minute
	readinessTimeout  = 90 * time.Second
	publishWait       = 30 * time.Second
	defaultPollEvery  = 250 * time.Millisecond
	binaryBuildBudget = 90 * time.Second
)

// binary build is shared across scenarios via this sync.Once so a
// single `make chaos` invocation does not pay the cost four times.
var (
	binaryOnce sync.Once
	binaryPath string
	binaryErr  error
)

// buildSn360ES compiles the production binary once per test process.
// It is safe to call concurrently from t.Parallel tests; the first
// caller does the build and every subsequent caller reuses the
// cached path.
func buildSn360ES(t *testing.T) string {
	t.Helper()
	binaryOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), binaryBuildBudget)
		defer cancel()
		root := findRepoRoot(t)
		out := filepath.Join(os.TempDir(), "sn360-es-chaos-"+strconv.FormatInt(time.Now().UnixNano(), 36))
		cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./cmd/sn360-es")
		cmd.Dir = root
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			binaryErr = fmt.Errorf("build sn360-es: %w", err)
			return
		}
		binaryPath = out
	})
	if binaryErr != nil {
		t.Fatalf("%v", binaryErr)
	}
	return binaryPath
}

// findRepoRoot walks upward from the test file's directory until it
// finds the go.mod. Mirrors tests/e2e/smoke_test.go::findRepoRoot so
// the harness stays correct regardless of the test invocation cwd.
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

// skipIfNoDocker mirrors the e2e harness so chaos tests skip cleanly
// when run on a host without Docker (e.g. a contributor running
// `make chaos` outside CI without spinning up Docker first).
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

// -----------------------------------------------------------------
// Container helpers
// -----------------------------------------------------------------

// startPostgres mirrors tests/e2e/smoke_test.go::startPostgres but
// returns the container handle as well so chaos tests that need to
// stop / start the container have access to it.
func startPostgres(ctx context.Context, t *testing.T) (*tcpg.PostgresContainer, postgres.Config) {
	t.Helper()
	c, err := tcpg.Run(ctx, "postgres:16-alpine",
		tcpg.WithDatabase("sn360es"),
		tcpg.WithUsername("sn360es"),
		tcpg.WithPassword("sn360es"),
		tcpg.BasicWaitStrategies(),
	)
	skipIfNoDocker(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	cfg := pgCfgFrom(ctx, t, c)
	return c, cfg
}

func pgCfgFrom(ctx context.Context, t *testing.T, c *tcpg.PostgresContainer) postgres.Config {
	t.Helper()
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

// startRedis spins a real Redis container. Pass extra testcontainers
// options (e.g. testcontainers.WithCmdArgs("--maxmemory", "32mb",
// "--maxmemory-policy", "allkeys-lru")) to configure the eviction
// policy for the eviction-storm scenario; the variadic signature
// keeps a single Docker-skip + lifecycle path (skipIfNoDocker +
// t.Cleanup) for every Redis container the suite stands up.
func startRedis(ctx context.Context, t *testing.T, opts ...testcontainers.ContainerCustomizer) (*tcredis.RedisContainer, string) {
	t.Helper()
	c, err := tcredis.Run(ctx, "redis:7-alpine", opts...)
	skipIfNoDocker(t, err)
	t.Cleanup(func() {
		// stop + terminate (not just terminate) so the
		// container's RDB save does not block the test exit.
		// (Redis containers configured with maxmemory may
		// snapshot on shutdown — the brief Stop drains the
		// RDB write before the unconditional Terminate.)
		grace := 1 * time.Second
		_ = c.Stop(context.Background(), &grace)
		_ = c.Terminate(context.Background())
	})
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("redis host: %v", err)
	}
	port, err := c.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("redis port: %v", err)
	}
	return c, fmt.Sprintf("%s:%s", host, port.Port())
}

// startNATS spins a real NATS container with JetStream + file
// storage. File storage is critical for the NATS-failover scenario
// because the test stops and restarts the container; with the
// default memory storage stream state would not survive the gap.
func startNATS(ctx context.Context, t *testing.T) (*tcnats.NATSContainer, string) {
	t.Helper()
	return startNATSWithOptions(ctx, t, 0)
}

// startNATSWithOptions is the variant used by the NATS chaos
// scenario. When hostPort != 0, the 4222/tcp port is bound to that
// fixed host port via HostConfigModifier so a container Stop/Start
// preserves the host-side URL. The Postgres / Redis chaos tests do
// not need a stable port, so they use the zero-value form which
// lets testcontainers pick an ephemeral port.
func startNATSWithOptions(ctx context.Context, t *testing.T, hostPort int) (*tcnats.NATSContainer, string) {
	t.Helper()
	// Default nats:2.10-alpine command is `-DV -js` which enables
	// JetStream with file storage at `/data`. Container Stop
	// preserves the container filesystem (only Terminate destroys
	// it), so JetStream state survives a stop/start cycle —
	// exactly the property the NATS chaos scenario relies on.
	opts := []testcontainers.ContainerCustomizer{}
	if hostPort > 0 {
		opts = append(opts, testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			// MERGE the 4222/tcp binding into any existing
			// PortBindings rather than replacing the whole
			// map. The testcontainers NATS module today only
			// exposes 4222/tcp, but a future module version
			// may add 8222 (monitoring) or 6222 (clustering);
			// replacing the map would silently drop those.
			// Initialise the map if the module has not set
			// any bindings yet.
			if hc.PortBindings == nil {
				hc.PortBindings = network.PortMap{}
			}
			hc.PortBindings[network.MustParsePort("4222/tcp")] = []network.PortBinding{{
				HostIP:   netip.MustParseAddr("127.0.0.1"),
				HostPort: strconv.Itoa(hostPort),
			}}
		}))
	}
	c, err := tcnats.Run(ctx, "nats:2.10-alpine", opts...)
	skipIfNoDocker(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	url, err := c.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("nats url: %v", err)
	}
	return c, url
}

// applyMigrations runs every migrations/*.up.sql against the live
// Postgres pointed to by cfg. Mirrors tests/e2e/smoke_test.go so
// the chaos tests build identical schema state.
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
// communication_histories FKs resolve. Mirrors the e2e harness.
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
VALUES ($1, $2, $3, 'gws', 'acme.test', 'arn:aws:kms:ap-southeast-1:000000000000:key/chaos')
ON CONFLICT (id) DO NOTHING
`
	if _, err := db.ExecContext(execCtx, ins, tenantID, "chaos-tenant-"+tenantID[:8], "chaos-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
}

// -----------------------------------------------------------------
// HTTP mocks for AI inference endpoints
// -----------------------------------------------------------------

// startTier1Mock returns the same /predict + /health stub the e2e
// harness uses: high-risk verdict, deterministic. The chaos tests
// rely on Tier 1 returning a clear "escalate" signal so they can
// distinguish "Blocked via Tier 0+1+Rspamd" from "Blocked via Tier 2"
// when the latter is unreachable.
func startTier1Mock(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "model": "xlm-roberta-chaos"})
	})
	mux.HandleFunc("/predict", func(w http.ResponseWriter, _ *http.Request) {
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
	return srv
}

// startTier2Mock is the canonical Tier 2 stub: returns a
// likely_phishing verdict. The Tier 2 chaos scenario closes this
// server mid-test to inject the failure; the helper returns the
// underlying server so the scenario can call Close() directly.
func startTier2Mock(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	// The ternary-bonsai provider speaks OpenAI's
	// /v1/chat/completions: a single ChatChoice whose
	// message.content is a JSON `Verdict` document. The mock
	// returns a deterministic "this is phishing" verdict so the
	// chaos test's pre-failure baseline produces a Tier 2 score
	// well above the Blocked threshold.
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		verdict, _ := json.Marshal(map[string]any{
			"score":       95,
			"categories":  []string{"likely_phishing", "credential_phishing"},
			"confidence":  0.95,
			"explanation": "chaos mock: deterministic phishing verdict",
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"index":         0,
					"finish_reason": "stop",
					"message": map[string]string{
						"role":    "assistant",
						"content": string(verdict),
					},
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	// Note: NOT t.Cleanup(srv.Close) — the Tier 2 scenario closes
	// the server manually mid-test, and a double-Close is fine
	// (httptest.Server.Close is idempotent). The scenarios that do
	// not close it should register Cleanup themselves.
	return srv
}

// startRspamdMock returns a high-risk Rspamd verdict so the chaos
// tests can attribute Blocked decisions to Tier 0+1+Rspamd reasoning
// when Tier 2 is unreachable.
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

// -----------------------------------------------------------------
// sn360-es subprocess + env wiring
// -----------------------------------------------------------------

// appEnv assembles the env-var set sn360-es expects for chaos runs.
// Differs from the e2e default in three ways: NATS_STORAGE=file
// (the NATS scenario requires JetStream state to survive container
// Stop/Start), CIRCUIT_BREAKER_TIER2_FAILURE_THRESHOLD=2 so the
// breaker trips quickly under fault injection, and PG_READ_HOST left
// for the caller to set when the Postgres scenario needs a replica
// pool.
type appEnv struct {
	pg           postgres.Config
	readPG       *postgres.Config
	redisAddr    string
	natsURL      string
	tier1URL     string
	tier2URL     string
	rspamdURL    string
	httpPort     int
	extra        map[string]string
	environment  string
	natsStorage  string
	bannerSecret string
}

// build produces a clean env slice for exec.Cmd.Env. We always
// disable the dotenv loader by not exporting any of the file-based
// env-vars; only the values the test sets are propagated.
//
// Override semantics: the base slice is appended FIRST and the
// caller-supplied `extra` map is appended LAST. Per the
// exec.Cmd.Env contract ("if Env contains duplicate environment
// keys, only the last value in the slice for each duplicate key
// is used"), any key the caller sets in `extra` wins over the
// hardcoded default. The Redis durable-store scenario relies on
// this to flip ENVIRONMENT=prod and PG_SSLMODE=require without
// having to fork the helper. Do NOT switch to a map-merge here —
// the explicit list-append is what makes the override path
// auditable from the call site.
func (e appEnv) build() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"APP_NAME=sn360-es-chaos",
		"ENVIRONMENT=" + envOrDefault(e.environment, "local"),
		"LOG_LEVEL=info",
		"LOG_FORMAT=text",
		"HTTP_HOST=127.0.0.1",
		"HTTP_PORT=" + strconv.Itoa(e.httpPort),

		"EVENT_BUS_TYPE=nats",
		"NATS_URL=" + e.natsURL,
		"NATS_STORAGE=" + envOrDefault(e.natsStorage, "file"),
		"NATS_REPLICAS=1",

		"REDIS_ADDR=" + e.redisAddr,

		"PG_HOST=" + e.pg.Host,
		"PG_PORT=" + strconv.Itoa(e.pg.Port),
		"PG_USER=" + e.pg.User,
		"PG_PASSWORD=" + e.pg.Password,
		"PG_DATABASE=" + e.pg.Database,
		"PG_SSLMODE=disable",

		"TIER1_URL=" + e.tier1URL,
		"TIER1_BATCH_ENABLED=false",
		"AI_URL=" + e.tier2URL,
		"RSPAMD_URL=" + e.rspamdURL,

		"TIER0_SKIP_INTERNAL=false",
		"TIER0_SKIP_VENDOR=false",
		"TIER0_SKIP_RECURRING=false",
		"TIER0_HIGH_VOLUME_RSPAMD_ONLY=false",

		"BANNER_TOKEN_SECRET=" + envOrDefault(e.bannerSecret, "chaos-banner-secret-do-not-use-in-prod"),
	}
	if e.readPG != nil {
		env = append(env,
			"PG_READ_HOST="+e.readPG.Host,
			"PG_READ_PORT="+strconv.Itoa(e.readPG.Port),
			"PG_READ_USER="+e.readPG.User,
			"PG_READ_PASSWORD="+e.readPG.Password,
			"PG_READ_DATABASE="+e.readPG.Database,
			"PG_READ_SSLMODE=disable",
		)
	}
	for k, v := range e.extra {
		env = append(env, k+"="+v)
	}
	return env
}

func envOrDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// freePort grabs an ephemeral port for the sn360-es HTTP server.
// We bind 127.0.0.1 (not 0.0.0.0) so the chaos test never opens a
// listener on a routable interface even on developer laptops.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startApp spawns the production binary with the given env. The
// returned cancel cleanly shuts it down — chaos scenarios must call
// it via t.Cleanup so a panicking test does not leak a subprocess.
func startApp(ctx context.Context, t *testing.T, binary string, env []string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, binary)
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

// waitForHealthy polls /readyz until it returns 200 or the
// readinessTimeout elapses. The chaos scenarios use this both to
// verify the initial boot and to verify recovery after a failure
// injection — e.g. the Redis eviction scenario re-attaches Redis
// and waits for /readyz to flip back to 200.
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
		case <-time.After(defaultPollEvery):
		}
	}
	t.Fatalf("sn360-es never became ready: %v", lastErr)
}

// -----------------------------------------------------------------
// JetStream test client
// -----------------------------------------------------------------

func connectJetStream(t *testing.T, natsURL string) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	nc, err := nats.Connect(natsURL,
		nats.Name("chaos-test-driver"),
		nats.Timeout(5*time.Second),
		// MaxReconnects(-1) is what the production code uses; it
		// matters here because the NATS-failover scenario stops
		// the broker and we want the test client to reconnect
		// after restart rather than fail-fast.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(250*time.Millisecond),
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

// -----------------------------------------------------------------
// Prometheus metric scraping
// -----------------------------------------------------------------

// counterValue reads a single counter from the /metrics endpoint
// and returns the float value of the first matching label set. The
// `labels` map is interpreted as a strict subset filter: a sample
// is matched only when every key/value pair in `labels` appears in
// the scraped sample's label set (extra labels on the sample are
// ignored). Returns 0 (not an error) when no matching sample is
// present, so the caller can write monotonic-increment assertions
// that handle the "metric not yet emitted" case naturally.
func counterValue(t *testing.T, metricsURL, name string, labels map[string]string) float64 {
	t.Helper()
	resp, err := http.Get(metricsURL)
	if err != nil {
		t.Fatalf("scrape %s: %v", metricsURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	var total float64
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexAny(line, " \t")
		if idx <= 0 {
			continue
		}
		head := line[:idx]
		valStr := strings.TrimSpace(line[idx:])
		// head: name{label="v",...}  OR  name
		metricName := head
		var labelBlock string
		if open := strings.IndexByte(head, '{'); open >= 0 {
			metricName = head[:open]
			closing := strings.LastIndexByte(head, '}')
			if closing < open {
				continue
			}
			labelBlock = head[open+1 : closing]
		}
		if metricName != name {
			continue
		}
		if !labelsMatch(labelBlock, labels) {
			continue
		}
		f, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			continue
		}
		total += f
	}
	return total
}

// labelsMatch reports whether every (k=v) pair in want appears in
// the Prometheus textual label block. The block format is
// `k1="v1",k2="v2"` — escape sequences are not unescaped because
// the chaos tests only assert against ASCII label values they
// control.
func labelsMatch(block string, want map[string]string) bool {
	if len(want) == 0 {
		return true
	}
	got := make(map[string]string, len(want))
	for _, pair := range splitLabelPairs(block) {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(pair[:eq])
		v := strings.Trim(strings.TrimSpace(pair[eq+1:]), `"`)
		got[k] = v
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// splitLabelPairs splits the inside of a Prometheus label block on
// commas while respecting double-quoted values (which may contain
// commas). We do not handle escaped quotes because the chaos test
// label set is curated and never includes them.
func splitLabelPairs(block string) []string {
	var pairs []string
	var cur strings.Builder
	inQuote := false
	for _, r := range block {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			pairs = append(pairs, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		pairs = append(pairs, cur.String())
	}
	return pairs
}

// eventually polls fn until it returns true or the timeout elapses.
// All chaos scenarios use this in place of time.Sleep so the suite
// stays deterministic on a slow runner — the bound is documented at
// each call site, never opaque.
func eventually(t *testing.T, timeout time.Duration, msg string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(defaultPollEvery)
	}
	t.Fatalf("eventually: %s did not become true within %s", msg, timeout)
}

// -----------------------------------------------------------------
// Small utilities
// -----------------------------------------------------------------

type prefixedWriter struct {
	prefix string
	out    io.Writer
	mu     sync.Mutex
}

func (p *prefixedWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
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

// openPgDB is a small helper used by the Postgres failover scenario
// to issue verification queries directly against a Postgres pool
// (bypassing the sn360-es binary). It returns a *sql.DB the caller
// must Close.
func openPgDB(ctx context.Context, t *testing.T, cfg postgres.Config) *sql.DB {
	t.Helper()
	db, err := postgres.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db.SQL()
}
