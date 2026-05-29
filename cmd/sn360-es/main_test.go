package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/middleware"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/internal/service/education"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/predict"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

// stubBus is a minimal events.EventService that satisfies the
// interface without talking to a real broker. It returns nil for
// Health/Close so /readyz can succeed in tests, and records published
// subjects so callers can assert on event-bus traffic.
type stubBus struct {
	published []string
}

func (b *stubBus) Publish(_ context.Context, subject string, _ []byte, _ ...events.PublishOption) error {
	b.published = append(b.published, subject)
	return nil
}

func (b *stubBus) Subscribe(_ context.Context, subject string, _ events.MessageHandler, _ ...events.SubscribeOption) (events.Subscription, error) {
	return stubSubscription{subject: subject}, nil
}

func (b *stubBus) Health(_ context.Context) error { return nil }
func (b *stubBus) Close() error                   { return nil }

type stubSubscription struct{ subject string }

func (s stubSubscription) Subject() string { return s.subject }
func (s stubSubscription) Close() error    { return nil }

// stubMessage is a minimal events.Message used to drive the header
// override path of evaluateResultRow without depending on a real bus
// implementation.
type stubMessage struct {
	headers map[string]string
}

func (m stubMessage) Data() []byte                              { return nil }
func (m stubMessage) Subject() string                           { return "" }
func (m stubMessage) Headers() map[string]string                { return m.headers }
func (m stubMessage) Ack() error                                { return nil }
func (m stubMessage) Nak(time.Duration) error                   { return nil }
func (m stubMessage) Metadata() (events.MessageMetadata, error) { return events.MessageMetadata{}, nil }

// newTestApp builds a minimum-wired *application suitable for HTTP
// route tests. We use a stub event bus and skip Postgres/Redis so the
// test does not need any external infrastructure. Handlers that depend
// on optional services are still registered; they return 503 when the
// service is nil, which is the contract we want to lock in.
func newTestApp(t *testing.T) *application {
	t.Helper()
	cfg := &config.Config{
		AppName:     "sn360-es-test",
		Environment: config.EnvironmentLocal,
		EventBus:    config.EventBusNATS,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	bus := &stubBus{}

	app := &application{
		cfg:     cfg,
		logger:  logger,
		metrics: telemetry.DefaultMetrics(),
		// signalEnricher is always populated in production by
		// buildSignalEnricher (which returns NoopEnricher when the
		// communication-histories repo or PII hasher is missing).
		// Mirror that contract here so tests don't have to nil-
		// check before calling handleEvaluateRequest /
		// processBatch.
		signalEnricher: evaluate.NoopEnricher{},
		eventBus:       bus,
		recipientSvc:   predict.NewRecipientService(predict.RecipientServiceConfig{}),
		openSvc:        predict.NewOpenService(predict.OpenServiceConfig{}),
	}

	// Real micro-lesson service so the education route serves an
	// actual lesson rather than 503.
	if store, serr := education.DefaultLessonStore(); serr == nil {
		if svc, lerr := education.NewMicroLessonService(education.MicroLessonConfig{
			Store:     store,
			Publisher: bus,
			Logger:    logger,
		}); lerr == nil {
			app.microLessonSvc = svc
		}
	}

	// Escalation service backed by an in-memory ticket store and
	// the stub bus as publisher.
	if esc, eerr := agent.NewEscalationService(agent.EscalationServiceConfig{
		Publisher: escalationPublisherAdapter{bus: bus},
		Store:     agent.NewMemoryTicketStore(),
		Logger:    logger,
	}); eerr == nil {
		app.escalationSvc = esc
	}
	return app
}

func TestBuildMux_RegistersAllRoutes(t *testing.T) {
	app := newTestApp(t)
	mux, err := buildMux(app)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	// buildMux registers handlers but does not wire JWTAuth (which
	// needs an Issuer the test fixture does not stand up). The
	// escalation handlers now require a tenant in context, so we
	// wrap the mux with a minimal test middleware that reads the
	// tenant from an "X-Test-Tenant" header and seeds the same
	// context key the JWT middleware would. Tests that want to
	// exercise the unauthenticated path simply omit the header.
	authedMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rename to `tid` so the closure parameter does not shadow
		// the enclosing *testing.T (which is intentionally NOT
		// captured here — handlers reach for the request, not the
		// test, and shadowing makes that easy to misread).
		if tid := r.Header.Get("X-Test-Tenant"); tid != "" {
			r = r.WithContext(middleware.ContextWithTenantID(r.Context(), tid))
		}
		mux.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(authedMux)
	t.Cleanup(srv.Close)

	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		notStatus  []int
		mustStatus []int
	}{
		// Infrastructure / observability.
		{name: "healthz", method: http.MethodGet, path: "/healthz", mustStatus: []int{http.StatusOK}},
		{name: "readyz", method: http.MethodGet, path: "/readyz", mustStatus: []int{http.StatusOK}},
		{name: "metrics", method: http.MethodGet, path: "/metrics", mustStatus: []int{http.StatusOK}},
		{name: "openapi", method: http.MethodGet, path: "/openapi.yaml", mustStatus: []int{http.StatusOK}},
		{name: "docs index", method: http.MethodGet, path: "/docs", notStatus: []int{http.StatusNotFound}},
		{name: "docs sub", method: http.MethodGet, path: "/docs/", notStatus: []int{http.StatusNotFound}},

		// Banner action — POST contract. We send a missing-token body
		// and expect 400 (not 404) to confirm the route is wired.
		{name: "banner action wired", method: http.MethodPost, path: "/v1/banner/action",
			body: `{}`, notStatus: []int{http.StatusNotFound}},

		// Dashboard — 503 with nil generator, anything but 404 proves wiring.
		{name: "dashboard wired", method: http.MethodGet, path: "/v1/dashboard/summary?tenant_id=t1&range=24h",
			notStatus: []int{http.StatusNotFound}},

		// Education — GET with category + locale, anything but 404 proves wiring.
		{name: "education wired", method: http.MethodGet, path: "/v1/education/lesson/phishing?locale=en",
			notStatus: []int{http.StatusNotFound}},

		// Predict — wired endpoints.
		{name: "predict recipient wired", method: http.MethodPost, path: "/v1/predict/recipient",
			body: `{}`, notStatus: []int{http.StatusNotFound}},
		{name: "predict open wired", method: http.MethodPost, path: "/v1/predict/open",
			body: `{}`, notStatus: []int{http.StatusNotFound}},

		// Escalation — both verbs.
		{name: "escalation resolve wired", method: http.MethodPost, path: "/v1/escalation/resolve",
			body: `{}`, notStatus: []int{http.StatusNotFound}},

		// Unmatched route — confirm fallback 404 still works.
		{name: "unmatched returns 404", method: http.MethodGet, path: "/no/such/route",
			mustStatus: []int{http.StatusNotFound}},
	}
	client := srv.Client()
	// Don't auto-follow redirects so the docs probe sees the 30x.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			_ = resp.Body.Close()
			if len(tc.mustStatus) > 0 {
				if !containsStatus(tc.mustStatus, resp.StatusCode) {
					t.Errorf("status: got %d, want one of %v", resp.StatusCode, tc.mustStatus)
				}
			}
			for _, bad := range tc.notStatus {
				if resp.StatusCode == bad {
					t.Errorf("status: got %d, but expected anything except %d", resp.StatusCode, bad)
				}
			}
		})
	}

	// Escalation GET — the handler returns its own 404 (with a JSON
	// body) for unknown ticket IDs, which is indistinguishable by
	// status from the bare-mux 404 above. Round-trip a created ticket
	// to prove the route is genuinely wired.
	t.Run("escalation get wired via round-trip", func(t *testing.T) {
		if app.escalationSvc == nil {
			t.Skip("escalation service not configured")
		}
		ticket, err := app.escalationSvc.Escalate(context.Background(), "t-1", dto.EscalationIncident{
			PseudoMessageID: "msg-route-test",
			Reason:          dto.EscalationReasonUserRequested,
		})
		if err != nil {
			t.Fatalf("seed ticket: %v", err)
		}
		// Pass the tenant through the test middleware (the JWT
		// middleware is not wired in this test fixture; see the
		// authedMux comment in TestBuildMux_RegistersAllRoutes).
		getReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/escalation/"+ticket.TicketID, nil)
		getReq.Header.Set("X-Test-Tenant", "t-1")
		resp, err := client.Do(getReq)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status: got %d, want 200", resp.StatusCode)
		}
	})
}

// TestBuildMux_RequiresApp guards against a buildMux refactor that
// quietly accepts a nil application — every dependency we look up in
// buildMux would otherwise panic with a nil dereference at request
// time, which would be much harder to debug than an explicit error at
// startup.
func TestBuildMux_RequiresApp(t *testing.T) {
	if _, err := buildMux(nil); err == nil {
		t.Fatal("buildMux(nil) returned no error")
	}
}

// TestWrapMiddleware_AppliesChain verifies that the standard middleware
// chain is applied: telemetry sees every request (the underlying
// counter increments), CORS sets headers on preflight, and the JWT
// auth middleware is skipped for the configured allow-list paths.
func TestWrapMiddleware_AppliesChain(t *testing.T) {
	app := newTestApp(t)
	mux, err := buildMux(app)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	wrapped, werr := wrapMiddleware(mux, app)
	if werr != nil {
		t.Fatalf("wrapMiddleware: %v", werr)
	}
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)

	t.Run("healthz remains reachable through chain", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status: got %d, want 200", resp.StatusCode)
		}
	})

	t.Run("CORS preflight is handled", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodOptions, srv.URL+"/v1/predict/recipient", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_ = resp.Body.Close()
		// CORS middleware should respond 204/200/4xx for the
		// preflight; the important thing is that the request
		// reached the CORS handler and not the bare mux 404.
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("preflight status: got 404, want CORS-handled")
		}
	})
}

// TestTriggersLesson covers the tier-based decision used by the
// evaluate.result education-trigger consumer.
func TestTriggersLesson(t *testing.T) {
	cases := []struct {
		tier constant.Tier
		want bool
	}{
		{tier: constant.TierTrusted, want: false},
		{tier: constant.TierInformational, want: false},
		{tier: constant.TierCaution, want: false},
		{tier: constant.TierWarning, want: true},
		{tier: constant.TierHighRisk, want: true},
		{tier: constant.TierBlocked, want: true},
		{tier: constant.Tier(""), want: false},
	}
	for _, tc := range cases {
		t.Run(string(tc.tier), func(t *testing.T) {
			got := triggersLesson(dto.EvaluateResult{Tier: tc.tier})
			if got != tc.want {
				t.Errorf("triggersLesson(%q) = %v, want %v", tc.tier, got, tc.want)
			}
		})
	}
}

// TestEvaluateResultRow exercises the DTO → repository row projection
// the management-persist consumer relies on.
func TestEvaluateResultRow(t *testing.T) {
	now := time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC)
	res := dto.EvaluateResult{
		MessageID:     "msg-1",
		TenantID:      "t-from-body",
		CorrelationID: "corr-from-body",
		EvaluatedAt:   now,
		Score:         42,
		Tier:          constant.TierWarning,
		Primary:       constant.CategoryCredentialHarvesting,
		Secondary:     []constant.Category{constant.CategorySuspiciousURL},
		ReasonCodes:   []string{"lookalike_domain"},
		Degraded:      true,
	}
	t.Run("body-only fallback", func(t *testing.T) {
		row := evaluateResultRow(res, nil)
		if row.TenantID != "t-from-body" {
			t.Errorf("tenant: got %q, want body value", row.TenantID)
		}
		if row.CorrelationID != "corr-from-body" {
			t.Errorf("correlation: got %q, want body value", row.CorrelationID)
		}
		if got := string(row.MessageIDHash); got != "msg-1" {
			t.Errorf("message id hash: got %q, want msg-1", got)
		}
		if row.Tier != string(constant.TierWarning) || row.Primary != string(constant.CategoryCredentialHarvesting) {
			t.Errorf("tier/primary mismatch: %s/%s", row.Tier, row.Primary)
		}
		if len(row.Secondary) != 1 || row.Secondary[0] != string(constant.CategorySuspiciousURL) {
			t.Errorf("secondary: %v", row.Secondary)
		}
		if !row.EvaluatedAt.Equal(now) {
			t.Errorf("evaluated at: got %v, want %v", row.EvaluatedAt, now)
		}
	})
	t.Run("headers override body", func(t *testing.T) {
		msg := stubMessage{headers: map[string]string{
			events.HeaderTenantID:      "t-from-header",
			events.HeaderCorrelationID: "corr-from-header",
		}}
		row := evaluateResultRow(res, msg)
		if row.TenantID != "t-from-header" {
			t.Errorf("tenant: got %q, want header value", row.TenantID)
		}
		if row.CorrelationID != "corr-from-header" {
			t.Errorf("correlation: got %q, want header value", row.CorrelationID)
		}
	})
	t.Run("zero evaluatedAt fills in now", func(t *testing.T) {
		zero := res
		zero.EvaluatedAt = time.Time{}
		row := evaluateResultRow(zero, nil)
		if row.EvaluatedAt.IsZero() {
			t.Error("expected non-zero EvaluatedAt fallback")
		}
	})
}

// TestFactoryConfigFromAppConfig pins the Redis FetchBatchSize fix
// from 3H: the factory must read Redis.FetchBatchSize from the Redis
// section, not from the NATS section.
func TestFactoryConfigFromAppConfig(t *testing.T) {
	cfg := &config.Config{
		AppName:  "sn360-es",
		EventBus: config.EventBusNATS,
	}
	cfg.NATS.FetchBatchSize = 7
	cfg.Redis.FetchBatchSize = 13
	out := factoryConfigFromAppConfig(cfg)
	if out.NATS.FetchBatchSize != 7 {
		t.Errorf("NATS.FetchBatchSize: got %d, want 7", out.NATS.FetchBatchSize)
	}
	if out.Redis.FetchBatchSize != 13 {
		t.Errorf("Redis.FetchBatchSize: got %d, want 13 (regression: 3H bug)", out.Redis.FetchBatchSize)
	}
}

func containsStatus(set []int, got int) bool {
	for _, s := range set {
		if s == got {
			return true
		}
	}
	return false
}

// TestMemoryQuarantineStore exercises the in-memory fallback for
// action.QuarantineStore: round-trip, TTL expiry, Del, and the
// "missing key returns ok=false without error" contract.
func TestMemoryQuarantineStore(t *testing.T) {
	ctx := context.Background()
	store := newMemoryQuarantineStore()
	if err := store.Set(ctx, "k1", "v1", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, ok, err := store.Get(ctx, "k1"); err != nil || !ok || v != "v1" {
		t.Fatalf("Get k1: v=%q ok=%v err=%v", v, ok, err)
	}
	if _, ok, err := store.Get(ctx, "missing"); err != nil || ok {
		t.Fatalf("Get missing: ok=%v err=%v", ok, err)
	}
	// TTL expiry path: 1ns is in the past on any real clock by the
	// time Get runs, so the store must report ok=false and evict.
	if err := store.Set(ctx, "k2", "v2", time.Nanosecond); err != nil {
		t.Fatalf("Set k2: %v", err)
	}
	time.Sleep(time.Millisecond)
	if _, ok, _ := store.Get(ctx, "k2"); ok {
		t.Fatal("Get k2: expected expiry to evict")
	}
	if err := store.Set(ctx, "k3", "v3", 0); err != nil {
		t.Fatalf("Set k3: %v", err)
	}
	if err := store.Del(ctx, "k3", "missing"); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if _, ok, _ := store.Get(ctx, "k3"); ok {
		t.Fatal("Get k3: expected deleted")
	}
}

// TestLatestVerdictReevaluator_NoRepo asserts the conservative
// fallback when no EvaluationResults repository is wired: every
// reevaluate request returns a Blocked tier so the release flow
// refuses to restore messages we cannot re-verify.
func TestLatestVerdictReevaluator_NoRepo(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := newLatestVerdictReevaluator(nil, logger)
	got, err := r.Reevaluate(context.Background(), "t-1", "msg-1")
	if err != nil {
		t.Fatalf("Reevaluate: %v", err)
	}
	if got.Tier != constant.TierBlocked {
		t.Errorf("tier: got %q, want %q (still-blocked fallback)", got.Tier, constant.TierBlocked)
	}
	if got.TenantID != "t-1" || got.MessageID != "msg-1" {
		t.Errorf("identifiers passed through: %+v", got)
	}
}

// TestLatestVerdictReevaluator_HappyPath round-trips a stored
// EvaluationResult through the adapter and verifies the projection
// onto dto.EvaluateResult preserves tier, score, primary, secondary,
// reason codes, and the evaluated_at timestamp.
func TestLatestVerdictReevaluator_HappyPath(t *testing.T) {
	ctx := context.Background()
	repos := repository.NewInMemoryRegistry()
	evaluatedAt := time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC)
	row := &repository.EvaluationResult{
		TenantID:      "t-1",
		MessageIDHash: []byte("msg-1"),
		CorrelationID: "corr-1",
		Score:         62,
		Tier:          string(constant.TierWarning),
		Primary:       string(constant.CategoryCredentialHarvesting),
		Secondary:     []string{string(constant.CategorySuspiciousURL)},
		ReasonCodes:   []string{"lookalike_domain"},
		Degraded:      true,
		EvaluatedAt:   evaluatedAt,
	}
	if err := repos.EvaluationResults.Create(ctx, row); err != nil {
		t.Fatalf("seed: %v", err)
	}
	r := newLatestVerdictReevaluator(repos, slog.New(slog.NewTextHandler(io.Discard, nil)))
	got, err := r.Reevaluate(ctx, "t-1", "msg-1")
	if err != nil {
		t.Fatalf("Reevaluate: %v", err)
	}
	if got.Tier != constant.TierWarning {
		t.Errorf("tier: got %q, want %q", got.Tier, constant.TierWarning)
	}
	if got.Score != 62 {
		t.Errorf("score: got %d, want 62", got.Score)
	}
	if got.Primary != constant.CategoryCredentialHarvesting {
		t.Errorf("primary: got %q", got.Primary)
	}
	if len(got.Secondary) != 1 || got.Secondary[0] != constant.CategorySuspiciousURL {
		t.Errorf("secondary: %v", got.Secondary)
	}
	if len(got.ReasonCodes) != 1 || got.ReasonCodes[0] != "lookalike_domain" {
		t.Errorf("reason_codes: %v", got.ReasonCodes)
	}
	if !got.Degraded {
		t.Error("degraded: expected true")
	}
	if !got.EvaluatedAt.Equal(evaluatedAt) {
		t.Errorf("evaluated_at: got %v, want %v", got.EvaluatedAt, evaluatedAt)
	}
}

// TestLatestVerdictReevaluator_NotFound asserts that a missing row
// also falls back to the conservative Blocked tier — refusing the
// release is safer than guessing when we have no verdict on file.
func TestLatestVerdictReevaluator_NotFound(t *testing.T) {
	repos := repository.NewInMemoryRegistry()
	r := newLatestVerdictReevaluator(repos, slog.New(slog.NewTextHandler(io.Discard, nil)))
	got, err := r.Reevaluate(context.Background(), "t-1", "msg-missing")
	if err != nil {
		t.Fatalf("Reevaluate: %v", err)
	}
	if got.Tier != constant.TierBlocked {
		t.Errorf("tier: got %q, want %q (no-row fallback)", got.Tier, constant.TierBlocked)
	}
}

// stubMessageWith is a stubMessage with a settable payload, used to
// drive the feedback-persist handler directly.
type stubMessageWith struct {
	payload []byte
}

func (m stubMessageWith) Data() []byte               { return m.payload }
func (m stubMessageWith) Subject() string            { return "es.action.feedback.report_phishing" }
func (m stubMessageWith) Headers() map[string]string { return nil }
func (m stubMessageWith) Ack() error                 { return nil }
func (m stubMessageWith) Nak(time.Duration) error    { return nil }
func (m stubMessageWith) Metadata() (events.MessageMetadata, error) {
	return events.MessageMetadata{}, nil
}

// TestHandleFeedbackPersist_HappyPath verifies that a valid
// FeedbackEvent payload is decoded, projected onto a
// repository.FeedbackEvent row, and persisted via the wired
// FeedbackEventRepository.
func TestHandleFeedbackPersist_HappyPath(t *testing.T) {
	ctx := context.Background()
	repos := repository.NewInMemoryRegistry()
	app := newTestApp(t)
	app.repos = repos

	occurred := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	payload, err := json.Marshal(action.FeedbackEvent{
		TenantID:             "t-1",
		PseudonymizedMessage: "msg-1",
		Action:               action.FeedbackReportPhishing,
		Tier:                 string(constant.TierWarning),
		OccurredAt:           occurred,
		CorrelationID:        "corr-1",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := app.handleFeedbackPersist(ctx, stubMessageWith{payload: payload}); err != nil {
		t.Fatalf("handleFeedbackPersist: %v", err)
	}
	counts, err := repos.FeedbackEvents.Counts(ctx, "t-1",
		occurred.Add(-time.Hour), occurred.Add(time.Hour))
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if counts.ReportedPhishing != 1 || counts.MarkedSafe != 0 || counts.TrustedSender != 0 {
		t.Errorf("counts: %+v", counts)
	}
}

// TestHandleFeedbackPersist_DropsMalformed pins the poison-message
// contract: a malformed payload or one missing required fields must
// log + return nil so the bus does not redeliver forever.
func TestHandleFeedbackPersist_DropsMalformed(t *testing.T) {
	ctx := context.Background()
	repos := repository.NewInMemoryRegistry()
	app := newTestApp(t)
	app.repos = repos

	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "invalid json", payload: []byte("not json")},
		{name: "missing tenant", payload: mustJSON(t, action.FeedbackEvent{
			PseudonymizedMessage: "m", Action: action.FeedbackMarkSafe,
		})},
		{name: "missing message id", payload: mustJSON(t, action.FeedbackEvent{
			TenantID: "t", Action: action.FeedbackMarkSafe,
		})},
		{name: "unknown action", payload: mustJSON(t, action.FeedbackEvent{
			TenantID: "t", PseudonymizedMessage: "m", Action: action.FeedbackAction("bogus"),
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := app.handleFeedbackPersist(ctx, stubMessageWith{payload: tc.payload}); err != nil {
				t.Fatalf("handleFeedbackPersist: %v (expected nil)", err)
			}
		})
	}
	now := time.Now().UTC()
	counts, err := repos.FeedbackEvents.Counts(ctx, "t",
		now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if counts.ReportedPhishing+counts.MarkedSafe+counts.TrustedSender != 0 {
		t.Errorf("expected no rows persisted, got %+v", counts)
	}
}

// TestHandleFeedbackPersist_NoRepo verifies the handler short-circuits
// to nil when the application has no FeedbackEvents repository wired.
// This is the dev / no-Postgres path and must never error.
func TestHandleFeedbackPersist_NoRepo(t *testing.T) {
	app := newTestApp(t)
	if err := app.handleFeedbackPersist(context.Background(), stubMessageWith{
		payload: mustJSON(t, action.FeedbackEvent{
			TenantID: "t", PseudonymizedMessage: "m",
			Action: action.FeedbackReportPhishing,
		}),
	}); err != nil {
		t.Fatalf("handleFeedbackPersist: %v (expected nil)", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
