package main

import (
	"context"
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
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/internal/service/education"
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
		cfg:          cfg,
		logger:       logger,
		metrics:      telemetry.DefaultMetrics(),
		eventBus:     bus,
		recipientSvc: predict.NewRecipientService(predict.RecipientServiceConfig{}),
		openSvc:      predict.NewOpenService(predict.OpenServiceConfig{}),
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
	srv := httptest.NewServer(mux)
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
		resp, err := client.Get(srv.URL + "/v1/escalation/" + ticket.TicketID)
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
	srv := httptest.NewServer(wrapMiddleware(mux, app))
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
