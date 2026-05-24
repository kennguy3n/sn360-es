package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

// --- Test doubles --------------------------------------------------------

// pushBus is a stubBus that also records the payload of every Publish
// so the test can assert what arrived on the evaluate.request subject.
// We keep it separate from stubBus (in main_test.go) so changes to the
// generic stub do not silently alter the assertions on this test path.
type pushBus struct {
	mu        sync.Mutex
	published []pushBusEvent
}

type pushBusEvent struct {
	subject string
	data    []byte
	opts    []events.PublishOption
}

func (b *pushBus) Publish(_ context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	dup := make([]byte, len(data))
	copy(dup, data)
	b.published = append(b.published, pushBusEvent{subject: subject, data: dup, opts: opts})
	return nil
}

func (b *pushBus) Subscribe(_ context.Context, subject string, _ events.MessageHandler, _ ...events.SubscribeOption) (events.Subscription, error) {
	return stubSubscription{subject: subject}, nil
}

func (b *pushBus) Health(_ context.Context) error { return nil }
func (b *pushBus) Close() error                   { return nil }

func (b *pushBus) Snapshot() []pushBusEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]pushBusEvent, len(b.published))
	copy(out, b.published)
	return out
}

// fakePushReceiver implements ingestion.PushReceiver for tests. It
// returns a deterministic subscription ID and a stable raw email on
// every HandleNotification call so the assertions are
// timing-independent.
type fakePushReceiver struct {
	kind   string
	tenant string
	body   string
}

func (f *fakePushReceiver) Kind() string { return f.kind }

func (f *fakePushReceiver) Tenants() []string {
	if f.tenant == "" {
		return nil
	}
	return []string{f.tenant}
}

func (f *fakePushReceiver) Subscribe(_ context.Context, _ string, _ string) (string, time.Time, error) {
	return "sub-" + f.kind, time.Now().Add(24 * time.Hour), nil
}

func (f *fakePushReceiver) Renew(_ context.Context, _, _ string, _ string) (time.Time, error) {
	return time.Now().Add(24 * time.Hour), nil
}

func (f *fakePushReceiver) Unsubscribe(_ context.Context, _, _ string) error {
	// The integration test does not assert teardown behaviour
	// (it exercises the live notification path); a no-op
	// keeps PushReceiver satisfied without coupling to it.
	return nil
}

func (f *fakePushReceiver) HandleNotification(_ context.Context, tenantID string, _ json.RawMessage) ([]ingestion.RawEmail, error) {
	return []ingestion.RawEmail{
		{
			ProviderMessageID: "msg-" + f.kind + "-1",
			TenantID:          tenantID,
			Mailbox:           "ops@example.com",
			Sender:            "sender@example.com",
			Recipients:        []string{"ops@example.com"},
			Subject:           "push integration test",
			Body:              f.body,
			ReceivedAt:        time.Now().UTC(),
		},
	}, nil
}

// acceptAllVerifier is a [handler.PushSignatureVerifier] that always
// returns nil. The signature-verification path is exhaustively
// covered by internal/handler/push_webhook_test.go; this integration
// test exercises the post-verification path
// (handler → manager → receiver → normalizer → event bus) end-to-end,
// so we deliberately do not re-test signature verification here.
type acceptAllVerifier struct{}

func (acceptAllVerifier) VerifyPush(_ context.Context, _ string, _ string, _ *http.Request, _ []byte) error {
	return nil
}

// --- Test ----------------------------------------------------------------

// TestPushIngestion_RoutesNotificationsToEventBus boots a wired
// application with INGESTION_MODE=push, mounts /v1/push/{provider}/{tenant}
// via buildMux, and asserts that a notification POSTed to the route
// is normalized and published on the evaluate.request subject.
//
// The test substitutes a fake PushReceiver and an accept-all signature
// verifier so it exercises the wiring contract — route mounted,
// handler decodes path, manager dispatches to receiver, normalizer
// builds an EvaluateRequest, event bus sees the publish — without
// requiring real Google Pub/Sub or Microsoft Graph credentials.
func TestPushIngestion_RoutesNotificationsToEventBus(t *testing.T) {
	bus := &pushBus{}
	cfg := &config.Config{
		AppName:     "sn360-es-test",
		Environment: config.EnvironmentLocal,
		EventBus:    config.EventBusNATS,
		Ingestion: config.Ingestion{
			Mode:                "push",
			PushCallbackBaseURL: "https://es.test.example.com",
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	receiver := &fakePushReceiver{kind: "gmail", tenant: "t-int-1", body: "hello push"}
	mgr, err := ingestion.NewPushManager(ingestion.PushConfig{
		Receivers:       []ingestion.PushReceiver{receiver},
		Publisher:       bus,
		Logger:          logger,
		Normalizer:      ingestion.NewDefaultNormalizer(),
		CallbackBaseURL: cfg.Ingestion.PushCallbackBaseURL,
	})
	if err != nil {
		t.Fatalf("NewPushManager: %v", err)
	}

	app := &application{
		cfg:                   cfg,
		logger:                logger,
		metrics:               telemetry.DefaultMetrics(),
		eventBus:              bus,
		pushManager:           mgr,
		pushSignatureVerifier: acceptAllVerifier{},
	}

	mux, err := buildMux(app)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Gmail Pub/Sub envelope shape: a base64 message payload wrapped
	// in {"message":{"data":"..."}}. The fake receiver ignores the
	// payload and returns a hard-coded raw email, so any well-formed
	// JSON works.
	payload := []byte(`{"message":{"data":"e30=","messageId":"1"}}`)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/v1/push/gmail/"+receiver.tenant,
		strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dummy-oidc-token")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /v1/push/gmail: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("push webhook returned %d: %s", resp.StatusCode, body)
	}

	// The push manager dispatches synchronously from
	// HandleNotification, which the webhook handler invokes inline.
	// The publish therefore lands before ServeHTTP returns, so a
	// poll loop is not required.
	events := bus.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event published, got %d", len(events))
	}
	got := events[0]
	if got.subject != "es.evaluate.request" {
		t.Errorf("subject = %q, want %q", got.subject, "es.evaluate.request")
	}
	var payloadDecoded map[string]any
	if err := json.Unmarshal(got.data, &payloadDecoded); err != nil {
		t.Fatalf("unmarshal event payload: %v", err)
	}
	if tid, _ := payloadDecoded["tenant_id"].(string); tid != receiver.tenant {
		t.Errorf("tenant_id = %q, want %q", tid, receiver.tenant)
	}
	if mid, _ := payloadDecoded["message_id"].(string); mid != "msg-gmail-1" {
		t.Errorf("message_id = %q, want %q", mid, "msg-gmail-1")
	}
}

// TestPushIngestion_RouteNotMountedWhenManagerNil locks in the
// closed-by-default invariant: when the push manager is not wired
// (the default mode "poll"), the /v1/push/ route is absent and any
// POST falls through to the 404 fallback. Together with
// TestPushIngestion_RoutesNotificationsToEventBus this pins the
// wiring contract from both directions.
func TestPushIngestion_RouteNotMountedWhenManagerNil(t *testing.T) {
	app := newTestApp(t)
	app.pushManager = nil
	app.pushSignatureVerifier = nil

	mux, err := buildMux(app)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+"/v1/push/gmail/anything",
		"application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /v1/push/gmail: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 when push manager is nil, got %d", resp.StatusCode)
	}
}
