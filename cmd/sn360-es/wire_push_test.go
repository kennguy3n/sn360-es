package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/internal/handler"
	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
)

// TestOutlookClientStateForTenant_DeterministicPerSecretAndTenant pins
// the two correctness properties of outlookClientStateForTenant: the
// function is deterministic per (secret, tenantID) so callers on
// either side of the push pipeline can recompute the expected value,
// and different tenants under the same secret resolve to different
// clientStates so a leaked clientState for tenant A cannot be replayed
// against tenant B.
func TestOutlookClientStateForTenant_DeterministicPerSecretAndTenant(t *testing.T) {
	const secret = "deployment-secret-acme"

	fn := outlookClientStateForTenant(secret)

	a := fn("tenant-A")
	if got := fn("tenant-A"); got != a {
		t.Fatalf("not deterministic for same tenant: %q != %q", got, a)
	}
	if b := fn("tenant-B"); a == b {
		t.Fatalf("tenant-A and tenant-B resolved to the same clientState %q; expected per-tenant divergence", a)
	}

	other := outlookClientStateForTenant("other-secret")
	if got := other("tenant-A"); got == a {
		t.Fatalf("different secrets produced the same clientState %q; expected secret-keyed divergence", got)
	}

	if !strings.HasPrefix(a, "sn360-es-") {
		t.Fatalf("clientState %q missing required \"sn360-es-\" prefix", a)
	}
	// Graph's clientState upper bound is 128 chars; we should be
	// well under it.
	if len(a) > 128 {
		t.Fatalf("clientState %q exceeds Graph's 128-char limit", a)
	}
}

// TestOutlookClientStateForTenant_FallsBackWithoutSecret confirms that
// the helper preserves the legacy "sn360-es-<tenantID>" value when no
// secret is configured. Production callers gate on a non-empty secret
// before reaching this path, but the fallback keeps tests / dev wiring
// that construct an OutlookPushReceiver directly with the receiver's
// own default behaviour.
func TestOutlookClientStateForTenant_FallsBackWithoutSecret(t *testing.T) {
	fn := outlookClientStateForTenant("")
	if got := fn("acme"); got != "sn360-es-acme" {
		t.Fatalf("empty-secret fallback = %q, want %q", got, "sn360-es-acme")
	}
}

// TestPushSignatureVerifier_RegistersOutlookKey is the regression test
// for the verifier-key bug: the OutlookPushReceiver.Kind() returns
// "outlook" and the URL path is /v1/push/outlook/{tenant}, so the
// router looks up verifiers["outlook"]. Wiring under any other key
// (e.g. "microsoft") would 400 every legitimate Outlook callback.
func TestPushSignatureVerifier_RegistersOutlookKey(t *testing.T) {
	cfg := &config.Config{
		Ingestion: config.Ingestion{
			PushMicrosoftClientStateSecret: "deployment-secret",
			PushGoogleAudience:             "https://es.example.com/v1/push/gmail",
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	v := buildPushSignatureVerifier(cfg, logger)
	if v == nil {
		t.Fatal("buildPushSignatureVerifier returned nil with both providers configured")
	}
	router, ok := v.(*handler.PushSignatureRouter)
	if !ok {
		t.Fatalf("buildPushSignatureVerifier returned %T, want *PushSignatureRouter", v)
	}
	if _, ok := router.Verifiers["outlook"]; !ok {
		t.Fatalf("router missing outlook verifier; keys=%v", keysOf(router.Verifiers))
	}
	if _, ok := router.Verifiers["microsoft"]; ok {
		t.Fatalf("router registered legacy \"microsoft\" key; only \"outlook\" should be present (keys=%v)", keysOf(router.Verifiers))
	}
}

// TestOutlookPushReceiver_ClientStateRoundTripsThroughVerifier locks
// the lock-step invariant: the value OutlookPushReceiver.Subscribe
// would stamp on a Graph subscription is exactly the value the
// MicrosoftClientStateVerifier built alongside it expects to see on
// the inbound notification. A drift between the two would silently
// reject every legitimate callback in production.
func TestOutlookPushReceiver_ClientStateRoundTripsThroughVerifier(t *testing.T) {
	const (
		secret = "deployment-secret-xyz"
		tenant = "tenant-acme"
	)
	clientStateFn := outlookClientStateForTenant(secret)

	// Stand up a fake Graph endpoint that captures the
	// subscription-create payload so we can read back the
	// clientState the receiver actually stamps.
	var captured struct {
		ClientState string `json:"clientState"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sub-1","expirationDateTime":"2099-01-01T00:00:00Z"}`))
	}))
	t.Cleanup(srv.Close)

	receiver := &ingestion.OutlookPushReceiver{
		BaseURL:              srv.URL,
		TokenSource:          staticTokenSource("test-token"),
		ClientStateForTenant: clientStateFn,
	}

	if _, _, err := receiver.Subscribe(context.Background(), tenant, "https://es.example.com/v1/push/outlook/"+tenant); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	verifier := &handler.MicrosoftClientStateVerifier{ExpectedFor: clientStateFn}
	body := []byte(fmt.Sprintf(`{"value":[{"clientState":%q}]}`, captured.ClientState))
	if err := verifier.VerifyPush(context.Background(), "outlook", tenant, nil, body); err != nil {
		t.Fatalf("verifier rejected the clientState %q the receiver stamped: %v", captured.ClientState, err)
	}

	// Defence-in-depth: the receiver's own HandleNotification must
	// also accept the value that round-tripped through the verifier.
	payload := json.RawMessage(fmt.Sprintf(
		`{"value":[{"subscriptionId":"sub-1","changeType":"created","clientState":%q,"resource":"users/u@example.com/messages/1","resourceData":{"id":"1"}}]}`,
		captured.ClientState))
	_, err := receiver.HandleNotification(context.Background(), tenant, payload)
	// HandleNotification will fail to fetch the message (the fake
	// server doesn't implement /messages), but the failure must NOT
	// be a clientState mismatch — that's the invariant we care
	// about here.
	if err != nil && strings.Contains(err.Error(), "clientState mismatch") {
		t.Fatalf("HandleNotification rejected its own subscribed clientState: %v", err)
	}
}

func keysOf(m map[string]handler.PushSignatureVerifier) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type staticTokenSource string

func (s staticTokenSource) Token(_ context.Context) (string, error) { return string(s), nil }
