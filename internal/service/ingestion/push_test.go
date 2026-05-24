package ingestion

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// recordingReceiver captures Subscribe calls so tests can assert
// exactly which (provider, tenantID, callbackURL) tuples the
// PushManager dispatches.
type recordingReceiver struct {
	kind    string
	tenants []string

	mu        sync.Mutex
	subscribe []subscribeCall
}

type subscribeCall struct {
	TenantID    string
	CallbackURL string
}

func (r *recordingReceiver) Kind() string      { return r.kind }
func (r *recordingReceiver) Tenants() []string { return r.tenants }

func (r *recordingReceiver) Subscribe(_ context.Context, tenantID string, callbackURL string) (string, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subscribe = append(r.subscribe, subscribeCall{TenantID: tenantID, CallbackURL: callbackURL})
	return "sub-" + r.kind + "-" + tenantID, time.Now().Add(24 * time.Hour), nil
}

func (r *recordingReceiver) Renew(_ context.Context, _, _ string, _ string) (time.Time, error) {
	return time.Now().Add(24 * time.Hour), nil
}

func (r *recordingReceiver) HandleNotification(_ context.Context, _ string, _ json.RawMessage) ([]RawEmail, error) {
	return nil, nil
}

// TestSetupSubscriptions_NoCrossProductBetweenProviders pins the
// architectural invariant that BUG_0001 surfaced: PushManager must
// iterate each receiver against ITS OWN Tenants(), not against a
// global tenant list that cross-products across providers.
//
// Without this invariant a Gmail receiver (GWS domain tenants) and an
// Outlook receiver (Azure AD tenant IDs) in the same deployment would
// be subscribed with every combination, producing four subscriptions
// from two providers — invalid callback URLs on the mismatched pairs
// and, on the Outlook side, duplicate Graph subscriptions that
// double-publish every legitimate notification into the event bus.
func TestSetupSubscriptions_NoCrossProductBetweenProviders(t *testing.T) {
	gmail := &recordingReceiver{kind: "gmail", tenants: []string{"acme.com"}}
	outlook := &recordingReceiver{kind: "outlook", tenants: []string{"azure-tenant-abc"}}

	mgr, err := NewPushManager(PushConfig{
		Receivers:       []PushReceiver{gmail, outlook},
		Publisher:       &capturingBus{},
		Logger:          discardLogger(),
		CallbackBaseURL: "https://es.example.com",
	})
	if err != nil {
		t.Fatalf("NewPushManager: %v", err)
	}
	if err := mgr.SetupSubscriptions(context.Background()); err != nil {
		t.Fatalf("SetupSubscriptions: %v", err)
	}

	if len(gmail.subscribe) != 1 || gmail.subscribe[0].TenantID != "acme.com" {
		t.Errorf("gmail Subscribe calls = %+v; want exactly one with tenant=acme.com", gmail.subscribe)
	}
	if len(outlook.subscribe) != 1 || outlook.subscribe[0].TenantID != "azure-tenant-abc" {
		t.Errorf("outlook Subscribe calls = %+v; want exactly one with tenant=azure-tenant-abc", outlook.subscribe)
	}
	// Pin the callback URL shape so a future refactor of the path
	// builder can't reintroduce empty/missing tenant segments.
	wantGmail := "https://es.example.com/v1/push/gmail/acme.com"
	if got := gmail.subscribe[0].CallbackURL; got != wantGmail {
		t.Errorf("gmail callback URL = %q; want %q", got, wantGmail)
	}
	wantOutlook := "https://es.example.com/v1/push/outlook/azure-tenant-abc"
	if got := outlook.subscribe[0].CallbackURL; got != wantOutlook {
		t.Errorf("outlook callback URL = %q; want %q", got, wantOutlook)
	}
}

// TestSetupSubscriptions_SkipsReceiverWithNoTenants pins the
// closed-by-default behaviour: a receiver that exposes an empty
// Tenants() slice MUST NOT trigger any Subscribe calls, because
// "subscribe with empty tenant" would yield an invalid callback URL
// (/v1/push/{provider}/) that the webhook handler rejects.
func TestSetupSubscriptions_SkipsReceiverWithNoTenants(t *testing.T) {
	silent := &recordingReceiver{kind: "outlook", tenants: nil}
	wired := &recordingReceiver{kind: "gmail", tenants: []string{"acme.com"}}

	mgr, err := NewPushManager(PushConfig{
		Receivers:       []PushReceiver{silent, wired},
		Publisher:       &capturingBus{},
		Logger:          discardLogger(),
		CallbackBaseURL: "https://es.example.com",
	})
	if err != nil {
		t.Fatalf("NewPushManager: %v", err)
	}
	if err := mgr.SetupSubscriptions(context.Background()); err != nil {
		t.Fatalf("SetupSubscriptions: %v", err)
	}
	if len(silent.subscribe) != 0 {
		t.Errorf("tenant-less receiver was subscribed: %+v", silent.subscribe)
	}
	if len(wired.subscribe) != 1 {
		t.Errorf("wired receiver should have one subscription; got %+v", wired.subscribe)
	}
}

// TestSetupSubscriptions_SkipsEmptyTenantString defends against
// receivers that leak an empty string into Tenants() — the URL
// builder would otherwise emit /v1/push/{provider}/, which the
// webhook handler rejects with 400 and which Microsoft Graph treats
// as a validation handshake failure.
func TestSetupSubscriptions_SkipsEmptyTenantString(t *testing.T) {
	leaky := &recordingReceiver{kind: "outlook", tenants: []string{""}}

	mgr, err := NewPushManager(PushConfig{
		Receivers:       []PushReceiver{leaky},
		Publisher:       &capturingBus{},
		Logger:          discardLogger(),
		CallbackBaseURL: "https://es.example.com",
	})
	if err != nil {
		t.Fatalf("NewPushManager: %v", err)
	}
	if err := mgr.SetupSubscriptions(context.Background()); err != nil {
		t.Fatalf("SetupSubscriptions: %v", err)
	}
	if len(leaky.subscribe) != 0 {
		t.Errorf("receiver with empty-string tenant was subscribed: %+v", leaky.subscribe)
	}
}
