package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	mu          sync.Mutex
	subscribe   []subscribeCall
	unsubscribe []unsubscribeCall
	// unsubscribeErr, when non-nil, is returned by every
	// Unsubscribe call. Lets tests prove Close keeps going
	// after a per-subscription teardown failure.
	unsubscribeErr error
}

type subscribeCall struct {
	TenantID    string
	CallbackURL string
}

type unsubscribeCall struct {
	TenantID       string
	SubscriptionID string
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

func (r *recordingReceiver) Unsubscribe(_ context.Context, tenantID, subscriptionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unsubscribe = append(r.unsubscribe, unsubscribeCall{TenantID: tenantID, SubscriptionID: subscriptionID})
	return r.unsubscribeErr
}

func (r *recordingReceiver) unsubscribeCalls() []unsubscribeCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]unsubscribeCall, len(r.unsubscribe))
	copy(out, r.unsubscribe)
	return out
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

// TestClose_UnsubscribesAllTrackedSubscriptions pins the graceful-
// shutdown contract: every (provider, tenant) pair the manager has
// Subscribed must receive a matching Unsubscribe call when Close
// runs, and the internal subs map must be empty afterwards so a
// post-Close re-Subscribe starts from a clean slate.
//
// Without this guarantee, an Outlook subscription opened by
// SetupSubscriptions outlives the process for ~48h and the next
// boot creates a second one alongside it — duplicate notification
// delivery for that whole window. The test asserts the call-shape
// (tenantID + subscriptionID) so a future refactor that drops one
// of those args on the way to Unsubscribe is caught here.
func TestClose_UnsubscribesAllTrackedSubscriptions(t *testing.T) {
	gmail := &recordingReceiver{kind: "gmail", tenants: []string{"acme.com"}}
	outlook := &recordingReceiver{kind: "outlook", tenants: []string{"azure-tenant-abc", "azure-tenant-xyz"}}

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
	if got := len(mgr.Subscriptions()); got != 3 {
		t.Fatalf("setup: expected 3 tracked subscriptions; got %d", got)
	}

	if err := mgr.Close(context.Background()); err != nil {
		t.Fatalf("Close: unexpected error: %v", err)
	}

	// Every Subscribe must have a matching Unsubscribe carrying the
	// same (tenantID, subscriptionID) pair.
	wantGmail := []unsubscribeCall{{TenantID: "acme.com", SubscriptionID: "sub-gmail-acme.com"}}
	if got := gmail.unsubscribeCalls(); !equalUnsubscribeCalls(got, wantGmail) {
		t.Errorf("gmail Unsubscribe calls = %+v; want %+v", got, wantGmail)
	}
	wantOutlook := []unsubscribeCall{
		{TenantID: "azure-tenant-abc", SubscriptionID: "sub-outlook-azure-tenant-abc"},
		{TenantID: "azure-tenant-xyz", SubscriptionID: "sub-outlook-azure-tenant-xyz"},
	}
	if got := outlook.unsubscribeCalls(); !equalUnsubscribeCalls(got, wantOutlook) {
		t.Errorf("outlook Unsubscribe calls = %+v; want %+v", got, wantOutlook)
	}

	// Post-Close, the manager's tracked-subs map must be empty so a
	// re-Setup starts from a clean slate. Without this, a re-Setup
	// would skip Subscribe (sees the key still tracked) and the
	// orphaned provider-side subscription would silently win.
	if subs := mgr.Subscriptions(); len(subs) != 0 {
		t.Errorf("post-Close: tracked subscriptions = %+v; want empty", subs)
	}
}

// TestClose_ContinuesPastPerSubscriptionUnsubscribeFailures pins the
// best-effort teardown contract: if one provider's Unsubscribe
// errors (e.g. a Graph 500 during shutdown), Close must continue
// tearing down every other tracked subscription rather than
// short-circuiting. The aggregate error is returned to the caller
// but the side-effects on the healthy receiver still complete.
//
// Without this, a single transient provider failure during shutdown
// would orphan every subscription opened after it in the iteration
// order — the exact failure mode Close is supposed to prevent.
func TestClose_ContinuesPastPerSubscriptionUnsubscribeFailures(t *testing.T) {
	gmail := &recordingReceiver{
		kind:           "gmail",
		tenants:        []string{"acme.com"},
		unsubscribeErr: errors.New("simulated stop watch 500"),
	}
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

	if err := mgr.Close(context.Background()); err == nil {
		t.Fatalf("Close: expected aggregate error from failing gmail unsubscribe, got nil")
	}
	// The failing receiver still received the call (the error
	// surfaces from inside Unsubscribe, not from a skipped call).
	if got := len(gmail.unsubscribeCalls()); got != 1 {
		t.Errorf("gmail Unsubscribe calls = %d; want 1 (even on error)", got)
	}
	// The healthy receiver MUST also receive its call — proves
	// Close did not short-circuit on the first failure.
	if got := len(outlook.unsubscribeCalls()); got != 1 {
		t.Errorf("outlook Unsubscribe calls = %d; want 1 (Close must continue past gmail's failure)", got)
	}
}

// equalUnsubscribeCalls is a stable comparison helper: unsubscribeCalls
// preserves Subscribe iteration order (which is deterministic for
// recordingReceiver's slice-backed Tenants), so equality is just a
// per-index field check.
func equalUnsubscribeCalls(got, want []unsubscribeCall) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// flakeyReceiver is a Subscribe implementation that fails the first
// N calls and succeeds afterwards. It models a transient provider
// outage (e.g. a Microsoft Graph 503 during initial subscription
// boot) so we can prove the reconciliation loop retries failed
// (provider, tenant) pairs on subsequent passes without requiring
// a process restart.
type flakeyReceiver struct {
	kind    string
	tenants []string

	mu              sync.Mutex
	failuresRemain  int
	subscribeCalls  int
	successfulCalls []subscribeCall
}

func (f *flakeyReceiver) Kind() string      { return f.kind }
func (f *flakeyReceiver) Tenants() []string { return f.tenants }

func (f *flakeyReceiver) Subscribe(_ context.Context, tenantID string, callbackURL string) (string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subscribeCalls++
	if f.failuresRemain > 0 {
		f.failuresRemain--
		return "", time.Time{}, errors.New("simulated transient subscribe failure")
	}
	f.successfulCalls = append(f.successfulCalls, subscribeCall{TenantID: tenantID, CallbackURL: callbackURL})
	return "sub-" + f.kind + "-" + tenantID, time.Now().Add(24 * time.Hour), nil
}

func (f *flakeyReceiver) Unsubscribe(_ context.Context, _, _ string) error { return nil }

func (f *flakeyReceiver) Renew(_ context.Context, _, _ string, _ string) (time.Time, error) {
	return time.Now().Add(24 * time.Hour), nil
}

func (f *flakeyReceiver) HandleNotification(_ context.Context, _ string, _ json.RawMessage) ([]RawEmail, error) {
	return nil, nil
}

// TestReconcile_ResubscribesFailedTenantsOnNextTick is the
// regression for the subscription-retry gap: if SetupSubscriptions
// fails for a tenant on first boot, the next reconcile tick MUST
// attempt Subscribe again. Without this, a transient provider
// outage at boot would leave the tenant permanently unsubscribed
// until the pod restarted — a failure mode invisible from outside.
func TestReconcile_ResubscribesFailedTenantsOnNextTick(t *testing.T) {
	flakey := &flakeyReceiver{
		kind:           "outlook",
		tenants:        []string{"azure-tenant-abc"},
		failuresRemain: 1, // fail once, succeed on retry
	}

	mgr, err := NewPushManager(PushConfig{
		Receivers:       []PushReceiver{flakey},
		Publisher:       &capturingBus{},
		Logger:          discardLogger(),
		CallbackBaseURL: "https://es.example.com",
	})
	if err != nil {
		t.Fatalf("NewPushManager: %v", err)
	}

	// First pass: SetupSubscriptions returns the aggregated error
	// because the only tenant's Subscribe failed. m.subs MUST NOT
	// contain an entry — that's the invariant the reconciliation
	// pattern relies on to know "this tenant still needs a
	// Subscribe call".
	if err := mgr.SetupSubscriptions(context.Background()); err == nil {
		t.Fatal("SetupSubscriptions should have returned an error on the first call")
	}
	if got := mgr.Subscriptions(); len(got) != 0 {
		t.Fatalf("after failed Subscribe, m.subs should be empty; got %+v", got)
	}

	// Second reconciliation pass — same code path RenewLoop calls
	// every minute. Now Subscribe succeeds, so the tenant gets
	// registered without operator intervention.
	if err := mgr.SetupSubscriptions(context.Background()); err != nil {
		t.Fatalf("SetupSubscriptions retry: %v", err)
	}
	subs := mgr.Subscriptions()
	if len(subs) != 1 || subs[0].TenantID != "azure-tenant-abc" {
		t.Fatalf("after retry, expected one subscription for tenant azure-tenant-abc; got %+v", subs)
	}
	if flakey.subscribeCalls != 2 {
		t.Fatalf("expected 2 Subscribe attempts (1 failure + 1 success); got %d", flakey.subscribeCalls)
	}

	// Third pass MUST be a no-op for an already-subscribed,
	// not-yet-expiring tenant. Otherwise reconciliation would
	// re-Subscribe on every tick, blowing through provider quotas
	// and creating duplicate Graph subscriptions.
	if err := mgr.SetupSubscriptions(context.Background()); err != nil {
		t.Fatalf("SetupSubscriptions idempotent pass: %v", err)
	}
	if flakey.subscribeCalls != 2 {
		t.Fatalf("idempotent reconcile pass made extra Subscribe calls; total=%d, want 2", flakey.subscribeCalls)
	}
}

// slowSubscribeReceiver blocks inside Subscribe on a shared channel
// so a test can hold one reconcile pass mid-Subscribe while a second
// reconcile call observes the manager state. Used to prove the
// single-flight reconcile invariant: only one Subscribe per
// (provider, tenant) pair across concurrent reconcile callers.
type slowSubscribeReceiver struct {
	kind    string
	tenants []string

	// gate is read inside Subscribe; the test sends on it when it
	// wants Subscribe to return. Each Subscribe call consumes one
	// value, so the test controls per-call timing.
	gate chan struct{}

	mu             sync.Mutex
	subscribeCalls int
}

func (s *slowSubscribeReceiver) Kind() string      { return s.kind }
func (s *slowSubscribeReceiver) Tenants() []string { return s.tenants }

func (s *slowSubscribeReceiver) Subscribe(ctx context.Context, tenantID string, _ string) (string, time.Time, error) {
	s.mu.Lock()
	s.subscribeCalls++
	n := s.subscribeCalls
	s.mu.Unlock()

	// Block until the test releases this Subscribe call (or the
	// context cancels).
	select {
	case <-s.gate:
	case <-ctx.Done():
		return "", time.Time{}, ctx.Err()
	}
	return fmt.Sprintf("sub-%s-%s-%d", s.kind, tenantID, n), time.Now().Add(24 * time.Hour), nil
}

func (s *slowSubscribeReceiver) Unsubscribe(_ context.Context, _, _ string) error { return nil }

func (s *slowSubscribeReceiver) Renew(_ context.Context, _, _ string, _ string) (time.Time, error) {
	return time.Now().Add(24 * time.Hour), nil
}

func (s *slowSubscribeReceiver) HandleNotification(_ context.Context, _ string, _ json.RawMessage) ([]RawEmail, error) {
	return nil, nil
}

func (s *slowSubscribeReceiver) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subscribeCalls
}

// TestReconcile_SingleFlightUnderConcurrentCallers proves that two
// concurrent reconcile callers (e.g. SetupSubscriptions still
// running while RenewLoop's 60s ticker fires) do NOT both
// Subscribe the same (provider, tenant) pair. Without the
// reconcileMu in PushManager, both passes would see an empty m.subs
// for the key, both call Subscribe, and the provider would issue
// two subscriptions — only one of which the manager tracks. The
// orphan would silently double-publish notifications until natural
// expiry.
func TestReconcile_SingleFlightUnderConcurrentCallers(t *testing.T) {
	slow := &slowSubscribeReceiver{
		kind:    "outlook",
		tenants: []string{"azure-tenant-abc"},
		gate:    make(chan struct{}, 8),
	}

	mgr, err := NewPushManager(PushConfig{
		Receivers:       []PushReceiver{slow},
		Publisher:       &capturingBus{},
		Logger:          discardLogger(),
		CallbackBaseURL: "https://es.example.com",
	})
	if err != nil {
		t.Fatalf("NewPushManager: %v", err)
	}

	// Launch two concurrent reconcile passes. The first to enter
	// reconcileMu wins, blocks inside slow.Subscribe; the second
	// must wait on reconcileMu until the first completes. After
	// the first finishes its single Subscribe, the second will
	// see m.subs already populated for the key and skip Subscribe
	// entirely.
	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			errCh <- mgr.SetupSubscriptions(context.Background())
		}()
	}

	// Release exactly two Subscribe calls' worth of gates so that
	// IF both reconciles slipped past the mutex (the bug), both
	// could complete instead of deadlocking. With the fix only
	// the first reconcile reaches Subscribe; the second never
	// calls Subscribe at all, so the second gate value is unused
	// (the buffered channel absorbs it without panicking).
	slow.gate <- struct{}{}
	slow.gate <- struct{}{}

	// Allow both goroutines to finish.
	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("reconcile callers did not finish within 5s; reconcileMu may be deadlocked")
	}
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Errorf("concurrent reconcile returned error: %v", err)
		}
	}

	if got := slow.calls(); got != 1 {
		t.Fatalf("concurrent reconcile callers issued %d Subscribe calls; want exactly 1 (single-flight)", got)
	}
	if subs := mgr.Subscriptions(); len(subs) != 1 {
		t.Fatalf("expected exactly 1 tracked subscription; got %d (%+v)", len(subs), subs)
	}
}

// renewTrackingReceiver counts Renew invocations so we can assert
// that reconcile renews subscriptions whose ExpiresAt has slipped
// inside the renewal buffer window.
type renewTrackingReceiver struct {
	kind    string
	tenants []string

	mu          sync.Mutex
	subscribed  bool
	renewCalls  int
	newExpiry   time.Time
	subscribeAt time.Time
}

func (r *renewTrackingReceiver) Kind() string      { return r.kind }
func (r *renewTrackingReceiver) Tenants() []string { return r.tenants }

func (r *renewTrackingReceiver) Subscribe(_ context.Context, tenantID string, _ string) (string, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subscribed = true
	r.subscribeAt = time.Now()
	// Return an ExpiresAt that's already inside the renewal
	// buffer so the next reconcile tick must renew immediately.
	return "sub-" + r.kind + "-" + tenantID, time.Now().Add(30 * time.Second), nil
}

func (r *renewTrackingReceiver) Unsubscribe(_ context.Context, _, _ string) error { return nil }

func (r *renewTrackingReceiver) Renew(_ context.Context, _, _ string, _ string) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.renewCalls++
	r.newExpiry = time.Now().Add(24 * time.Hour)
	return r.newExpiry, nil
}

func (r *renewTrackingReceiver) HandleNotification(_ context.Context, _ string, _ json.RawMessage) ([]RawEmail, error) {
	return nil, nil
}

// TestReconcile_RenewsSubscriptionsInsideRenewalBuffer is the
// regression for the second half of the reconciliation contract:
// once a tenant is subscribed, subsequent reconcile passes must
// renew the subscription before its ExpiresAt slips past
// RenewalBuffer. Without this, a long-lived deployment would let
// every Graph subscription expire silently and stop receiving
// callbacks.
func TestReconcile_RenewsSubscriptionsInsideRenewalBuffer(t *testing.T) {
	r := &renewTrackingReceiver{kind: "outlook", tenants: []string{"acme-tenant"}}

	mgr, err := NewPushManager(PushConfig{
		Receivers:       []PushReceiver{r},
		Publisher:       &capturingBus{},
		Logger:          discardLogger(),
		CallbackBaseURL: "https://es.example.com",
		// RenewalBuffer of 1h means any ExpiresAt within 1h of
		// now triggers a Renew on the next tick. The receiver
		// returns ExpiresAt at now+30s, so the very next
		// reconcile call must renew.
		RenewalBuffer: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewPushManager: %v", err)
	}

	if err := mgr.SetupSubscriptions(context.Background()); err != nil {
		t.Fatalf("initial SetupSubscriptions: %v", err)
	}
	if !r.subscribed {
		t.Fatal("initial reconcile failed to Subscribe")
	}
	if r.renewCalls != 0 {
		t.Fatalf("initial reconcile should not Renew; got renewCalls=%d", r.renewCalls)
	}

	// Second reconcile pass: ExpiresAt is now+30s which is
	// inside the 1h RenewalBuffer, so Renew must fire.
	if err := mgr.SetupSubscriptions(context.Background()); err != nil {
		t.Fatalf("renewal reconcile: %v", err)
	}
	if r.renewCalls != 1 {
		t.Fatalf("expected exactly 1 Renew call after expiring-soon subscription; got %d", r.renewCalls)
	}

	// Third reconcile pass: Renew refreshed ExpiresAt to now+24h
	// (well past RenewalBuffer), so the next pass must NOT renew
	// again. This proves the renewal trigger is gated on the
	// updated ExpiresAt, not on a per-tick fixed schedule.
	if err := mgr.SetupSubscriptions(context.Background()); err != nil {
		t.Fatalf("post-renewal reconcile: %v", err)
	}
	if r.renewCalls != 1 {
		t.Fatalf("Renew should NOT have fired again after ExpiresAt was refreshed; got renewCalls=%d", r.renewCalls)
	}
}
