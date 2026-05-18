package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// ---------------------------------------------------------------------
// Test doubles for the provider-side action consumers.
//
// These fakes implement the minimum surface of the action package's
// provider interfaces so the handlers can be exercised without a real
// Gmail / Outlook API. They also record every call so tests can assert
// the consumer routed correctly.
// ---------------------------------------------------------------------

// fakeLabelProvider is a thread-safe LabelProvider used by the label
// consumer tests. Each call appends an entry to the recorded slice so
// the test can assert the consumer reached the provider.
type fakeLabelProvider struct {
	kind action.LabelProviderKind

	mu        sync.Mutex
	ensure    []fakeEnsureCall
	applies   []fakeApplyCall
	removes   []fakeApplyCall
	ensureErr error
	applyErr  error
}

type fakeEnsureCall struct {
	Email string
	Name  string
	Color action.LabelColor
}

type fakeApplyCall struct {
	Email     string
	MessageID string
	LabelID   string
}

func (f *fakeLabelProvider) Kind() action.LabelProviderKind { return f.kind }

func (f *fakeLabelProvider) EnsureLabel(_ context.Context, email, name string, color action.LabelColor) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ensureErr != nil {
		return "", f.ensureErr
	}
	f.ensure = append(f.ensure, fakeEnsureCall{Email: email, Name: name, Color: color})
	return "label-" + name, nil
}

func (f *fakeLabelProvider) ApplyLabel(_ context.Context, email, messageID, labelID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return f.applyErr
	}
	f.applies = append(f.applies, fakeApplyCall{Email: email, MessageID: messageID, LabelID: labelID})
	return nil
}

func (f *fakeLabelProvider) RemoveLabel(_ context.Context, email, messageID, labelID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removes = append(f.removes, fakeApplyCall{Email: email, MessageID: messageID, LabelID: labelID})
	return nil
}

// fakeBannerInjector records every InjectBanner call.
type fakeBannerInjector struct {
	kind action.LabelProviderKind

	mu       sync.Mutex
	requests []action.BannerInjectRequest
	err      error
}

func (f *fakeBannerInjector) InjectBanner(_ context.Context, req action.BannerInjectRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.requests = append(f.requests, req)
	return nil
}

func (f *fakeBannerInjector) seen() []action.BannerInjectRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]action.BannerInjectRequest, len(f.requests))
	copy(out, f.requests)
	return out
}

// fakeQuarantineProvider implements action.QuarantineProvider.
type fakeQuarantineProvider struct {
	kind action.LabelProviderKind

	mu       sync.Mutex
	ensures  []string
	moves    []fakeMoveCall
	restores []fakeMoveCall
	err      error
}

type fakeMoveCall struct {
	Email     string
	MessageID string
	LabelID   string
	Stub      string
}

func (f *fakeQuarantineProvider) Kind() action.LabelProviderKind { return f.kind }

func (f *fakeQuarantineProvider) EnsureQuarantineLabel(_ context.Context, email string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.ensures = append(f.ensures, email)
	return "qlabel-" + email, nil
}

func (f *fakeQuarantineProvider) MoveToQuarantine(_ context.Context, email, messageID, labelID, stub string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.moves = append(f.moves, fakeMoveCall{Email: email, MessageID: messageID, LabelID: labelID, Stub: stub})
	return nil
}

func (f *fakeQuarantineProvider) RestoreFromQuarantine(_ context.Context, email, messageID, labelID, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restores = append(f.restores, fakeMoveCall{Email: email, MessageID: messageID, LabelID: labelID, Stub: body})
	return nil
}

// fakeQuarantineStore is an in-memory QuarantineStore.
type fakeQuarantineStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newFakeQuarantineStore() *fakeQuarantineStore {
	return &fakeQuarantineStore{values: map[string]string{}}
}

func (s *fakeQuarantineStore) Set(_ context.Context, key, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value
	return nil
}

func (s *fakeQuarantineStore) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	return v, ok, nil
}

func (s *fakeQuarantineStore) Del(_ context.Context, keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		delete(s.values, k)
	}
	return nil
}

// fakeQuarantineEncryptor is a passthrough encryptor — the consumer
// tests don't exercise the cryptographic ladder.
type fakeQuarantineEncryptor struct{}

func (fakeQuarantineEncryptor) Encrypt(_ context.Context, _ string, p []byte) ([]byte, error) {
	return append([]byte("enc:"), p...), nil
}

func (fakeQuarantineEncryptor) Decrypt(_ context.Context, _ string, c []byte) ([]byte, error) {
	if len(c) <= 4 {
		return c, nil
	}
	return c[4:], nil
}

// memoryLabelCacheAdapter satisfies action.LabelCache against a
// goroutine-safe map. Used by the label-applier inside these tests.
type memoryLabelCacheAdapter struct {
	mu   sync.Mutex
	data map[string]string
}

func newMemoryLabelCacheAdapter() *memoryLabelCacheAdapter {
	return &memoryLabelCacheAdapter{data: map[string]string{}}
}

func (c *memoryLabelCacheAdapter) Get(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data[key], nil
}

func (c *memoryLabelCacheAdapter) Set(_ context.Context, key, value string, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
	return nil
}

// ---------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------

// newActionTestApp builds a minimal application with a provider
// registered for tenant "t-1". Each fake exposed via the returned
// struct can be inspected to verify the consumer's behaviour.
type actionTestRig struct {
	app         *application
	gmail       *fakeLabelProvider
	banner      *fakeBannerInjector
	quarantine  *fakeQuarantineProvider
	store       *fakeQuarantineStore
	bus         *recordingBus
	tenant      string
	kind        action.LabelProviderKind
	registryEnt *providerEntry
}

func newActionTestRig(t *testing.T) *actionTestRig {
	t.Helper()
	tenant := "t-1"
	kind := action.LabelProviderGmail
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	lp := &fakeLabelProvider{kind: kind}
	bi := &fakeBannerInjector{kind: kind}
	qp := &fakeQuarantineProvider{kind: kind}
	store := newFakeQuarantineStore()

	reg := newProviderRegistry(logger)
	entry := &providerEntry{
		kind:               kind,
		labelProvider:      lp,
		quarantineProvider: qp,
	}
	reg.entries[providerKey{tenant: tenant, kind: kind}] = entry
	// Custom fallback so the banner consumer routes to the fake
	// when no per-tenant banner injector is configured but the
	// tenant has a provider entry.
	reg.fallbackInjector = bi

	bus := &recordingBus{}
	applier := action.NewLabelApplier(logger, newMemoryLabelCacheAdapter(), lp)
	qsvc, err := action.NewQuarantineService(action.QuarantineConfig{
		Logger:    logger,
		Providers: []action.QuarantineProvider{qp},
		Store:     store,
		Encryptor: fakeQuarantineEncryptor{},
		Publisher: bus,
	})
	if err != nil {
		t.Fatalf("quarantine service: %v", err)
	}

	app := &application{
		logger:        logger,
		eventBus:      bus,
		providers:     reg,
		labelApplier:  applier,
		quarantineSvc: qsvc,
	}
	return &actionTestRig{
		app:         app,
		gmail:       lp,
		banner:      bi,
		quarantine:  qp,
		store:       store,
		bus:         bus,
		tenant:      tenant,
		kind:        kind,
		registryEnt: entry,
	}
}

// publish converts a typed envelope into a payloadMessage on the
// matching subject for the handler under test.
func publishEnvelope(subject string, env any) events.Message {
	body, _ := json.Marshal(env)
	return payloadMessage{data: body, subject: subject}
}

// ---------------------------------------------------------------------
// es.action.label
// ---------------------------------------------------------------------

func TestHandleActionLabel_AppliesGmailLabel(t *testing.T) {
	rig := newActionTestRig(t)
	env := actionLabelEnvelope{
		TenantID:  rig.tenant,
		MessageID: "msg-1",
		Email:     "alice@example.com",
		Tier:      constant.TierWarning,
		Primary:   constant.CategoryLookalikeDomain,
	}
	if err := rig.app.handleActionLabel(context.Background(), publishEnvelope("es.action.label", env)); err != nil {
		t.Fatalf("handleActionLabel: %v", err)
	}
	if len(rig.gmail.ensure) == 0 {
		t.Fatalf("expected EnsureLabel call, got none")
	}
	if len(rig.gmail.applies) == 0 {
		t.Fatalf("expected ApplyLabel call, got none")
	}
	// The applier should have asked for the canonical SN360 / Warning
	// label as the first ensure.
	if got := rig.gmail.ensure[0].Name; got != "SN360 / Warning" {
		t.Errorf("first ensured label = %q; want SN360 / Warning", got)
	}
}

func TestHandleActionLabel_NoProviderForTenant(t *testing.T) {
	rig := newActionTestRig(t)
	env := actionLabelEnvelope{
		TenantID:  "unknown-tenant",
		MessageID: "msg-1",
		Email:     "alice@example.com",
		Tier:      constant.TierWarning,
	}
	if err := rig.app.handleActionLabel(context.Background(), publishEnvelope("es.action.label", env)); err != nil {
		t.Fatalf("handleActionLabel: %v", err)
	}
	if len(rig.gmail.applies) != 0 {
		t.Errorf("ApplyLabel should not run for unknown tenant; got %d calls", len(rig.gmail.applies))
	}
}

func TestHandleActionLabel_NoLabelApplier(t *testing.T) {
	rig := newActionTestRig(t)
	rig.app.labelApplier = nil
	env := actionLabelEnvelope{
		TenantID:  rig.tenant,
		MessageID: "msg-1",
		Email:     "alice@example.com",
		Tier:      constant.TierWarning,
	}
	if err := rig.app.handleActionLabel(context.Background(), publishEnvelope("es.action.label", env)); err != nil {
		t.Fatalf("handleActionLabel: %v", err)
	}
	if len(rig.gmail.applies) != 0 {
		t.Errorf("ApplyLabel should not run without labelApplier; got %d", len(rig.gmail.applies))
	}
}

func TestHandleActionLabel_DropsMalformed(t *testing.T) {
	rig := newActionTestRig(t)
	if err := rig.app.handleActionLabel(context.Background(), payloadMessage{data: []byte("{not-json")}); err != nil {
		t.Fatalf("handleActionLabel returned err on malformed payload: %v", err)
	}
	if len(rig.gmail.applies) != 0 {
		t.Errorf("malformed envelope should not invoke provider; got %d applies", len(rig.gmail.applies))
	}
}

// ---------------------------------------------------------------------
// es.action.banner
// ---------------------------------------------------------------------

func TestHandleActionBanner_InjectsBanner(t *testing.T) {
	rig := newActionTestRig(t)
	env := actionBannerEnvelope{
		TenantID:  rig.tenant,
		MessageID: "msg-banner",
		Email:     "alice@example.com",
		Tier:      constant.TierWarning,
		HTML:      "<div>banner</div>",
	}
	if err := rig.app.handleActionBanner(context.Background(), publishEnvelope("es.action.banner", env)); err != nil {
		t.Fatalf("handleActionBanner: %v", err)
	}
	got := rig.banner.seen()
	if len(got) != 1 {
		t.Fatalf("expected 1 banner inject; got %d", len(got))
	}
	if got[0].Tenant != rig.tenant {
		t.Errorf("tenant = %q; want %q", got[0].Tenant, rig.tenant)
	}
	if string(got[0].HTML) != env.HTML {
		t.Errorf("html mismatch: %q vs %q", got[0].HTML, env.HTML)
	}
}

func TestHandleActionBanner_NoTenantSkips(t *testing.T) {
	rig := newActionTestRig(t)
	env := actionBannerEnvelope{
		TenantID:  "other-tenant",
		MessageID: "m",
		Email:     "a@b.com",
		HTML:      "<p>hi</p>",
	}
	if err := rig.app.handleActionBanner(context.Background(), publishEnvelope("es.action.banner", env)); err != nil {
		t.Fatalf("handleActionBanner: %v", err)
	}
	if len(rig.banner.seen()) != 0 {
		t.Errorf("banner should not inject for unknown tenant; got %d", len(rig.banner.seen()))
	}
}

func TestHandleActionBanner_DropsEmptyHTML(t *testing.T) {
	rig := newActionTestRig(t)
	env := actionBannerEnvelope{
		TenantID:  rig.tenant,
		MessageID: "m",
		Email:     "a@b.com",
		Tier:      constant.TierWarning,
		HTML:      "", // no html
	}
	if err := rig.app.handleActionBanner(context.Background(), publishEnvelope("es.action.banner", env)); err != nil {
		t.Fatalf("handleActionBanner: %v", err)
	}
	if len(rig.banner.seen()) != 0 {
		t.Errorf("empty HTML should skip; got %d", len(rig.banner.seen()))
	}
}

// ---------------------------------------------------------------------
// es.action.url_rewrite
// ---------------------------------------------------------------------

func TestHandleActionURLRewrite_AcknowledgesSignal(t *testing.T) {
	rig := newActionTestRig(t)
	rig.app.urlRewriter = &action.URLRewriter{}
	env := actionURLRewriteEnvelope{
		TenantID:  rig.tenant,
		MessageID: "msg-url",
		Email:     "a@b.com",
		Tier:      constant.TierHighRisk,
	}
	if err := rig.app.handleActionURLRewrite(context.Background(), publishEnvelope("es.action.url_rewrite", env)); err != nil {
		t.Fatalf("handleActionURLRewrite: %v", err)
	}
}

func TestHandleActionURLRewrite_NoRewriterSkips(t *testing.T) {
	rig := newActionTestRig(t)
	rig.app.urlRewriter = nil
	env := actionURLRewriteEnvelope{
		TenantID:  rig.tenant,
		MessageID: "msg-url",
		Tier:      constant.TierHighRisk,
	}
	if err := rig.app.handleActionURLRewrite(context.Background(), publishEnvelope("es.action.url_rewrite", env)); err != nil {
		t.Fatalf("handleActionURLRewrite: %v", err)
	}
}

// ---------------------------------------------------------------------
// es.action.quarantine
// ---------------------------------------------------------------------

func TestHandleActionQuarantine_QuarantinesMessage(t *testing.T) {
	rig := newActionTestRig(t)
	env := actionQuarantineEnvelope{
		TenantID:  rig.tenant,
		MessageID: "msg-q",
		Email:     "victim@example.com",
		Tier:      constant.TierBlocked,
		Primary:   constant.CategoryCredentialHarvesting,
		Score:     95,
	}
	if err := rig.app.handleActionQuarantine(context.Background(), publishEnvelope("es.action.quarantine", env)); err != nil {
		t.Fatalf("handleActionQuarantine: %v", err)
	}
	if len(rig.quarantine.moves) != 1 {
		t.Fatalf("expected 1 MoveToQuarantine; got %d", len(rig.quarantine.moves))
	}
	if rig.quarantine.moves[0].MessageID != env.MessageID {
		t.Errorf("MessageID = %q; want %q", rig.quarantine.moves[0].MessageID, env.MessageID)
	}
	// The quarantine service publishes an "applied" event.
	if rig.bus.firstPayload("es.action.quarantine.applied") == nil {
		t.Errorf("expected es.action.quarantine.applied to be published; got %v", rig.bus.publishedSubjects())
	}
}

func TestHandleActionQuarantine_SkipsNonBlocked(t *testing.T) {
	rig := newActionTestRig(t)
	env := actionQuarantineEnvelope{
		TenantID:  rig.tenant,
		MessageID: "msg-q",
		Email:     "victim@example.com",
		Tier:      constant.TierWarning, // not blocking
		Primary:   constant.CategoryLookalikeDomain,
	}
	if err := rig.app.handleActionQuarantine(context.Background(), publishEnvelope("es.action.quarantine", env)); err != nil {
		t.Fatalf("handleActionQuarantine: %v", err)
	}
	if len(rig.quarantine.moves) != 0 {
		t.Errorf("non-Blocked tier should skip; got %d moves", len(rig.quarantine.moves))
	}
}

func TestHandleActionQuarantine_SkipsWithoutEmail(t *testing.T) {
	rig := newActionTestRig(t)
	env := actionQuarantineEnvelope{
		TenantID:  rig.tenant,
		MessageID: "msg-q",
		Email:     "", // missing
		Tier:      constant.TierBlocked,
	}
	if err := rig.app.handleActionQuarantine(context.Background(), publishEnvelope("es.action.quarantine", env)); err != nil {
		t.Fatalf("handleActionQuarantine: %v", err)
	}
	if len(rig.quarantine.moves) != 0 {
		t.Errorf("missing email should skip; got %d moves", len(rig.quarantine.moves))
	}
}
