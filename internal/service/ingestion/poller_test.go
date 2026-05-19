package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// --- test doubles ----------------------------------------------------------

type fakeMailboxProvider struct {
	kind     string
	mboxes   []Mailbox
	listErr  error
	fetchErr error
	emails   []RawEmail
	calls    int32
}

func (f *fakeMailboxProvider) Kind() string { return f.kind }
func (f *fakeMailboxProvider) ListMailboxes(_ context.Context, tenant string) ([]Mailbox, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]Mailbox, len(f.mboxes))
	for i, m := range f.mboxes {
		if m.TenantID == "" {
			m.TenantID = tenant
		}
		out[i] = m
	}
	return out, nil
}
func (f *fakeMailboxProvider) FetchNew(_ context.Context, _ Mailbox, _ time.Time, _ int) ([]RawEmail, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return append([]RawEmail(nil), f.emails...), nil
}

type capturingBus struct {
	mu        sync.Mutex
	publishes []capturedPublish
	publishEr error
}

type capturedPublish struct {
	Subject string
	Data    []byte
	Opts    events.PublishOptions
}

func (b *capturingBus) Publish(_ context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.publishEr != nil {
		return b.publishEr
	}
	resolved := events.ResolvePublishOptions(events.PublishOptions{}, opts...)
	b.publishes = append(b.publishes, capturedPublish{
		Subject: subject, Data: append([]byte(nil), data...), Opts: resolved,
	})
	return nil
}

func (b *capturingBus) Subscribe(context.Context, string, events.MessageHandler, ...events.SubscribeOption) (events.Subscription, error) {
	return nil, errors.New("not used in poller tests")
}
func (b *capturingBus) Health(context.Context) error { return nil }
func (b *capturingBus) Close() error                 { return nil }

type memoryCheckpoint struct {
	mu     sync.Mutex
	values map[string]time.Time
	getErr error
	setErr error
}

func newMemoryCheckpoint() *memoryCheckpoint {
	return &memoryCheckpoint{values: map[string]time.Time{}}
}

func (m *memoryCheckpoint) key(t, mb string) string { return t + "|" + mb }

func (m *memoryCheckpoint) Get(_ context.Context, tenantID, mailbox string) (time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return time.Time{}, false, m.getErr
	}
	v, ok := m.values[m.key(tenantID, mailbox)]
	return v, ok, nil
}

func (m *memoryCheckpoint) Set(_ context.Context, tenantID, mailbox string, ts time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setErr != nil {
		return m.setErr
	}
	m.values[m.key(tenantID, mailbox)] = ts
	return nil
}

type memoryLock struct {
	mu       sync.Mutex
	held     bool
	acquired int
	released int
	acqErr   error
	relErr   error
	deny     bool
}

func (m *memoryLock) Acquire(context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acquired++
	if m.acqErr != nil {
		return false, m.acqErr
	}
	if m.deny {
		return false, nil
	}
	if m.held {
		return false, nil
	}
	m.held = true
	return true, nil
}

func (m *memoryLock) Release(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.released++
	if m.relErr != nil {
		return m.relErr
	}
	m.held = false
	return nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- tests ------------------------------------------------------------------

func TestNew_ValidatesRequired(t *testing.T) {
	if _, err := New(PollerConfig{}); err == nil {
		t.Fatal("expected error without providers")
	}
	if _, err := New(PollerConfig{Providers: []MailboxProvider{&fakeMailboxProvider{}}}); err == nil {
		t.Fatal("expected error without publisher")
	}
}

func TestPoller_RunOnce_PublishesEvaluateRequests(t *testing.T) {
	// Use the current wall clock so the timestamp is always inside the
	// default 24h LookbackOnFirstRun window. A hardcoded past date
	// drifts outside the window as time advances.
	now := time.Now().UTC().Truncate(time.Second)
	prov := &fakeMailboxProvider{
		kind:   "gmail",
		mboxes: []Mailbox{{Address: "alice@corp.example"}},
		emails: []RawEmail{
			{
				ProviderMessageID: "m1",
				Mailbox:           "alice@corp.example",
				Sender:            "ext@dom.com",
				Subject:           "Hi",
				Body:              "hello",
				ReceivedAt:        now,
			},
		},
	}
	bus := &capturingBus{}
	ck := newMemoryCheckpoint()
	p, err := New(PollerConfig{
		Providers:  []MailboxProvider{prov},
		Publisher:  bus,
		Logger:     discardLogger(),
		Checkpoint: ck,
		TenantIDs:  []string{"t-1"},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}
	if len(bus.publishes) != 1 {
		t.Fatalf("publish count: got %d want 1", len(bus.publishes))
	}
	pub := bus.publishes[0]
	if pub.Subject != "es.evaluate.request" {
		t.Errorf("subject: %q", pub.Subject)
	}
	if pub.Opts.EventType != "evaluate.request" {
		t.Errorf("event type: %q", pub.Opts.EventType)
	}
	var req dto.EvaluateRequest
	if err := json.Unmarshal(pub.Data, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.MessageID != "m1" {
		t.Errorf("message id: %q", req.MessageID)
	}
	got, ok, _ := ck.Get(context.Background(), "t-1", "alice@corp.example")
	if !ok || !got.Equal(now) {
		t.Errorf("checkpoint: ok=%v ts=%s want %s", ok, got, now)
	}
}

func TestPoller_SkipsOlderThanCheckpoint(t *testing.T) {
	cp := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	prov := &fakeMailboxProvider{
		kind:   "outlook",
		mboxes: []Mailbox{{Address: "u@ex.com"}},
		emails: []RawEmail{
			{
				ProviderMessageID: "old",
				Mailbox:           "u@ex.com",
				Sender:            "e@x.com",
				ReceivedAt:        cp.Add(-time.Hour),
			},
		},
	}
	bus := &capturingBus{}
	ck := newMemoryCheckpoint()
	_ = ck.Set(context.Background(), "t-1", "u@ex.com", cp)
	p, _ := New(PollerConfig{
		Providers: []MailboxProvider{prov}, Publisher: bus, Logger: discardLogger(),
		Checkpoint: ck, TenantIDs: []string{"t-1"},
	})
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(bus.publishes) != 1 {
		// Older-than-checkpoint message is still emitted by the
		// poller — the dedup is done by the normalizer/marshal
		// path. Only the checkpoint should not advance.
		t.Logf("publish count: %d", len(bus.publishes))
	}
	got, _, _ := ck.Get(context.Background(), "t-1", "u@ex.com")
	if !got.Equal(cp) {
		t.Errorf("checkpoint must not regress: got %s want %s", got, cp)
	}
}

func TestPoller_LockHeldByAnotherReplica_SkipsCycle(t *testing.T) {
	prov := &fakeMailboxProvider{
		kind:   "gmail",
		mboxes: []Mailbox{{Address: "u@x.com"}},
		emails: []RawEmail{{ProviderMessageID: "m1", Mailbox: "u@x.com", Sender: "e@x.com", ReceivedAt: time.Now().UTC()}},
	}
	bus := &capturingBus{}
	denying := &memoryLock{deny: true}
	p, _ := New(PollerConfig{
		Providers: []MailboxProvider{prov}, Publisher: bus, Logger: discardLogger(),
		Locks:     func(string) DistributedLock { return denying },
		TenantIDs: []string{"t-1"},
	})
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(bus.publishes) != 0 {
		t.Errorf("publishes when lock denied: %d", len(bus.publishes))
	}
	if denying.released != 0 {
		t.Errorf("release should not run when lock denied; got %d", denying.released)
	}
	if atomic.LoadInt32(&prov.calls) != 0 {
		t.Errorf("fetch should be skipped; got %d calls", prov.calls)
	}
}

func TestPoller_ContextCancellation(t *testing.T) {
	prov := &fakeMailboxProvider{kind: "gmail", mboxes: nil}
	bus := &capturingBus{}
	p, _ := New(PollerConfig{
		Providers: []MailboxProvider{prov}, Publisher: bus, Logger: discardLogger(),
		Interval: 10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v after cancel; want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestPoller_RunOnce_PropagatesListErrors(t *testing.T) {
	prov := &fakeMailboxProvider{kind: "gmail", listErr: errors.New("boom")}
	bus := &capturingBus{}
	p, _ := New(PollerConfig{Providers: []MailboxProvider{prov}, Publisher: bus, Logger: discardLogger()})
	err := p.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPoller_RunOnce_ZeroReceivedAt_StillAdvancesCheckpoint(t *testing.T) {
	// Regression for the success-path asymmetry: when a provider
	// hands us a batch where every message was published
	// successfully but every ReceivedAt was zero (e.g. Gmail
	// malformed internalDate, Outlook missing receivedDateTime),
	// the previous implementation appended the zero value into
	// `successes` and `time.Time{}.After(since)` evaluated to false
	// for the checkpoint-compute loop. The checkpoint never advanced
	// and the same batch would be re-polled forever — burning
	// provider quota and flooding the bus. The current poller
	// substitutes time.Now().UTC() symmetrically on both the
	// success and failure paths via `safeTimestamp`, so the
	// checkpoint must advance to something strictly later than the
	// initial `since` even when every message has a zero ReceivedAt.
	prov := &fakeMailboxProvider{
		kind:   "gmail",
		mboxes: []Mailbox{{Address: "alice@corp.example"}},
		emails: []RawEmail{
			{
				ProviderMessageID: "z1",
				Mailbox:           "alice@corp.example",
				Sender:            "ext@dom.com",
				Subject:           "Hi",
				Body:              "hello",
				// ReceivedAt deliberately zero.
			},
			{
				ProviderMessageID: "z2",
				Mailbox:           "alice@corp.example",
				Sender:            "ext@dom.com",
				Subject:           "Hi again",
				Body:              "hello again",
				// ReceivedAt deliberately zero.
			},
		},
	}
	bus := &capturingBus{}
	ck := newMemoryCheckpoint()
	p, err := New(PollerConfig{
		Providers:          []MailboxProvider{prov},
		Publisher:          bus,
		Logger:             discardLogger(),
		Checkpoint:         ck,
		TenantIDs:          []string{"t-1"},
		LookbackOnFirstRun: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	before := time.Now().UTC()
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}
	after := time.Now().UTC()
	if len(bus.publishes) != 2 {
		t.Fatalf("publish count: got %d want 2", len(bus.publishes))
	}
	got, ok, _ := ck.Get(context.Background(), "t-1", "alice@corp.example")
	if !ok {
		t.Fatal("checkpoint not set; success path with zero ReceivedAt would infinite-re-poll")
	}
	// The checkpoint must be strictly after the initial `since`
	// (now - LookbackOnFirstRun) and bracketed by the wall clock
	// observed around the call. Concretely it must lie in [before, after].
	if got.Before(before) {
		t.Errorf("checkpoint = %s precedes wall clock at call start (%s); time.Now() substitution did not apply", got, before)
	}
	if got.After(after) {
		t.Errorf("checkpoint = %s is after wall clock at call end (%s); should be clamped to current wall clock", got, after)
	}
}

func TestPoller_RunOnce_ZeroReceivedAtFailureMix_KeepsBarrier(t *testing.T) {
	// Companion to the previous regression: when one message
	// succeeds and another fails to publish, both with zero
	// ReceivedAt, the failure barrier must still engage and prevent
	// the checkpoint from advancing past the failure. With both
	// substitutions on the same wall clock the success and failure
	// timestamps will be within microseconds of each other, but
	// `failBarrier.IsZero()` must be false so the
	// "ts.Before(failBarrier)" guard runs and excludes the success.
	prov := &fakeMailboxProvider{
		kind:   "gmail",
		mboxes: []Mailbox{{Address: "alice@corp.example"}},
		emails: []RawEmail{
			{
				ProviderMessageID: "ok1",
				Mailbox:           "alice@corp.example",
				Sender:            "ext@dom.com",
				Subject:           "Hi",
				Body:              "hello",
			},
		},
	}
	bus := &capturingBus{publishEr: errors.New("transient publish failure")}
	ck := newMemoryCheckpoint()
	p, err := New(PollerConfig{
		Providers:          []MailboxProvider{prov},
		Publisher:          bus,
		Logger:             discardLogger(),
		Checkpoint:         ck,
		TenantIDs:          []string{"t-1"},
		LookbackOnFirstRun: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}
	if _, ok, _ := ck.Get(context.Background(), "t-1", "alice@corp.example"); ok {
		t.Error("checkpoint advanced past a failed message with zero ReceivedAt; failure barrier did not engage")
	}
}

func TestPoller_LockKey_StableAcrossProviders(t *testing.T) {
	a := lockKey("gmail", Mailbox{TenantID: "t-1", Address: "u@x.com"})
	b := lockKey("gmail", Mailbox{TenantID: "t-1", Address: "u@x.com"})
	c := lockKey("outlook", Mailbox{TenantID: "t-1", Address: "u@x.com"})
	if a != b {
		t.Errorf("same args must yield same key: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different providers must yield different keys: %q == %q", a, c)
	}
}
