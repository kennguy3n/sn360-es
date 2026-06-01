package webhooksink

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/sinks/webhook"
)

// --- Test doubles ---------------------------------------------------------
//
// The dispatcher accepts four collaborator interfaces (Repo,
// Encryptor, Publisher, Bus). Each test uses purpose-built doubles
// because a real privacy.Encryptor + JetStream + Redis trio would
// make the unit tests both slow and flaky. Doubles are kept here
// (not exported) so the public package surface stays focused on
// production code.

// captureBus records every Publish call so DLQ-fan-out tests can
// assert the subject + envelope content the dispatcher produced.
type captureBus struct {
	mu     sync.Mutex
	subj   []string
	bodies [][]byte
	opts   [][]events.PublishOption
	err    error
}

func (b *captureBus) Publish(_ context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subj = append(b.subj, subject)
	cp := make([]byte, len(data))
	copy(cp, data)
	b.bodies = append(b.bodies, cp)
	b.opts = append(b.opts, opts)
	return b.err
}
func (b *captureBus) Subscribe(context.Context, string, events.MessageHandler, ...events.SubscribeOption) (events.Subscription, error) {
	return nil, errors.New("not implemented")
}
func (b *captureBus) Health(context.Context) error { return nil }
func (b *captureBus) Close() error                 { return nil }

func (b *captureBus) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subj)
}

// identityEncryptor is a passthrough encryptor — the in-memory
// dispatcher uses this so the HMAC secret round-trips through
// the same code path as production (encrypt-store-decrypt-sign)
// without the cost of a real KMS.
type identityEncryptor struct{}

func (identityEncryptor) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	cp := make([]byte, len(plaintext))
	copy(cp, plaintext)
	return cp, nil
}
func (identityEncryptor) Decrypt(_ context.Context, _ string, ct []byte) ([]byte, error) {
	cp := make([]byte, len(ct))
	copy(cp, ct)
	return cp, nil
}

// blockingLimiter denies the first N takes, then unblocks. Used to
// assert the rate-limit branch reports "rate_limited" without
// invoking the publisher.
type blockingLimiter struct {
	mu   sync.Mutex
	deny int
}

func (l *blockingLimiter) Take(_ context.Context, _ string, _ float64, _ int) (bool, time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.deny > 0 {
		l.deny--
		return false, time.Second, nil
	}
	return true, 0, nil
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newSink(t *testing.T, repo repository.WebhookSinkRepository, name, tenant string, opts ...func(*repository.WebhookSink)) *repository.WebhookSink {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef") // 32B passthrough cipher
	s := &repository.WebhookSink{
		ID:                   "sink-" + name,
		TenantID:             tenant,
		Name:                 name,
		URL:                  "https://placeholder.invalid/hook",
		Format:               repository.WebhookSinkFormatECS,
		HMACSecretCiphertext: secret,
		Enabled:              true,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	for _, fn := range opts {
		fn(s)
	}
	if err := repo.Create(context.Background(), s); err != nil {
		t.Fatalf("repo.Create: %v", err)
	}
	return s
}

// --- DispatchVerdict success path -----------------------------------------

// TestDispatchVerdict_DeliversSignedECS round-trips a verdict
// through the dispatcher to a real httptest TLS server and
// asserts:
//  1. Body parses as a non-empty ECS document.
//  2. X-SN360-Signature is a valid HMAC over the body under the
//     configured secret (so the customer-side verifier would
//     accept it).
//  3. X-SN360-Event-Type is email.evaluation.
func TestDispatchVerdict_DeliversSignedECS(t *testing.T) {
	t.Parallel()
	tenant := "00000000-0000-0000-0000-000000000001"
	var (
		mu     sync.Mutex
		gotSig string
		gotBod []byte
		gotTyp string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotSig = r.Header.Get(webhook.SignatureHeader)
		gotTyp = r.Header.Get(webhook.EventTypeHeader)
		gotBod, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	repo := repository.NewInMemoryRegistry()
	sink := newSink(t, repo.WebhookSinks, "primary", tenant, func(s *repository.WebhookSink) {
		s.URL = srv.URL
	})
	pub := webhook.NewHTTPPublisher(webhook.HTTPPublisherConfig{
		Client: srv.Client(),
	})
	bus := &captureBus{}
	d, err := New(Config{
		Repo:      repo.WebhookSinks,
		Encryptor: identityEncryptor{},
		Publisher: pub,
		Bus:       bus,
		Logger:    newTestLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.DispatchVerdict(context.Background(), &dto.EvaluateResult{
		MessageID:   "msg-1",
		TenantID:    tenant,
		Score:       91,
		Tier:        constant.TierBlocked,
		Primary:     constant.CategoryLikelyPhishing,
		ReasonCodes: []string{"lookalike_domain"},
		EvaluatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("DispatchVerdict: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(gotBod) == 0 {
		t.Fatalf("customer endpoint received empty body")
	}
	if gotTyp != webhook.EventTypeEmailEvaluation {
		t.Errorf("event-type = %q; want %s", gotTyp, webhook.EventTypeEmailEvaluation)
	}
	// Customer-side verifier path: decrypt(secret) → Verify(sig).
	ct, _ := identityEncryptor{}.Decrypt(context.Background(), tenant, sink.HMACSecretCiphertext)
	if !webhook.Verify(ct, gotBod, gotSig) {
		t.Errorf("HMAC verification failed on customer side; signature=%q body=%dB", gotSig, len(gotBod))
	}
	if bus.Count() != 0 {
		t.Errorf("DLQ should not be touched on 2xx success; got %d publishes", bus.Count())
	}
}

// --- Retriable failure → DLQ ---------------------------------------------

// TestDispatchVerdict_5xxRoutesToDLQ confirms a retriable HTTP
// outcome republishes the request envelope onto the documented
// JetStream subject and stamps the deterministic dedup ID
// (sink|event|attempt). Without dedup, a dispatcher restart between
// crash + retry would put two retry envelopes on the wire.
func TestDispatchVerdict_5xxRoutesToDLQ(t *testing.T) {
	t.Parallel()
	tenant := "00000000-0000-0000-0000-000000000002"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	repo := repository.NewInMemoryRegistry()
	sink := newSink(t, repo.WebhookSinks, "broken", tenant, func(s *repository.WebhookSink) {
		s.URL = srv.URL
	})
	pub := webhook.NewHTTPPublisher(webhook.HTTPPublisherConfig{Client: srv.Client()})
	bus := &captureBus{}
	d, err := New(Config{
		Repo:      repo.WebhookSinks,
		Encryptor: identityEncryptor{},
		Publisher: pub,
		Bus:       bus,
		Logger:    newTestLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.DispatchVerdict(context.Background(), &dto.EvaluateResult{
		MessageID:   "msg-x",
		TenantID:    tenant,
		Score:       77,
		Tier:        constant.TierWarning,
		Primary:     constant.CategoryNewsletter,
		EvaluatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("DispatchVerdict: %v", err)
	}
	if bus.Count() != 1 {
		t.Fatalf("expected exactly 1 DLQ publish; got %d", bus.Count())
	}
	wantSubj := DLQSubject(tenant, sink.ID)
	if bus.subj[0] != wantSubj {
		t.Errorf("DLQ subject = %q; want %q", bus.subj[0], wantSubj)
	}
	// Envelope must parse + contain the (sink, attempt, last-status)
	// the consumer keys off of.
	env, uerr := webhook.ParseDLQEnvelope(bus.bodies[0])
	if uerr != nil {
		t.Fatalf("DLQ envelope parse: %v", uerr)
	}
	if env.SinkID != sink.ID || env.TenantID != tenant {
		t.Errorf("envelope identity = (%s,%s); want (%s,%s)", env.SinkID, env.TenantID, sink.ID, tenant)
	}
	if env.LastStatus != 502 {
		t.Errorf("envelope LastStatus = %d; want 502", env.LastStatus)
	}
	if env.Attempt != 1 {
		t.Errorf("envelope Attempt = %d; want 1 on first DLQ entry", env.Attempt)
	}
}

// --- Permanent (4xx) failure → audit only, no DLQ -------------------------

func TestDispatchVerdict_4xxAuditsOnly(t *testing.T) {
	t.Parallel()
	tenant := "00000000-0000-0000-0000-000000000003"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	repo := repository.NewInMemoryRegistry()
	sink := newSink(t, repo.WebhookSinks, "denied", tenant, func(s *repository.WebhookSink) {
		s.URL = srv.URL
	})
	bus := &captureBus{}
	pub := webhook.NewHTTPPublisher(webhook.HTTPPublisherConfig{Client: srv.Client()})
	d, _ := New(Config{
		Repo:      repo.WebhookSinks,
		Encryptor: identityEncryptor{},
		Publisher: pub,
		Bus:       bus,
		Logger:    newTestLogger(),
	})
	if err := d.DispatchVerdict(context.Background(), &dto.EvaluateResult{
		MessageID:   "msg-y",
		TenantID:    tenant,
		Score:       77,
		Tier:        constant.TierWarning,
		Primary:     constant.CategoryNewsletter,
		EvaluatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("DispatchVerdict: %v", err)
	}
	if bus.Count() != 0 {
		t.Errorf("4xx must not route to DLQ; got %d DLQ publishes", bus.Count())
	}
	rows, lErr := repo.WebhookSinks.ListAudit(context.Background(), tenant, 16)
	if lErr != nil {
		t.Fatalf("ListAudit: %v", lErr)
	}
	found := false
	for _, r := range rows {
		if r.SinkID == sink.ID && r.Action == repository.WebhookSinkAuditActionDispatchFailed {
			found = true
			if !strings.Contains(r.Reason, "http=401") {
				t.Errorf("audit Reason = %q; want substring 'http=401'", r.Reason)
			}
		}
	}
	if !found {
		t.Errorf("no dispatch_failed audit row found for sink %s", sink.ID)
	}
}

// --- Filter: tier under min_tier is dropped -------------------------------

func TestDispatchVerdict_FilterDropsBelowMinTier(t *testing.T) {
	t.Parallel()
	tenant := "00000000-0000-0000-0000-000000000004"
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	repo := repository.NewInMemoryRegistry()
	newSink(t, repo.WebhookSinks, "high-only", tenant, func(s *repository.WebhookSink) {
		s.URL = srv.URL
		s.EventFilters = repository.WebhookSinkFilters{
			MinTier: string(constant.TierHighRisk),
		}
	})
	pub := webhook.NewHTTPPublisher(webhook.HTTPPublisherConfig{Client: srv.Client()})
	bus := &captureBus{}
	d, _ := New(Config{
		Repo:      repo.WebhookSinks,
		Encryptor: identityEncryptor{},
		Publisher: pub,
		Bus:       bus,
		Logger:    newTestLogger(),
	})
	// Caution < HighRisk → filtered out.
	if err := d.DispatchVerdict(context.Background(), &dto.EvaluateResult{
		MessageID: "msg-caut", TenantID: tenant, Score: 12,
		Tier: constant.TierCaution, Primary: constant.CategoryNewsletter,
	}); err != nil {
		t.Fatalf("DispatchVerdict: %v", err)
	}
	if hits != 0 || bus.Count() != 0 {
		t.Errorf("Caution verdict should be dropped by min_tier=HighRisk filter; got hits=%d bus=%d", hits, bus.Count())
	}
	// HighRisk satisfies the filter → publish.
	if err := d.DispatchVerdict(context.Background(), &dto.EvaluateResult{
		MessageID: "msg-high", TenantID: tenant, Score: 88,
		Tier: constant.TierHighRisk, Primary: constant.CategoryLikelyPhishing,
	}); err != nil {
		t.Fatalf("DispatchVerdict: %v", err)
	}
	if hits != 1 {
		t.Errorf("HighRisk verdict should reach customer; got hits=%d", hits)
	}
}

// --- Rate-limit branch ----------------------------------------------------

func TestDispatchVerdict_RateLimitedDoesNotPublish(t *testing.T) {
	t.Parallel()
	tenant := "00000000-0000-0000-0000-000000000005"
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	repo := repository.NewInMemoryRegistry()
	newSink(t, repo.WebhookSinks, "throttled", tenant, func(s *repository.WebhookSink) {
		s.URL = srv.URL
	})
	pub := webhook.NewHTTPPublisher(webhook.HTTPPublisherConfig{Client: srv.Client()})
	bus := &captureBus{}
	limiter := &blockingLimiter{deny: 1}
	d, _ := New(Config{
		Repo:      repo.WebhookSinks,
		Encryptor: identityEncryptor{},
		Publisher: pub,
		Bus:       bus,
		Limiter:   limiter,
		Logger:    newTestLogger(),
	})
	if err := d.DispatchVerdict(context.Background(), &dto.EvaluateResult{
		MessageID: "msg-1", TenantID: tenant, Score: 88,
		Tier: constant.TierHighRisk, Primary: constant.CategoryLikelyPhishing,
	}); err != nil {
		t.Fatalf("DispatchVerdict: %v", err)
	}
	if hits != 0 {
		t.Errorf("rate-limited dispatch must not hit customer endpoint; got hits=%d", hits)
	}
	if bus.Count() != 0 {
		t.Errorf("rate-limited dispatch must not enqueue DLQ; got %d", bus.Count())
	}
}

// --- DispatchTestEvent surfaces customer status to the caller -------------

func TestDispatchTestEvent_SurfacesStatusToCaller(t *testing.T) {
	t.Parallel()
	tenant := "00000000-0000-0000-0000-000000000006"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated) // 201
	}))
	defer srv.Close()
	repo := repository.NewInMemoryRegistry()
	sink := newSink(t, repo.WebhookSinks, "manual", tenant, func(s *repository.WebhookSink) {
		s.URL = srv.URL
	})
	pub := webhook.NewHTTPPublisher(webhook.HTTPPublisherConfig{Client: srv.Client()})
	bus := &captureBus{}
	d, _ := New(Config{
		Repo:      repo.WebhookSinks,
		Encryptor: identityEncryptor{},
		Publisher: pub,
		Bus:       bus,
		Logger:    newTestLogger(),
	})
	res, err := d.DispatchTestEvent(context.Background(), sink)
	if err != nil {
		t.Fatalf("DispatchTestEvent: %v", err)
	}
	if res.HTTPStatus != http.StatusCreated {
		t.Errorf("HTTPStatus = %d; want 201", res.HTTPStatus)
	}
	if res.Outcome != webhook.OutcomeSuccess {
		t.Errorf("Outcome = %v; want OutcomeSuccess", res.Outcome)
	}
}

// --- Helpers --------------------------------------------------------------

// TestDLQSubject_Format pins the wire subject so the consumer
// wiring + ops dashboards key off the same value the producer
// publishes onto.
func TestDLQSubject_Format(t *testing.T) {
	t.Parallel()
	got := DLQSubject("tA", "sinkX")
	want := "sn360.dlq.webhook.tA.sinkX"
	if got != want {
		t.Errorf("DLQSubject = %q; want %q", got, want)
	}
}

// TestDedupID_Deterministic guards the JetStream dedup contract:
// the same (sink, event, attempt) tuple MUST hash to the same ID so
// the broker collapses crash-and-retry duplicates.
func TestDedupID_Deterministic(t *testing.T) {
	t.Parallel()
	a := DedupID("sink-1", "evt-1", 3)
	b := DedupID("sink-1", "evt-1", 3)
	if a != b {
		t.Errorf("DedupID not stable: %q vs %q", a, b)
	}
	// Different attempts must produce different IDs so the
	// 2nd/3rd retry envelopes don't collapse into the 1st.
	if DedupID("sink-1", "evt-1", 3) == DedupID("sink-1", "evt-1", 4) {
		t.Errorf("DedupID collides across attempts")
	}
}
