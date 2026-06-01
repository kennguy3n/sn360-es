package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// TestWS4A_EvaluateRequestPublishesCommHistoryUpdate pins the
// producer side of the WS-4a hot path: handleEvaluateRequest must
// derive a CommHistoryUpdate from the enricher (sharing read-side
// normalisation) and publish it onto
// es.management.comm_history.update with the deterministic dedup
// id keyed on (tenant, sender_hash, recipient_hash, message_id).
//
// This is the integration-level contract that prevents the worker-
// cycle staleness window from regressing — without the publish,
// every fresh sender-recipient pair stays at 0 counts until the
// 4-hour relationship_worker cycle catches it.
func TestWS4A_EvaluateRequestPublishesCommHistoryUpdate(t *testing.T) {
	t.Parallel()

	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})

	repo := newFakeCommHistoryRepo()
	hasher := fakeHasher{}
	app.signalEnricher = newCommHistorySignalEnricher(repo, hasher, discardLogger())
	if app.signalEnricher == nil {
		t.Fatalf("newCommHistorySignalEnricher returned nil; both deps were supplied")
	}

	receivedAt := time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC)
	req := dto.EvaluateRequest{
		MessageID:     "msg-ws4a-1",
		TenantID:      "t-ws4a",
		CorrelationID: "corr-ws4a-1",
		Sender:        "Alice@Partner.Example",
		Recipient:     "Bob@Acme.Test",
		Signals:       dto.RiskSignals{IsExternal: true, SenderDomain: "Partner.Example"},
		ReceivedAt:    receivedAt,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload}); err != nil {
		t.Fatalf("handleEvaluateRequest: %v", err)
	}

	// Two publishes are expected on the bus: the evaluate.result
	// envelope (existing contract) and the WS-4a comm_history
	// update (new contract).
	subjects := bus.publishedSubjects()
	gotEvalResult := false
	gotCommHistory := false
	for _, s := range subjects {
		if s == "es.evaluate.result" {
			gotEvalResult = true
		}
		if s == dto.CommHistoryUpdateSubject {
			gotCommHistory = true
		}
	}
	if !gotEvalResult {
		t.Fatalf("expected es.evaluate.result publish; got subjects=%v", subjects)
	}
	if !gotCommHistory {
		t.Fatalf("expected %s publish; got subjects=%v", dto.CommHistoryUpdateSubject, subjects)
	}

	commPayload := bus.firstPayload(dto.CommHistoryUpdateSubject)
	if len(commPayload) == 0 {
		t.Fatalf("comm_history update payload was empty")
	}
	var upd dto.CommHistoryUpdate
	if err := json.Unmarshal(commPayload, &upd); err != nil {
		t.Fatalf("unmarshal published comm_history update: %v", err)
	}
	if err := upd.Validate(); err != nil {
		t.Fatalf("published comm_history update failed Validate: %v", err)
	}

	// Tenant survives intact; sender / recipient are lowered to
	// match the enricher read path's deterministic hashing.
	if upd.TenantID != "t-ws4a" {
		t.Fatalf("TenantID=%q want t-ws4a", upd.TenantID)
	}
	if upd.MessageID != "msg-ws4a-1" {
		t.Fatalf("MessageID=%q want msg-ws4a-1", upd.MessageID)
	}
	// fakeHasher: HashPII(tenant, input) = tenant + "::" + input
	// after TrimSpace + ToLower; assert the exact bytes so any
	// drift in the normalisation cascade trips this test.
	wantSender := []byte("t-ws4a::alice@partner.example")
	wantRecipient := []byte("t-ws4a::bob@acme.test")
	wantSenderDomain := []byte("t-ws4a::partner.example")
	if string(upd.SenderHash) != string(wantSender) {
		t.Fatalf("SenderHash=%q want %q", upd.SenderHash, wantSender)
	}
	if string(upd.RecipientHash) != string(wantRecipient) {
		t.Fatalf("RecipientHash=%q want %q", upd.RecipientHash, wantRecipient)
	}
	if string(upd.SenderDomainHash) != string(wantSenderDomain) {
		t.Fatalf("SenderDomainHash=%q want %q", upd.SenderDomainHash, wantSenderDomain)
	}
	if upd.SenderDomain != "partner.example" {
		t.Fatalf("SenderDomain=%q want partner.example (lowered)", upd.SenderDomain)
	}
	if !upd.SentAt.Equal(receivedAt) {
		t.Fatalf("SentAt=%s want %s (ReceivedAt pass-through)", upd.SentAt, receivedAt)
	}

	// DedupID is the JetStream Nats-Msg-Id used for broker-side
	// idempotency. Pin its derivation: same (tenant, sender_hash,
	// recipient_hash, message_id) → same dedup id across calls.
	if upd.DedupID() == "" {
		t.Fatalf("DedupID returned empty string")
	}
	if redup := upd.DedupID(); redup != upd.DedupID() {
		t.Fatalf("DedupID is non-deterministic: %q vs %q", redup, upd.DedupID())
	}
}

// TestWS4A_PublishConsumerRoundTripRecordsSighting wires the
// producer (handleEvaluateRequest -> publish) directly into the
// consumer (handleCommHistoryUpdate -> RecordSighting) on the same
// in-process bus, and asserts the row lands in the repository.
// This is the closest in-process analogue of the production
// JetStream round-trip: enrich -> publish -> consume -> persist.
func TestWS4A_PublishConsumerRoundTripRecordsSighting(t *testing.T) {
	t.Parallel()

	repo := newRecordingCommHistoryRepo()
	app := newTestApp(t)
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})
	app.repos = &repository.Registry{CommunicationHistories: repo}
	app.signalEnricher = newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())

	loop := newLoopbackBus(t, dto.CommHistoryUpdateSubject, app.handleCommHistoryUpdate)
	app.eventBus = loop

	req := dto.EvaluateRequest{
		MessageID:     "msg-roundtrip-1",
		TenantID:      "t-roundtrip",
		CorrelationID: "corr-roundtrip",
		Sender:        "carol@vendor.test",
		Recipient:     "dave@acme.test",
		Signals:       dto.RiskSignals{IsExternal: true, SenderDomain: "vendor.test"},
		ReceivedAt:    time.Date(2026, 5, 26, 9, 15, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload}); err != nil {
		t.Fatalf("handleEvaluateRequest: %v", err)
	}

	sightings := repo.snapshot()
	if len(sightings) != 1 {
		t.Fatalf("expected 1 RecordSighting call, got %d", len(sightings))
	}
	got := sightings[0]
	if got.TenantID != "t-roundtrip" {
		t.Fatalf("Sighting.TenantID=%q want t-roundtrip", got.TenantID)
	}
	if string(got.SenderHash) != "t-roundtrip::carol@vendor.test" {
		t.Fatalf("Sighting.SenderHash=%q want t-roundtrip::carol@vendor.test", got.SenderHash)
	}
	if string(got.RecipientHash) != "t-roundtrip::dave@acme.test" {
		t.Fatalf("Sighting.RecipientHash=%q want t-roundtrip::dave@acme.test", got.RecipientHash)
	}
	if got.SenderDomain != "vendor.test" {
		t.Fatalf("Sighting.SenderDomain=%q want vendor.test", got.SenderDomain)
	}
	if got.SentAt.IsZero() {
		t.Fatalf("Sighting.SentAt is zero")
	}
}

// TestWS4A_DuplicateMessageIDProducesSameDedupID is the producer-
// side idempotency contract: two evaluate.request envelopes with
// the same (tenant, sender, recipient, message_id) tuple must
// derive the same JetStream Nats-Msg-Id so the broker can collapse
// the redelivery within the 2-minute dedup window. Without this,
// JetStream's dedup is useless and every retry double-counts.
func TestWS4A_DuplicateMessageIDProducesSameDedupID(t *testing.T) {
	t.Parallel()

	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})
	app.signalEnricher = newCommHistorySignalEnricher(newFakeCommHistoryRepo(), fakeHasher{}, discardLogger())

	req := dto.EvaluateRequest{
		MessageID:  "msg-dedup-1",
		TenantID:   "t-dedup",
		Sender:     "alice@vendor.test",
		Recipient:  "bob@acme.test",
		Signals:    dto.RiskSignals{IsExternal: true, SenderDomain: "vendor.test"},
		ReceivedAt: time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload}); err != nil {
			t.Fatalf("handleEvaluateRequest iteration %d: %v", i, err)
		}
	}

	var commPayloads [][]byte
	for _, p := range bus.publishes {
		if p.Subject == dto.CommHistoryUpdateSubject {
			commPayloads = append(commPayloads, p.Payload)
		}
	}
	if len(commPayloads) != 2 {
		t.Fatalf("expected 2 comm_history publishes, got %d", len(commPayloads))
	}
	var first, second dto.CommHistoryUpdate
	if err := json.Unmarshal(commPayloads[0], &first); err != nil {
		t.Fatalf("unmarshal first: %v", err)
	}
	if err := json.Unmarshal(commPayloads[1], &second); err != nil {
		t.Fatalf("unmarshal second: %v", err)
	}
	if first.DedupID() != second.DedupID() {
		t.Fatalf("dedup id drift between identical requests: first=%q second=%q",
			first.DedupID(), second.DedupID())
	}
}

// TestWS4A_ConsumerReturnsErrorOnTransientRepoFailure pins the
// retry contract: a transient RecordSighting error must surface as
// an error from the handler so JetStream's MaxDeliver=3 budget
// kicks in and redelivers the sighting. Returning nil here would
// silently swallow the sighting and force the operator to wait
// for the 4-hour relationship_worker recovery window.
func TestWS4A_ConsumerReturnsErrorOnTransientRepoFailure(t *testing.T) {
	t.Parallel()

	repo := newRecordingCommHistoryRepo()
	repo.recordErr = errors.New("postgres: connection refused")
	app := newTestApp(t)
	app.repos = &repository.Registry{CommunicationHistories: repo}

	upd := dto.CommHistoryUpdate{
		TenantID:      "t-transient",
		MessageID:     "msg-transient",
		SenderHash:    []byte("sender-hash"),
		RecipientHash: []byte("recipient-hash"),
		SentAt:        time.Now().UTC(),
	}
	payload, err := json.Marshal(upd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := app.handleCommHistoryUpdate(context.Background(), payloadMessage{data: payload}); err == nil {
		t.Fatalf("expected error from transient repo failure; got nil")
	}
	// One delivery attempt; JetStream would redeliver up to
	// MaxDeliver=3 in production. The handler must NOT eat the
	// error.
	if got := repo.snapshot(); len(got) != 1 {
		t.Fatalf("expected exactly one delivery attempt, got %d", len(got))
	}
}

// TestWS4A_ConsumerReturnsNilOnPoisonMessage pins the poison-pill
// contract: an unparseable or invalid envelope must NOT surface as
// an error (a return-error would force JetStream to redeliver
// until MaxDeliver=3 burns out, wasting bus and consumer budget on
// a payload that can never become valid). The handler logs the
// problem and returns nil; the broker drops the message.
func TestWS4A_ConsumerReturnsNilOnPoisonMessage(t *testing.T) {
	t.Parallel()

	repo := newRecordingCommHistoryRepo()
	app := newTestApp(t)
	app.repos = &repository.Registry{CommunicationHistories: repo}

	if err := app.handleCommHistoryUpdate(context.Background(), payloadMessage{data: []byte("{not-json")}); err != nil {
		t.Fatalf("expected nil on unparseable payload (poison-pill contract); got %v", err)
	}
	if got := repo.snapshot(); len(got) != 0 {
		t.Fatalf("unparseable payload reached the repository: %v", got)
	}

	// Validate-failure: missing required fields.
	badUpd := dto.CommHistoryUpdate{TenantID: "", MessageID: "m", SentAt: time.Now().UTC()}
	badPayload, _ := json.Marshal(badUpd)
	if err := app.handleCommHistoryUpdate(context.Background(), payloadMessage{data: badPayload}); err != nil {
		t.Fatalf("expected nil on validate failure (poison-pill contract); got %v", err)
	}
	if got := repo.snapshot(); len(got) != 0 {
		t.Fatalf("validate-failing payload reached the repository: %v", got)
	}
}

// TestWS4A_PublisherSkipsWhenSightingForReturnsFalse covers the
// NoopEnricher/short-circuit branch: when SightingFor returns
// (zero, false) (e.g. NoopEnricher fallback because no repo/hasher
// was wired), publishCommHistoryUpdate must NOT publish anything
// onto the bus. Publishing a zero-value sighting would corrupt
// the consumer (RecordSighting would reject empty hashes).
func TestWS4A_PublisherSkipsWhenSightingForReturnsFalse(t *testing.T) {
	t.Parallel()

	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})
	app.signalEnricher = evaluate.NoopEnricher{}

	req := dto.EvaluateRequest{
		MessageID:  "msg-noop-1",
		TenantID:   "t-noop",
		Sender:     "alice@partner.test",
		Recipient:  "bob@acme.test",
		Signals:    dto.RiskSignals{IsExternal: true},
		ReceivedAt: time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload}); err != nil {
		t.Fatalf("handleEvaluateRequest: %v", err)
	}
	for _, p := range bus.publishes {
		if p.Subject == dto.CommHistoryUpdateSubject {
			t.Fatalf("NoopEnricher path must not publish %s; got payload %q",
				dto.CommHistoryUpdateSubject, p.Payload)
		}
	}
}

// recordingCommHistoryRepo is a test double for
// CommunicationHistoryRepository that records every RecordSighting
// call and optionally returns a configurable error. Get / Upsert /
// UpdateCountsIfFresh / ListByTenant panic so an accidental call
// to a read or worker-CAS path produces a loud failure (the
// WS-4a write path lives entirely on RecordSighting).
type recordingCommHistoryRepo struct {
	mu        sync.Mutex
	sightings []repository.Sighting
	recordErr error
	rows      map[string]*repository.CommunicationHistory
}

func newRecordingCommHistoryRepo() *recordingCommHistoryRepo {
	return &recordingCommHistoryRepo{rows: map[string]*repository.CommunicationHistory{}}
}

func (r *recordingCommHistoryRepo) key(tenant string, sender, recipient []byte) string {
	return tenant + "|" + string(sender) + "|" + string(recipient)
}

func (r *recordingCommHistoryRepo) RecordSighting(_ context.Context, s repository.Sighting) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sightings = append(r.sightings, s)
	if r.recordErr != nil {
		return r.recordErr
	}
	return nil
}

func (r *recordingCommHistoryRepo) snapshot() []repository.Sighting {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]repository.Sighting, len(r.sightings))
	copy(cp, r.sightings)
	return cp
}

func (r *recordingCommHistoryRepo) Upsert(_ context.Context, _ *repository.CommunicationHistory) error {
	panic("unexpected Upsert call in WS-4a round-trip test")
}

func (r *recordingCommHistoryRepo) UpdateCountsIfFresh(_ context.Context, _ *repository.CommunicationHistory, _ time.Time) (bool, error) {
	panic("unexpected UpdateCountsIfFresh call in WS-4a round-trip test")
}

func (r *recordingCommHistoryRepo) Get(_ context.Context, tenantID string, senderHash, recipientHash []byte) (*repository.CommunicationHistory, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[r.key(tenantID, senderHash, recipientHash)]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *row
	return &cp, nil
}

func (r *recordingCommHistoryRepo) ListByTenant(_ context.Context, _ string, _ time.Time, _ int) ([]repository.CommunicationHistory, error) {
	panic("unexpected ListByTenant call in WS-4a round-trip test")
}

func (r *recordingCommHistoryRepo) ListBySender(_ context.Context, _ string, _ []byte, _ int) ([]repository.CommunicationHistory, error) {
	panic("unexpected ListBySender call in WS-4a round-trip test")
}

// loopbackBus is a test double for events.EventService that
// dispatches every Publish onto a registered handler synchronously
// on the same goroutine. It is intentionally narrower than
// recordingBus — Subscribe / Health / Close are no-ops because the
// round-trip tests drive subscription registration explicitly via
// newLoopbackBus rather than going through StartConsumers.
//
// The single registered handler is matched by subject equality so
// the loopback bus can host the production-shape contract: a
// publish onto es.management.comm_history.update routes to
// handleCommHistoryUpdate, anything else (e.g. es.evaluate.result)
// is recorded but no consumer is wired.
type loopbackBus struct {
	mu        sync.Mutex
	t         *testing.T
	subject   string
	handler   events.MessageHandler
	publishes []recordedPublish
}

func newLoopbackBus(t *testing.T, subject string, handler events.MessageHandler) *loopbackBus {
	return &loopbackBus{t: t, subject: subject, handler: handler}
}

func (b *loopbackBus) Publish(ctx context.Context, subject string, data []byte, _ ...events.PublishOption) error {
	b.mu.Lock()
	payload := append([]byte(nil), data...)
	b.publishes = append(b.publishes, recordedPublish{Subject: subject, Payload: payload})
	handler := b.handler
	subj := b.subject
	b.mu.Unlock()
	if handler == nil || subject != subj {
		return nil
	}
	return handler(ctx, payloadMessage{data: payload, subject: subject})
}

func (b *loopbackBus) Subscribe(_ context.Context, _ string, _ events.MessageHandler, _ ...events.SubscribeOption) (events.Subscription, error) {
	return nil, errors.New("loopbackBus: Subscribe is not implemented in WS-4a round-trip tests")
}

func (b *loopbackBus) Health(_ context.Context) error { return nil }
func (b *loopbackBus) Close() error                   { return nil }
