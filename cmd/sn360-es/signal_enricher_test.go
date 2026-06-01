package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
)

// fakeCommHistoryRepo is a minimal stand-in for
// repository.CommunicationHistoryRepository covering only Get (the
// single method the signal enricher consumes). The other interface
// methods panic so a test accidentally exercising them gets a loud
// failure rather than a silent wrong-answer.
type fakeCommHistoryRepo struct {
	mu      sync.Mutex
	rows    map[string]*repository.CommunicationHistory
	errOnce error
	hits    int
}

func newFakeCommHistoryRepo() *fakeCommHistoryRepo {
	return &fakeCommHistoryRepo{rows: map[string]*repository.CommunicationHistory{}}
}

func (f *fakeCommHistoryRepo) key(tenant string, sender, recipient []byte) string {
	return tenant + "|" + string(sender) + "|" + string(recipient)
}

func (f *fakeCommHistoryRepo) seed(tenant string, sender, recipient []byte, row *repository.CommunicationHistory) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[f.key(tenant, sender, recipient)] = row
}

func (f *fakeCommHistoryRepo) Upsert(_ context.Context, _ *repository.CommunicationHistory) error {
	panic("unexpected Upsert call in signal-enricher test")
}

func (f *fakeCommHistoryRepo) UpdateCountsIfFresh(_ context.Context, _ *repository.CommunicationHistory, _ time.Time) (bool, error) {
	panic("unexpected UpdateCountsIfFresh call in signal-enricher test")
}

func (f *fakeCommHistoryRepo) RecordSighting(_ context.Context, _ repository.Sighting) error {
	// The signal-enricher Enrich() path is read-only against the
	// repository; the WS-4a write path publishes asynchronously
	// onto es.management.comm_history.update and is exercised by
	// dedicated tests. A call here would mean the read-only
	// contract has regressed.
	panic("unexpected RecordSighting call in signal-enricher test")
}

func (f *fakeCommHistoryRepo) ListByTenant(_ context.Context, _ string, _ time.Time, _ int) ([]repository.CommunicationHistory, error) {
	panic("unexpected ListByTenant call in signal-enricher test")
}

func (f *fakeCommHistoryRepo) Get(_ context.Context, tenantID string, senderHash, recipientHash []byte) (*repository.CommunicationHistory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if f.errOnce != nil {
		err := f.errOnce
		f.errOnce = nil
		return nil, err
	}
	row, ok := f.rows[f.key(tenantID, senderHash, recipientHash)]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *row
	return &cp, nil
}

// fakeHasher implements agent.PIIHasher with a deterministic
// stringification so test cases can assert on row keys byte-for-
// byte.
type fakeHasher struct{}

func (fakeHasher) HashPII(tenantID, input string) string {
	return tenantID + "::" + input
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestCommHistorySignalEnricher_NewWithNilDepsReturnsNil(t *testing.T) {
	if e := newCommHistorySignalEnricher(nil, fakeHasher{}, nil); e != nil {
		t.Fatalf("expected nil enricher when repo is nil, got %v", e)
	}
	repo := newFakeCommHistoryRepo()
	if e := newCommHistorySignalEnricher(repo, nil, nil); e != nil {
		t.Fatalf("expected nil enricher when hasher is nil, got %v", e)
	}
}

func TestCommHistorySignalEnricher_NoRowFlagsFirstContact(t *testing.T) {
	repo := newFakeCommHistoryRepo()
	e := newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())
	req := dto.EvaluateRequest{
		TenantID:   "t-1",
		Sender:     "alice@external.com",
		Recipient:  "bob@acme.com",
		ReceivedAt: time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC),
	}
	out := e.Enrich(context.Background(), req, dto.RiskSignals{})
	if !out.IsFirstContact {
		t.Fatalf("expected IsFirstContact=true on missing row, got false")
	}
	if out.TypicalSendHour != nil {
		t.Fatalf("expected nil TypicalSendHour on missing row, got %v", *out.TypicalSendHour)
	}
	if out.CommunicationFrequency != 0 {
		t.Fatalf("expected CommunicationFrequency=0 on missing row, got %d", out.CommunicationFrequency)
	}
	if out.CurrentHourUTC != 14 {
		t.Fatalf("expected CurrentHourUTC=14 (from ReceivedAt), got %d", out.CurrentHourUTC)
	}
}

func TestCommHistorySignalEnricher_PopulatesFromExistingRow(t *testing.T) {
	repo := newFakeCommHistoryRepo()
	sender := []byte((fakeHasher{}).HashPII("t-1", "alice@partner.com"))
	recipient := []byte((fakeHasher{}).HashPII("t-1", "bob@acme.com"))
	repo.seed("t-1", sender, recipient, &repository.CommunicationHistory{
		TenantID:      "t-1",
		SenderHash:    sender,
		RecipientHash: recipient,
		Count30d:      37,
		TypicalHour:   9,
		Relationship:  string(dto.RelationshipPartner),
	})
	e := newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())

	req := dto.EvaluateRequest{
		TenantID:   "t-1",
		Sender:     "alice@partner.com",
		Recipient:  "bob@acme.com",
		ReceivedAt: time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC),
	}
	out := e.Enrich(context.Background(), req, dto.RiskSignals{})
	if out.IsFirstContact {
		t.Fatalf("expected IsFirstContact=false on existing row")
	}
	if out.CommunicationFrequency != 37 {
		t.Fatalf("CommunicationFrequency=%d want 37", out.CommunicationFrequency)
	}
	if out.TypicalSendHour == nil {
		t.Fatal("expected non-nil TypicalSendHour")
	}
	if *out.TypicalSendHour != 9 {
		t.Fatalf("*TypicalSendHour=%d want 9", *out.TypicalSendHour)
	}
	if out.CurrentHourUTC != 14 {
		t.Fatalf("CurrentHourUTC=%d want 14", out.CurrentHourUTC)
	}
	if out.RelationshipCategory != dto.RelationshipPartner {
		t.Fatalf("RelationshipCategory=%q want Partner", out.RelationshipCategory)
	}
}

func TestCommHistorySignalEnricher_SentinelTypicalHourMapsToNil(t *testing.T) {
	repo := newFakeCommHistoryRepo()
	sender := []byte((fakeHasher{}).HashPII("t-1", "alice@partner.com"))
	recipient := []byte((fakeHasher{}).HashPII("t-1", "bob@acme.com"))
	repo.seed("t-1", sender, recipient, &repository.CommunicationHistory{
		TenantID:      "t-1",
		SenderHash:    sender,
		RecipientHash: recipient,
		Count30d:      4,
		TypicalHour:   repository.TypicalHourUnset, // -1 sentinel
	})
	e := newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())
	req := dto.EvaluateRequest{
		TenantID:  "t-1",
		Sender:    "alice@partner.com",
		Recipient: "bob@acme.com",
	}
	out := e.Enrich(context.Background(), req, dto.RiskSignals{})
	if out.TypicalSendHour != nil {
		t.Fatalf("expected nil TypicalSendHour for -1 sentinel, got %d", *out.TypicalSendHour)
	}
	if out.CommunicationFrequency != 4 {
		t.Fatalf("CommunicationFrequency=%d want 4", out.CommunicationFrequency)
	}
	if out.IsFirstContact {
		t.Fatalf("IsFirstContact should be false when a row exists, even with sentinel TypicalHour")
	}
}

func TestCommHistorySignalEnricher_OutOfRangeTypicalHourMapsToNil(t *testing.T) {
	repo := newFakeCommHistoryRepo()
	sender := []byte((fakeHasher{}).HashPII("t-1", "alice@partner.com"))
	recipient := []byte((fakeHasher{}).HashPII("t-1", "bob@acme.com"))
	repo.seed("t-1", sender, recipient, &repository.CommunicationHistory{
		TenantID:      "t-1",
		SenderHash:    sender,
		RecipientHash: recipient,
		Count30d:      4,
		TypicalHour:   25, // out of [0,24)
	})
	e := newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())
	req := dto.EvaluateRequest{TenantID: "t-1", Sender: "alice@partner.com", Recipient: "bob@acme.com"}
	out := e.Enrich(context.Background(), req, dto.RiskSignals{})
	if out.TypicalSendHour != nil {
		t.Fatalf("expected nil TypicalSendHour for out-of-range value, got %d", *out.TypicalSendHour)
	}
}

func TestCommHistorySignalEnricher_TransientErrorDegradesToBase(t *testing.T) {
	repo := newFakeCommHistoryRepo()
	repo.errOnce = errors.New("postgres: blip")
	e := newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())

	base := dto.RiskSignals{SenderDomain: "external.com", IsExternal: true}
	req := dto.EvaluateRequest{TenantID: "t-1", Sender: "x@y.com", Recipient: "a@b.com"}
	out := e.Enrich(context.Background(), req, base)
	if out.IsFirstContact {
		t.Fatalf("transient error must NOT synthesise IsFirstContact=true")
	}
	if out.CommunicationFrequency != 0 {
		t.Fatalf("CommunicationFrequency must remain at base zero, got %d", out.CommunicationFrequency)
	}
	if out.TypicalSendHour != nil {
		t.Fatal("TypicalSendHour must remain nil on transient error")
	}
	if !out.IsExternal || out.SenderDomain != "external.com" {
		t.Fatalf("base fields must flow through untouched: %+v", out)
	}
}

func TestCommHistorySignalEnricher_MissingTenantOrAddressShortCircuits(t *testing.T) {
	repo := newFakeCommHistoryRepo()
	e := newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())

	cases := []struct {
		name string
		req  dto.EvaluateRequest
	}{
		{"no tenant", dto.EvaluateRequest{Sender: "a@b", Recipient: "c@d"}},
		{"no sender", dto.EvaluateRequest{TenantID: "t", Recipient: "c@d"}},
		{"no recipient", dto.EvaluateRequest{TenantID: "t", Sender: "a@b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := repo.hits
			_ = e.Enrich(context.Background(), tc.req, dto.RiskSignals{})
			if repo.hits != before {
				t.Fatalf("repo.Get was called for %s; expected short-circuit", tc.name)
			}
		})
	}
}

// TestCommHistorySignalEnricher_ClearsProducerSuppliedTypicalSendHour
// pins the enricher-owned contract on TypicalSendHour. A future
// producer that erroneously populates dto.RiskSignals.TypicalSendHour
// on base must not be able to smuggle that value past the enricher
// when the DB row is missing OR carries an out-of-range sentinel —
// the only way TypicalSendHour leaves the enricher non-nil is if a
// valid (0..23) row exists for the pair.
func TestCommHistorySignalEnricher_ClearsProducerSuppliedTypicalSendHour(t *testing.T) {
	repo := newFakeCommHistoryRepo()
	sender := []byte((fakeHasher{}).HashPII("t-1", "alice@partner.com"))
	recipient := []byte((fakeHasher{}).HashPII("t-1", "bob@acme.com"))
	repo.seed("t-1", sender, recipient, &repository.CommunicationHistory{
		TenantID:      "t-1",
		SenderHash:    sender,
		RecipientHash: recipient,
		Count30d:      4,
		TypicalHour:   repository.TypicalHourUnset, // -1 sentinel; row exists but no baseline yet
	})
	e := newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())
	req := dto.EvaluateRequest{TenantID: "t-1", Sender: "alice@partner.com", Recipient: "bob@acme.com"}

	stale := 7
	base := dto.RiskSignals{TypicalSendHour: &stale}
	out := e.Enrich(context.Background(), req, base)
	if out.TypicalSendHour != nil {
		t.Fatalf("stale producer-supplied TypicalSendHour leaked past enricher when DB row had sentinel: got *TypicalSendHour=%d", *out.TypicalSendHour)
	}

	// Out-of-range DB row must also nil out base's value.
	repo.seed("t-1", sender, recipient, &repository.CommunicationHistory{
		TenantID:      "t-1",
		SenderHash:    sender,
		RecipientHash: recipient,
		Count30d:      4,
		TypicalHour:   25, // out of [0,24)
	})
	out = e.Enrich(context.Background(), req, base)
	if out.TypicalSendHour != nil {
		t.Fatalf("stale producer-supplied TypicalSendHour leaked past enricher when DB row was out-of-range: got *TypicalSendHour=%d", *out.TypicalSendHour)
	}

	// Missing row (ErrNotFound branch) must also clear base.
	repo = newFakeCommHistoryRepo()
	e = newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())
	out = e.Enrich(context.Background(), req, base)
	if out.TypicalSendHour != nil {
		t.Fatalf("stale producer-supplied TypicalSendHour leaked past enricher when row was missing (IsFirstContact): got *TypicalSendHour=%d", *out.TypicalSendHour)
	}
	if !out.IsFirstContact {
		t.Fatalf("expected IsFirstContact=true on missing row")
	}
}

func TestCommHistorySignalEnricher_PreservesProducerSuppliedRelationship(t *testing.T) {
	repo := newFakeCommHistoryRepo()
	sender := []byte((fakeHasher{}).HashPII("t-1", "alice@partner.com"))
	recipient := []byte((fakeHasher{}).HashPII("t-1", "bob@acme.com"))
	repo.seed("t-1", sender, recipient, &repository.CommunicationHistory{
		TenantID:      "t-1",
		SenderHash:    sender,
		RecipientHash: recipient,
		Count30d:      37,
		TypicalHour:   9,
		Relationship:  string(dto.RelationshipPartner),
	})
	e := newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())
	req := dto.EvaluateRequest{TenantID: "t-1", Sender: "alice@partner.com", Recipient: "bob@acme.com"}

	// Producer already classified as Customer; enricher must not overwrite.
	base := dto.RiskSignals{RelationshipCategory: dto.RelationshipCustomer}
	out := e.Enrich(context.Background(), req, base)
	if out.RelationshipCategory != dto.RelationshipCustomer {
		t.Fatalf("producer-supplied RelationshipCategory was overwritten: got %q want Customer", out.RelationshipCategory)
	}
}

// recordingEnricher captures every Enrich invocation so consumer-
// side wiring tests can assert handleEvaluateRequest /
// BatchOrchestrator actually invoke the enricher with the expected
// request envelope.
//
// applyOverride is an explicit override hook (rather than a zero-
// value sentinel on a dto.RiskSignals field) so a test that needs
// to override CurrentHourUTC to 0 (midnight UTC) or any other Go
// zero-value still produces an unambiguous override.
type recordingEnricher struct {
	mu            sync.Mutex
	calls         []recordingEnricherCall
	applyOverride func(base dto.RiskSignals) dto.RiskSignals
}

type recordingEnricherCall struct {
	req  dto.EvaluateRequest
	base dto.RiskSignals
}

func (r *recordingEnricher) Enrich(_ context.Context, req dto.EvaluateRequest, base dto.RiskSignals) dto.RiskSignals {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordingEnricherCall{req: req, base: base})
	if r.applyOverride == nil {
		return base
	}
	return r.applyOverride(base)
}

// SightingFor implements the SightingFor half of the SignalEnricher
// interface. The recording enricher exists to exercise the Enrich
// path of handleEvaluateRequest, not the WS-4a sighting publish, so
// this stub returns (zero, false) which the publisher treats as a
// short-circuit (skip publish). Test files that exercise the
// publish path should use a dedicated fake that returns a populated
// CommHistoryUpdate.
func (r *recordingEnricher) SightingFor(_ context.Context, _ dto.EvaluateRequest) (dto.CommHistoryUpdate, bool) {
	return dto.CommHistoryUpdate{}, false
}

func (r *recordingEnricher) snapshot() []recordingEnricherCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]recordingEnricherCall, len(r.calls))
	copy(cp, r.calls)
	return cp
}

// TestHandleEvaluateRequest_InvokesSignalEnricher pins the consumer-
// side wiring: when app.signalEnricher is set, handleEvaluateRequest
// must invoke Enrich with the unmarshalled request and use the
// returned signals when calling the evaluator. The recording
// enricher captures the call and overrides TypicalSendHour so we
// can verify by side-effect that the enriched signals (not
// req.Signals) reached the downstream pipeline.
func TestHandleEvaluateRequest_InvokesSignalEnricher(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})

	typical := 9
	rec := &recordingEnricher{
		applyOverride: func(base dto.RiskSignals) dto.RiskSignals {
			h := typical
			out := base
			out.TypicalSendHour = &h
			out.CommunicationFrequency = 17
			out.CurrentHourUTC = 14
			return out
		},
	}
	app.signalEnricher = rec

	req := dto.EvaluateRequest{
		MessageID:     "msg-enrich-1",
		TenantID:      "t-enrich",
		CorrelationID: "corr-enrich",
		Sender:        "alice@partner.example",
		Recipient:     "bob@acme.test",
		Subject:       "Q3 invoice",
		Body:          "Please find attached.",
		Signals:       dto.RiskSignals{IsExternal: true},
		ReceivedAt:    time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload}); err != nil {
		t.Fatalf("handleEvaluateRequest: %v", err)
	}

	calls := rec.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one enricher call, got %d", len(calls))
	}
	if calls[0].req.MessageID != req.MessageID {
		t.Fatalf("enricher saw MessageID=%q, want %q", calls[0].req.MessageID, req.MessageID)
	}
	if !calls[0].base.IsExternal {
		t.Fatalf("enricher base signals lost the producer's IsExternal flag")
	}
	if len(bus.publishedSubjects()) != 1 {
		t.Fatalf("expected one published verdict, got %d", len(bus.publishedSubjects()))
	}
}

// TestHandleEvaluateRequest_NoopEnricherUsesRequestSignals pins the
// degraded-deployment contract: when the composition root has
// substituted evaluate.NoopEnricher (because the
// communication-histories repo or the PII hasher was not wired),
// the handler must pass req.Signals through unmodified. The
// production composition root and newTestApp both make the same
// guarantee that app.signalEnricher is always non-nil, so the
// handler can call Enrich unconditionally — this test exercises
// that contract end-to-end.
func TestHandleEvaluateRequest_NoopEnricherUsesRequestSignals(t *testing.T) {
	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})
	app.signalEnricher = evaluate.NoopEnricher{}

	req := dto.EvaluateRequest{
		MessageID:     "msg-noenrich",
		TenantID:      "t-noenrich",
		CorrelationID: "corr-noenrich",
		Sender:        "ext@x.test",
		Recipient:     "in@y.test",
		Subject:       "hi",
		Signals:       dto.RiskSignals{IsExternal: true},
		ReceivedAt:    time.Now().UTC(),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload}); err != nil {
		t.Fatalf("handleEvaluateRequest: %v", err)
	}
	if len(bus.publishedSubjects()) != 1 {
		t.Fatalf("expected one published verdict, got %d", len(bus.publishedSubjects()))
	}
}

func TestNoopEnricher_PassesBaseThrough(t *testing.T) {
	hour := 7
	base := dto.RiskSignals{
		SenderDomain:           "x.com",
		IsExternal:             true,
		TypicalSendHour:        &hour,
		CommunicationFrequency: 12,
		IsFirstContact:         true,
		CurrentHourUTC:         3,
	}
	out := evaluate.NoopEnricher{}.Enrich(context.Background(), dto.EvaluateRequest{}, base)
	if out.SenderDomain != "x.com" || !out.IsExternal {
		t.Fatalf("noop enricher must not mutate base fields: %+v", out)
	}
	if out.TypicalSendHour == nil || *out.TypicalSendHour != 7 {
		t.Fatalf("noop enricher must preserve TypicalSendHour pointer")
	}
}
