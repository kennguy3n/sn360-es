package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// failingResultBus is a stripped-down events.EventService that
// fails Publish for a configured subject pattern (default
// "es.evaluate.result") and records every Publish attempt — even
// the failed one — so a test can assert which subjects were
// attempted in order.
type failingResultBus struct {
	mu                  sync.Mutex
	failSubjectContains string
	attempts            []recordedPublish
}

func (b *failingResultBus) Publish(_ context.Context, subject string, data []byte, _ ...events.PublishOption) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempts = append(b.attempts, recordedPublish{
		Subject: subject,
		Payload: append([]byte(nil), data...),
	})
	if b.failSubjectContains != "" && strings.Contains(subject, b.failSubjectContains) {
		return errors.New("simulated bus failure for " + subject)
	}
	return nil
}

func (b *failingResultBus) Subscribe(_ context.Context, _ string, _ events.MessageHandler, _ ...events.SubscribeOption) (events.Subscription, error) {
	return nil, errors.New("failingResultBus: Subscribe not supported")
}

func (b *failingResultBus) Health(_ context.Context) error { return nil }
func (b *failingResultBus) Close() error                   { return nil }

func (b *failingResultBus) attemptedSubjects() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.attempts))
	for i, p := range b.attempts {
		out[i] = p.Subject
	}
	return out
}

// TestWS4A_SightingPublishOrderingFollowsResult pins the per-message
// path's ordering contract caught in Devin Review round 2 on PR #61:
// the WS-4a sighting publish onto es.management.comm_history.update
// must land AFTER the es.evaluate.result publish succeeds, not before.
//
// Rationale (from the ordering contract comment in
// handleEvaluateRequest): if the sighting publish ran before the
// result publish and the result publish then failed, JetStream would
// NAK the upstream evaluate.request envelope and redeliver after the
// dedup window potentially expired, producing an orphaned
// communication_histories increment for a message whose result was
// never published. Mirroring the batch path's finalisePending tail
// (internal/service/evaluate/batch.go) — publish result, then
// publish sighting — closes that gap.
func TestWS4A_SightingPublishOrderingFollowsResult(t *testing.T) {
	t.Parallel()

	bus := &recordingBus{}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})

	repo := newFakeCommHistoryRepo()
	app.signalEnricher = newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())

	req := dto.EvaluateRequest{
		MessageID:     "msg-ordering-1",
		TenantID:      "t-ordering",
		CorrelationID: "corr-ordering-1",
		Sender:        "alice@partner.example",
		Recipient:     "bob@acme.test",
		Signals:       dto.RiskSignals{IsExternal: true, SenderDomain: "partner.example"},
		ReceivedAt:    time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload}); err != nil {
		t.Fatalf("handleEvaluateRequest: %v", err)
	}

	subjects := bus.publishedSubjects()
	if len(subjects) != 2 {
		t.Fatalf("expected exactly 2 publishes (result + sighting), got %d: %v",
			len(subjects), subjects)
	}
	if subjects[0] != "es.evaluate.result" {
		t.Fatalf("first publish must be es.evaluate.result; got %q", subjects[0])
	}
	if subjects[1] != dto.CommHistoryUpdateSubject {
		t.Fatalf("second publish must be %s; got %q",
			dto.CommHistoryUpdateSubject, subjects[1])
	}
}

// TestWS4A_SightingPublishSkippedWhenResultPublishFails pins the
// per-message path's failure-mode contract: if the
// es.evaluate.result publish fails, the WS-4a sighting MUST NOT be
// emitted — JetStream redelivers the upstream evaluate.request
// envelope and the (result, sighting) pair runs again as a unit on
// retry. Emitting the sighting on the failure branch would orphan a
// communication_histories increment for a message whose verdict
// was never delivered.
//
// This is the symmetry guarantee the round-2 review called out: the
// batch path's finalisePending tail (internal/service/evaluate/
// batch.go) already implements this exact ordering and skip-on-
// failure semantics; this test pins the per-message side so the two
// paths cannot drift again.
func TestWS4A_SightingPublishSkippedWhenResultPublishFails(t *testing.T) {
	t.Parallel()

	bus := &failingResultBus{failSubjectContains: "es.evaluate.result"}
	app := newTestApp(t)
	app.eventBus = bus
	app.evaluator = buildEvaluator(t, fakeTier1{score: 30})

	repo := newFakeCommHistoryRepo()
	app.signalEnricher = newCommHistorySignalEnricher(repo, fakeHasher{}, discardLogger())

	req := dto.EvaluateRequest{
		MessageID:     "msg-orphan-guard-1",
		TenantID:      "t-orphan-guard",
		CorrelationID: "corr-orphan-guard-1",
		Sender:        "alice@partner.example",
		Recipient:     "bob@acme.test",
		Signals:       dto.RiskSignals{IsExternal: true, SenderDomain: "partner.example"},
		ReceivedAt:    time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	err = app.handleEvaluateRequest(context.Background(), payloadMessage{data: payload})
	if err == nil {
		t.Fatalf("handleEvaluateRequest must return an error when result publish fails so JetStream NAKs and redelivers; got nil")
	}

	attempted := bus.attemptedSubjects()
	if len(attempted) != 1 {
		t.Fatalf("expected exactly 1 Publish attempt (the failed result publish, and NO sighting attempt); got %d: %v",
			len(attempted), attempted)
	}
	if attempted[0] != "es.evaluate.result" {
		t.Fatalf("the one Publish attempt must be the result publish; got %q", attempted[0])
	}
	for _, s := range attempted {
		if s == dto.CommHistoryUpdateSubject {
			t.Fatalf("WS-4a sighting must NOT be published when result publish fails; attempted=%v", attempted)
		}
	}
}
