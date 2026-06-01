// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/sinks/webhook"
)

// dlqIdentityEncryptor is a passthrough SecretEncryptor used by the
// DLQ tests so the handler exercises the production
// encrypt-decrypt-sign code path without a real KMS round-trip. The
// dispatcher_test in internal/service/webhooksink has a sibling
// identityEncryptor; we keep a local copy here so the cmd-package
// test stays in its own package without importing test helpers.
type dlqIdentityEncryptor struct{}

func (dlqIdentityEncryptor) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	cp := make([]byte, len(plaintext))
	copy(cp, plaintext)
	return cp, nil
}

func (dlqIdentityEncryptor) Decrypt(_ context.Context, _ string, ct []byte) ([]byte, error) {
	cp := make([]byte, len(ct))
	copy(cp, ct)
	return cp, nil
}

// dlqRecordingPublisher counts Publish invocations so the test can
// assert that the final-fail short-circuit does NOT POST. Calls
// return a benign retriable outcome — the test only inspects the
// invocation count, never the outcome.
type dlqRecordingPublisher struct {
	calls atomic.Int32
}

func (p *dlqRecordingPublisher) Publish(_ context.Context, _ *webhook.Request) (webhook.PublishResult, error) {
	p.calls.Add(1)
	return webhook.PublishResult{
		Outcome:    webhook.OutcomeRetriable,
		HTTPStatus: 503,
		LatencyMS:  1,
		Cause:      "test publisher invoked",
	}, nil
}

// dlqAckRecorder is a payloadMessage variant whose Metadata()
// returns a controllable NumDelivered and whose Ack / Nak record
// invocations so the test can assert the handler's terminal
// behaviour (the production payloadMessage is metadata-less and
// no-ops both verbs).
type dlqAckRecorder struct {
	data         []byte
	subject      string
	numDelivered uint64

	mu       sync.Mutex
	acked    int
	nakDelay []time.Duration
}

func (m *dlqAckRecorder) Data() []byte               { return m.data }
func (m *dlqAckRecorder) Subject() string            { return m.subject }
func (m *dlqAckRecorder) Headers() map[string]string { return nil }
func (m *dlqAckRecorder) Ack() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acked++
	return nil
}
func (m *dlqAckRecorder) Nak(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nakDelay = append(m.nakDelay, d)
	return nil
}
func (m *dlqAckRecorder) Metadata() (events.MessageMetadata, error) {
	return events.MessageMetadata{NumDelivered: m.numDelivered}, nil
}

// dlqTestFixture wires the bare-minimum application needed to drive
// handleWebhookDLQ end-to-end: one in-memory sink, a recording
// publisher, an identity encryptor, and a discard logger.
type dlqTestFixture struct {
	app *application
	pub *dlqRecordingPublisher

	tenantID string
	sinkID   string
}

func newDLQTestFixture(t *testing.T) *dlqTestFixture {
	t.Helper()
	reg := repository.NewInMemoryRegistry()
	tenantID := "t-dlq-final-fail"
	sink := &repository.WebhookSink{
		TenantID:             tenantID,
		Name:                 "primary",
		URL:                  "https://siem.example.com/ingest",
		HMACSecretCiphertext: []byte("00000000000000000000000000000000"),
		Format:               repository.WebhookSinkFormatECS,
		Enabled:              true,
	}
	if err := reg.WebhookSinks.Create(context.Background(), sink); err != nil {
		t.Fatalf("create sink: %v", err)
	}
	pub := &dlqRecordingPublisher{}
	return &dlqTestFixture{
		app: &application{
			logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
			repos:            reg,
			encryptor:        dlqIdentityEncryptor{},
			webhookPublisher: pub,
		},
		pub:      pub,
		tenantID: tenantID,
		sinkID:   sink.ID,
	}
}

// envelopeJSON returns a marshalled DLQEnvelope referencing fx.sink
// with the supplied event ID. Body content is irrelevant — the
// short-circuit happens before re-sign / re-encode, and the
// happy-path retry test only cares that Publish is invoked.
func (fx *dlqTestFixture) envelopeJSON(t *testing.T, eventID string) []byte {
	t.Helper()
	env := &webhook.DLQEnvelope{
		SchemaVersion: webhook.DLQEnvelopeSchemaVersion,
		SinkID:        fx.sinkID,
		TenantID:      fx.tenantID,
		SinkName:      "primary",
		URL:           "https://siem.example.com/ingest",
		Format:        repository.WebhookSinkFormatECS,
		EventType:     webhook.EventTypeEmailEvaluation,
		EventID:       eventID,
		OccurredAt:    time.Now().UTC(),
		Body:          []byte(`{"event":"placeholder"}`),
		Signature:     "sha256=placeholder",
		Attempt:       1,
		FirstFailedAt: time.Now().UTC(),
		LastCause:     "http 500: upstream",
		LastStatus:    500,
	}
	data, err := env.Marshal()
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

// TestHandleWebhookDLQ_FinalDelivery_SkipsPOST locks in the
// short-circuit contract documented at the top of
// consumers_webhook_dlq.go: on the terminal JetStream delivery
// (NumDelivered == webhookDLQMaxDeliver), the handler must NOT
// invoke the webhook publisher — POSTing here would burn a 6th
// customer-facing attempt past the documented 5-attempt budget (1
// dispatcher publish + 4 DLQ retries). Instead the handler must
// write a dispatch_failed audit row and Ack out of the queue.
func TestHandleWebhookDLQ_FinalDelivery_SkipsPOST(t *testing.T) {
	fx := newDLQTestFixture(t)
	msg := &dlqAckRecorder{
		data:         fx.envelopeJSON(t, "evt-final"),
		subject:      "sn360.dlq.webhook." + fx.tenantID + "." + fx.sinkID,
		numDelivered: uint64(webhookDLQMaxDeliver),
	}

	if err := fx.app.handleWebhookDLQ(context.Background(), msg); err != nil {
		t.Fatalf("handleWebhookDLQ on final delivery returned err: %v", err)
	}

	if got := fx.pub.calls.Load(); got != 0 {
		t.Errorf("Publish call count on final delivery: got %d, want 0 (short-circuit must skip POST so the customer never sees a 6th attempt past the documented 5-attempt budget)", got)
	}
	if msg.acked != 1 {
		t.Errorf("Ack count on final delivery: got %d, want 1 (final-fail must drain the message from the DLQ stream)", msg.acked)
	}
	if len(msg.nakDelay) != 0 {
		t.Errorf("Nak count on final delivery: got %d, want 0 (Naking after MaxDeliver is meaningless and only delays the inevitable drop)", len(msg.nakDelay))
	}

	auditRows, err := fx.app.repos.WebhookSinks.ListAudit(context.Background(), fx.tenantID, 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(auditRows) != 1 {
		t.Fatalf("audit row count: got %d, want 1; rows=%+v", len(auditRows), auditRows)
	}
	row := auditRows[0]
	if row.Action != repository.WebhookSinkAuditActionDispatchFailed {
		t.Errorf("audit action: got %q, want %q", row.Action, repository.WebhookSinkAuditActionDispatchFailed)
	}
	const wantPrefix = "dlq final fail after max attempts"
	if got := row.Reason; len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Errorf("audit reason: got %q, want prefix %q", got, wantPrefix)
	}
}

// TestHandleWebhookDLQ_MidDelivery_POSTsAndNaks covers the
// complement of the short-circuit: on any non-final delivery the
// handler still invokes the publisher and (for a retriable
// outcome) Naks with a backoff. This guards against an over-eager
// future refactor that lifts the short-circuit out of the
// MaxDeliver bound and accidentally skips the POST on every
// delivery.
func TestHandleWebhookDLQ_MidDelivery_POSTsAndNaks(t *testing.T) {
	fx := newDLQTestFixture(t)
	msg := &dlqAckRecorder{
		data:         fx.envelopeJSON(t, "evt-mid"),
		subject:      "sn360.dlq.webhook." + fx.tenantID + "." + fx.sinkID,
		numDelivered: 1, // first DLQ delivery → publisher must run
	}

	if err := fx.app.handleWebhookDLQ(context.Background(), msg); err != nil {
		t.Fatalf("handleWebhookDLQ on mid delivery returned err: %v", err)
	}

	if got := fx.pub.calls.Load(); got != 1 {
		t.Errorf("Publish call count on first DLQ delivery: got %d, want 1", got)
	}
	if msg.acked != 0 {
		t.Errorf("Ack count on mid delivery (retriable outcome): got %d, want 0", msg.acked)
	}
	if len(msg.nakDelay) != 1 {
		t.Fatalf("Nak count on mid delivery: got %d, want 1", len(msg.nakDelay))
	}
	if got, want := msg.nakDelay[0], webhookDLQBackoffs[0]; got != want {
		t.Errorf("Nak delay on first DLQ delivery: got %v, want %v (backoffs[0])", got, want)
	}
}

// TestHandleWebhookDLQ_FinalDeliveryWritesTerminalAudit_OncePerEnvelope
// guards the dedup key shape: the terminal audit reason is a fixed
// string (no varying result.Cause) so a second JetStream delivery
// at NumDelivered == MaxDeliver — possible only under a misbehaving
// stream that retries past the terminal Ack — collapses on the
// dedup key instead of writing a duplicate dispatch_failed row.
func TestHandleWebhookDLQ_FinalDeliveryWritesTerminalAudit_OncePerEnvelope(t *testing.T) {
	fx := newDLQTestFixture(t)
	msgA := &dlqAckRecorder{
		data:         fx.envelopeJSON(t, "evt-dup"),
		subject:      "sn360.dlq.webhook." + fx.tenantID + "." + fx.sinkID,
		numDelivered: uint64(webhookDLQMaxDeliver),
	}
	msgB := &dlqAckRecorder{
		data:         fx.envelopeJSON(t, "evt-dup"),
		subject:      "sn360.dlq.webhook." + fx.tenantID + "." + fx.sinkID,
		numDelivered: uint64(webhookDLQMaxDeliver),
	}

	for i, m := range []*dlqAckRecorder{msgA, msgB} {
		if err := fx.app.handleWebhookDLQ(context.Background(), m); err != nil {
			t.Fatalf("handleWebhookDLQ delivery %d: %v", i+1, err)
		}
	}

	if got := fx.pub.calls.Load(); got != 0 {
		t.Errorf("Publish call count across duplicate final deliveries: got %d, want 0", got)
	}
	auditRows, err := fx.app.repos.WebhookSinks.ListAudit(context.Background(), fx.tenantID, 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	// Dedup is enforced at the repository layer via
	// WebhookSinkAuditEntry.DedupID; a second appendDLQAudit for
	// the same envelope identity (sink, event, attempt) — even
	// with a slightly different reason string — must collapse to
	// one row.
	if len(auditRows) != 1 {
		t.Errorf("audit row count across duplicate final deliveries: got %d, want 1 (dedup must collapse)", len(auditRows))
	}
}

// TestAppendDLQAudit_DedupIgnoresReasonText guards the dedup-key
// shape directly: two appendDLQAudit calls for the SAME envelope
// identity (tenant, sink, event, attempt) with DIFFERENT reason
// strings must still collapse to a single audit row. This protects
// against an Ack-loss + JetStream redelivery where the customer
// endpoint returns slightly different error bodies on retry (e.g.
// embedded timestamps, retry-ids, request-ids) — the bounded
// `result.Cause` snippet flows into the audit Reason column, but
// MUST NOT be folded into the dedup key, or a duplicate
// `dispatch_failed` row appears for the same logical event.
func TestAppendDLQAudit_DedupIgnoresReasonText(t *testing.T) {
	fx := newDLQTestFixture(t)
	env := &webhook.DLQEnvelope{
		SchemaVersion: webhook.DLQEnvelopeSchemaVersion,
		SinkID:        fx.sinkID,
		TenantID:      fx.tenantID,
		SinkName:      "primary",
		URL:           "https://siem.example.com/ingest",
		Format:        repository.WebhookSinkFormatECS,
		EventType:     webhook.EventTypeEmailEvaluation,
		EventID:       "evt-reason-drift",
		OccurredAt:    time.Now().UTC(),
		Attempt:       1,
	}

	// First terminal observation — represents the originally-Ack'd
	// permanent-failure path with the customer's first response body.
	fx.app.appendDLQAudit(context.Background(), env, "permanent: http 500 upstream timeout at t=1700000001")
	// JetStream Ack-loss → handler runs again on redelivery. The
	// customer endpoint returns a slightly different body on retry,
	// which would (under a reason-inclusive dedup key) produce a
	// second row.
	fx.app.appendDLQAudit(context.Background(), env, "permanent: http 500 upstream timeout at t=1700000037")

	auditRows, err := fx.app.repos.WebhookSinks.ListAudit(context.Background(), fx.tenantID, 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(auditRows) != 1 {
		t.Fatalf("audit row count with reason-drift redelivery: got %d, want 1 (reason MUST NOT be in dedup key)", len(auditRows))
	}
	// The first-writer-wins row is preserved; the second call is a
	// no-op so the original Reason text survives.
	if got, want := auditRows[0].Reason, "dlq permanent: http 500 upstream timeout at t=1700000001"; got != want {
		t.Errorf("preserved Reason: got %q, want %q (first-writer-wins)", got, want)
	}
}
