package evaluate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// recordedPublish is one Publish call observed by recordingSink.
type recordedPublish struct {
	subject string
	data    []byte
	opts    []events.PublishOption
}

// recordingSink captures every Publish call so the test can assert on
// the subject, payload, and options the WS-4a helper picked. It
// satisfies evaluate.Sink (the in-package Publish interface
// BatchOrchestrator and the per-message handler both consume).
type recordingSink struct {
	mu   sync.Mutex
	pubs []recordedPublish
	err  error
}

func (r *recordingSink) Publish(_ context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pubs = append(r.pubs, recordedPublish{
		subject: subject,
		data:    append([]byte(nil), data...),
		opts:    append([]events.PublishOption(nil), opts...),
	})
	return r.err
}

func (r *recordingSink) snapshot() []recordedPublish {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedPublish, len(r.pubs))
	copy(out, r.pubs)
	return out
}

// stubEnricher returns a fixed CommHistoryUpdate. It is the minimum
// SignalEnricher the helper needs — Enrich is required by the
// interface but the helper never calls it.
type stubEnricher struct {
	upd dto.CommHistoryUpdate
	ok  bool
}

func (s stubEnricher) Enrich(_ context.Context, _ dto.EvaluateRequest, base dto.RiskSignals) dto.RiskSignals {
	return base
}

func (s stubEnricher) SightingFor(_ context.Context, _ dto.EvaluateRequest) (dto.CommHistoryUpdate, bool) {
	return s.upd, s.ok
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func validUpdate(t *testing.T) dto.CommHistoryUpdate {
	t.Helper()
	return dto.CommHistoryUpdate{
		TenantID:         "tenant-1",
		MessageID:        "msg-7",
		SenderHash:       []byte("sha-sender"),
		RecipientHash:    []byte("sha-recipient"),
		SenderDomainHash: []byte("sha-dom"),
		SenderDomain:     "example.com",
		SentAt:           time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
	}
}

// TestPublishCommHistoryUpdate_HappyPath pins the shared publisher
// path that both handleEvaluateRequest and the batch orchestrator
// consume: a successful SightingFor + valid update produces exactly
// one Publish on dto.CommHistoryUpdateSubject with the deterministic
// dedup id bound to the (tenant, sender, recipient, message_id)
// tuple.
func TestPublishCommHistoryUpdate_HappyPath(t *testing.T) {
	t.Parallel()
	upd := validUpdate(t)
	sink := &recordingSink{}
	en := stubEnricher{upd: upd, ok: true}
	req := dto.EvaluateRequest{
		TenantID:      upd.TenantID,
		MessageID:     upd.MessageID,
		CorrelationID: "corr-9",
	}
	PublishCommHistoryUpdate(context.Background(), sink, en, quietLogger(), req)
	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("Publish calls: got %d, want 1", len(got))
	}
	if got[0].subject != dto.CommHistoryUpdateSubject {
		t.Fatalf("subject: got %q, want %q", got[0].subject, dto.CommHistoryUpdateSubject)
	}
	// Spot-check that the marshalled JSON includes the tenant id
	// and the sender domain — the marshaller-level shape itself is
	// covered by internal/dto/comm_history_test.go.
	if !bytes.Contains(got[0].data, []byte("tenant-1")) {
		t.Fatalf("payload missing tenant_id: %q", got[0].data)
	}
	if !bytes.Contains(got[0].data, []byte("example.com")) {
		t.Fatalf("payload missing sender_domain: %q", got[0].data)
	}
	// The options must include a MessageID header equal to the
	// CommHistoryUpdate's DedupID (so JetStream's broker dedup
	// window collapses redeliveries) and a TenantID header equal
	// to the update's tenant id. We can't introspect PublishOption
	// without applying it to a builder; build the options against a
	// dummy PublishOptions struct so the test sees what production
	// would.
	hdrs := applyOpts(got[0].opts)
	if hdrs.MessageID != upd.DedupID() {
		t.Fatalf("MessageID header: got %q, want %q (DedupID)", hdrs.MessageID, upd.DedupID())
	}
	if hdrs.TenantID != upd.TenantID {
		t.Fatalf("TenantID header: got %q, want %q", hdrs.TenantID, upd.TenantID)
	}
	if hdrs.CorrelationID != req.CorrelationID {
		t.Fatalf("CorrelationID header: got %q, want %q", hdrs.CorrelationID, req.CorrelationID)
	}
	if hdrs.EventType != "management.comm_history.update" {
		t.Fatalf("EventType header: got %q, want %q", hdrs.EventType, "management.comm_history.update")
	}
}

// TestPublishCommHistoryUpdate_ShortCircuitsOnFalse covers the
// NoopEnricher / incomplete-request path: when SightingFor returns
// (zero, false), the helper must NOT publish anything (the consumer
// is downstream of the per-relationship lookup, so a sighting with
// empty (tenant, sender, recipient) would write a row that never
// matches a read-path Get and would silently corrupt the table).
func TestPublishCommHistoryUpdate_ShortCircuitsOnFalse(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	en := stubEnricher{ok: false}
	PublishCommHistoryUpdate(context.Background(), sink, en, quietLogger(), dto.EvaluateRequest{TenantID: "t", MessageID: "m"})
	if got := sink.snapshot(); len(got) != 0 {
		t.Fatalf("Publish should be skipped when SightingFor returns false, got %d publishes", len(got))
	}
}

// TestPublishCommHistoryUpdate_DropsInvalidUpdate pins the
// defense-in-depth Validate gate: if SightingFor returns (upd, true)
// but the update is incomplete, the helper must NOT publish (the
// consumer would have to log + drop the message anyway since
// Validate is mandatory upstream of RecordSighting).
func TestPublishCommHistoryUpdate_DropsInvalidUpdate(t *testing.T) {
	t.Parallel()
	bad := validUpdate(t)
	bad.SenderHash = nil // breaks Validate
	sink := &recordingSink{}
	en := stubEnricher{upd: bad, ok: true}
	PublishCommHistoryUpdate(context.Background(), sink, en, quietLogger(), dto.EvaluateRequest{TenantID: bad.TenantID, MessageID: bad.MessageID})
	if got := sink.snapshot(); len(got) != 0 {
		t.Fatalf("Publish should be skipped for invalid update, got %d publishes", len(got))
	}
}

// TestPublishCommHistoryUpdate_SwallowsSinkError pins the
// best-effort contract: a sink that errors must not surface to the
// caller (which is on the hot path of either handleEvaluateRequest
// or BatchOrchestrator and treating this as a hard error would NAK
// the upstream envelope and produce a duplicate evaluate.result).
func TestPublishCommHistoryUpdate_SwallowsSinkError(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{err: errors.New("bus down")}
	en := stubEnricher{upd: validUpdate(t), ok: true}
	// Should not panic and should not surface the error. The fact
	// that the helper returns no value AND the test reaches its
	// final line is the assertion.
	PublishCommHistoryUpdate(context.Background(), sink, en, quietLogger(), dto.EvaluateRequest{TenantID: "tenant-1", MessageID: "msg-7"})
	if got := sink.snapshot(); len(got) != 1 {
		t.Fatalf("sink should still be called once even on error; got %d publishes", len(got))
	}
}

// TestPublishCommHistoryUpdate_TolerantOnNilDependencies pins the
// composition-root contract: a partially-wired deployment (no
// enricher, no sink) is a no-op rather than a panic. The
// per-message handler and the orchestrator both call this helper
// unconditionally from the hot path, so a panic here would be a
// production crash on every message.
func TestPublishCommHistoryUpdate_TolerantOnNilDependencies(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("helper must not panic with nil deps; got %v", r)
		}
	}()
	// nil sink
	PublishCommHistoryUpdate(context.Background(), nil, stubEnricher{upd: validUpdate(t), ok: true}, quietLogger(), dto.EvaluateRequest{})
	// nil enricher
	PublishCommHistoryUpdate(context.Background(), &recordingSink{}, nil, quietLogger(), dto.EvaluateRequest{})
	// nil logger (helper substitutes slog.Default())
	PublishCommHistoryUpdate(context.Background(), &recordingSink{}, stubEnricher{ok: false}, nil, dto.EvaluateRequest{})
}

// extractedHeaders mirrors the subset of events.PublishOptions the
// helper sets. Reading them back out requires applying the captured
// options to a PublishOptions struct since PublishOption is opaque
// otherwise.
type extractedHeaders struct {
	MessageID     string
	TenantID      string
	CorrelationID string
	EventType     string
}

func applyOpts(opts []events.PublishOption) extractedHeaders {
	po := &events.PublishOptions{}
	for _, o := range opts {
		o(po)
	}
	return extractedHeaders{
		MessageID:     po.MessageID,
		TenantID:      po.TenantID,
		CorrelationID: po.CorrelationID,
		EventType:     po.EventType,
	}
}
