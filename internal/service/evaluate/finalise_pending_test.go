package evaluate

import (
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

// stubMsg is a minimal events.Message double for unit-testing the
// orchestrator's per-pending tail. It records Ack/Nak calls so the
// test can assert which terminal state finalisePending reached.
type stubMsg struct {
	mu       sync.Mutex
	subject  string
	data     []byte
	acked    bool
	nakedFor *time.Duration
}

func (m *stubMsg) Data() []byte               { return m.data }
func (m *stubMsg) Subject() string            { return m.subject }
func (m *stubMsg) Headers() map[string]string { return nil }
func (m *stubMsg) Ack() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acked = true
	return nil
}
func (m *stubMsg) Nak(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nakedFor = &d
	return nil
}
func (m *stubMsg) Metadata() (events.MessageMetadata, error) {
	return events.MessageMetadata{Subject: m.subject}, nil
}

// flakyResultSink fails the first Publish on the result subject and
// then records all subsequent publishes. Lets the test cover the
// "publishResult error → Nak, do NOT publish sighting" branch without
// also failing the sighting publish.
type flakyResultSink struct {
	mu                sync.Mutex
	failResultSubject string
	pubs              []recordedPublish
	resultFailed      bool
}

func (f *flakyResultSink) Publish(_ context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.resultFailed && subject == f.failResultSubject {
		f.resultFailed = true
		return errors.New("flaky result sink")
	}
	f.pubs = append(f.pubs, recordedPublish{
		subject: subject,
		data:    append([]byte(nil), data...),
		opts:    append([]events.PublishOption(nil), opts...),
	})
	return nil
}

func (f *flakyResultSink) snapshot() []recordedPublish {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedPublish, len(f.pubs))
	copy(out, f.pubs)
	return out
}

// TestBatchOrchestrator_FinalisePending_PublishesSightingOnSuccess
// pins the WS-4a coverage fix at the heart of this PR: when the
// batch orchestrator successfully publishes an EvaluateResult for a
// pending message, it MUST also publish the WS-4a sighting on
// es.management.comm_history.update with the deterministic dedup id
// derived from the same SignalEnricher.SightingFor() the per-message
// handler uses. Without this, the 4-hour relationship_worker cycle
// is the only writer of communication_histories for batch-mode
// tenants, defeating the entire point of WS-4a.
func TestBatchOrchestrator_FinalisePending_PublishesSightingOnSuccess(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	upd := validUpdate(t)
	o := &BatchOrchestrator{
		cfg: BatchOrchestratorConfig{
			Sink:          sink,
			ResultSubject: "es.evaluate.result",
			Enricher:      stubEnricher{upd: upd, ok: true},
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	msg := &stubMsg{subject: "es.evaluate.request"}
	req := dto.EvaluateRequest{TenantID: upd.TenantID, MessageID: upd.MessageID, CorrelationID: "corr-1"}
	res := dto.EvaluateResult{TenantID: upd.TenantID, MessageID: upd.MessageID}

	o.finalisePending(context.Background(), msg, req, res, "evaluate: publish result failed")

	if !msg.acked || msg.nakedFor != nil {
		t.Fatalf("msg state: acked=%v naked=%v, want acked=true naked=nil", msg.acked, msg.nakedFor)
	}
	got := sink.snapshot()
	if len(got) != 2 {
		t.Fatalf("Publish calls: got %d, want 2 (result + sighting)", len(got))
	}
	if got[0].subject != "es.evaluate.result" {
		t.Fatalf("first Publish: got subject %q, want es.evaluate.result", got[0].subject)
	}
	if got[1].subject != dto.CommHistoryUpdateSubject {
		t.Fatalf("second Publish: got subject %q, want %q", got[1].subject, dto.CommHistoryUpdateSubject)
	}
	hdrs := applyOpts(got[1].opts)
	if hdrs.MessageID != upd.DedupID() {
		t.Fatalf("sighting MessageID header: got %q, want %q (DedupID)", hdrs.MessageID, upd.DedupID())
	}
}

// TestBatchOrchestrator_FinalisePending_NakBlocksSightingPublish
// pins the failure-mode contract: if the EvaluateResult publish
// fails, the orchestrator NAKs the message AND must NOT publish the
// WS-4a sighting. Otherwise a sighting would record a verdict the
// downstream never sees, and the next redelivery would double-count
// the sighting at the broker (the same DedupID would fall within
// the dedup window so the broker collapses it — but the contract is
// still cleaner to skip the publish entirely on the failure branch).
func TestBatchOrchestrator_FinalisePending_NakBlocksSightingPublish(t *testing.T) {
	t.Parallel()
	sink := &flakyResultSink{failResultSubject: "es.evaluate.result"}
	upd := validUpdate(t)
	o := &BatchOrchestrator{
		cfg: BatchOrchestratorConfig{
			Sink:          sink,
			ResultSubject: "es.evaluate.result",
			Enricher:      stubEnricher{upd: upd, ok: true},
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	msg := &stubMsg{subject: "es.evaluate.request"}
	req := dto.EvaluateRequest{TenantID: upd.TenantID, MessageID: upd.MessageID}
	res := dto.EvaluateResult{TenantID: upd.TenantID, MessageID: upd.MessageID}

	o.finalisePending(context.Background(), msg, req, res, "evaluate: publish result failed")

	if msg.acked {
		t.Fatalf("msg should not be acked on publishResult failure")
	}
	if msg.nakedFor == nil {
		t.Fatalf("msg should be naked on publishResult failure")
	}
	if got := sink.snapshot(); len(got) != 0 {
		// The flaky sink fails on the result publish and the
		// helper returns early — neither result nor sighting
		// should land in the snapshot.
		t.Fatalf("sighting must not be published on result failure; got %d publishes", len(got))
	}
}

// TestBatchOrchestrator_FinalisePending_NoopEnricher pins the
// degraded-mode contract: a partially-wired orchestrator (no
// SignalEnricher, e.g. when the repository or PII hasher is not
// configured) still publishes the EvaluateResult — sighting publish
// just no-ops via the helper's enricher==nil short-circuit. This is
// the parity guarantee with the per-message path's same wiring.
func TestBatchOrchestrator_FinalisePending_NoopEnricher(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	o := &BatchOrchestrator{
		cfg: BatchOrchestratorConfig{
			Sink:          sink,
			ResultSubject: "es.evaluate.result",
			Enricher:      NoopEnricher{},
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	msg := &stubMsg{subject: "es.evaluate.request"}
	req := dto.EvaluateRequest{TenantID: "tenant-x", MessageID: "msg-y"}
	res := dto.EvaluateResult{TenantID: "tenant-x", MessageID: "msg-y"}

	o.finalisePending(context.Background(), msg, req, res, "evaluate: publish result failed")

	if !msg.acked {
		t.Fatalf("msg should be acked when result publish succeeds")
	}
	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("with NoopEnricher: got %d Publishes, want 1 (result only, no sighting)", len(got))
	}
	if got[0].subject != "es.evaluate.result" {
		t.Fatalf("the one Publish should be the result, got %q", got[0].subject)
	}
}
