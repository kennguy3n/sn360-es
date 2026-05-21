//go:build integration
// +build integration

package ingestion_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tcnats "github.com/testcontainers/testcontainers-go/modules/nats"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
	"github.com/kennguy3n/sn360-es/pkg/events"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
)

// fakeProvider serves a single static batch of raw emails and records
// the (tenant, mailbox) pairs the poller asked it to enumerate. It is
// the moral equivalent of a Gmail/Outlook MailboxProvider but
// deterministic and free of HTTP / OAuth.
type fakeProvider struct {
	mu        sync.Mutex
	mailboxes []ingestion.Mailbox
	emails    map[string][]ingestion.RawEmail // keyed by mailbox address
	calls     atomic.Int32
}

func (f *fakeProvider) Kind() string { return "fake" }

func (f *fakeProvider) ListMailboxes(_ context.Context, _ string) ([]ingestion.Mailbox, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ingestion.Mailbox, len(f.mailboxes))
	copy(out, f.mailboxes)
	return out, nil
}

func (f *fakeProvider) FetchNew(_ context.Context, m ingestion.Mailbox, _ time.Time, limit int) ([]ingestion.RawEmail, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	batch := f.emails[m.Address]
	if limit > 0 && len(batch) > limit {
		batch = batch[:limit]
	}
	out := make([]ingestion.RawEmail, len(batch))
	copy(out, batch)
	// One-shot: subsequent polls should see no new mail so the
	// test does not race with itself.
	f.emails[m.Address] = nil
	return out, nil
}

// fakeEvaluator turns every request into a deterministic HighRisk
// verdict so the action fan-out exercises a non-trivial path. It is
// intentionally lighter-weight than evaluate.NewEvaluator so the test
// does not require Tier 0 / Tier 1 / categoriser wiring.
type fakeEvaluator struct {
	called atomic.Int32
}

func (f *fakeEvaluator) Evaluate(_ context.Context, req dto.EvaluateRequest, _ dto.RiskSignals) dto.EvaluateResult {
	f.called.Add(1)
	return dto.EvaluateResult{
		MessageID:     req.MessageID,
		TenantID:      req.TenantID,
		CorrelationID: req.CorrelationID,
		Recipient:     req.Recipient,
		EvaluatedAt:   time.Now().UTC(),
		Score:         90,
		Tier:          constant.TierHighRisk,
		Primary:       constant.CategoryLikelyPhishing,
		ReasonCodes:   []string{"e2e_test"},
	}
}

func startNATSService(t *testing.T) *natsbus.Service {
	t.Helper()
	c, err := tcnats.Run(context.Background(), "nats:2.10-alpine")
	if err != nil {
		if strings.Contains(err.Error(), "docker") || errors.Is(err, context.Canceled) {
			t.Skipf("docker not available, skipping: %v", err)
		}
		t.Fatalf("start container: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	url, err := c.ConnectionString(context.Background())
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	cfg := natsbus.DefaultConfig()
	cfg.URL = url
	cfg.Storage = "memory"
	cfg.Replicas = 1
	svc, err := natsbus.NewService(context.Background(), cfg, "ingestion-e2e",
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// TestE2E_IngestionToEvaluateToAction is the first true end-to-end
// integration test that covers the full pipeline from a mailbox to
// a provider-side action signal, end-to-end through the JetStream
// event bus.
//
// The test runs against a NATS testcontainer and exercises:
//
//  1. A fake MailboxProvider feeds the ingestion.Poller a synthetic
//     phishing-shaped email.
//  2. The poller normalises the message and publishes
//     `es.evaluate.request` on the bus.
//  3. A subscriber acts as the evaluator: it runs the message
//     through a fake evaluator, then publishes the verdict on the
//     four action subjects (`es.action.label`, `es.action.banner`,
//     `es.action.url_rewrite`, `es.action.quarantine`).
//  4. Four parallel subscribers act as the provider-side action
//     consumers and record receipt.
//
// The assertion is that every step of the chain produced its
// expected output within the test deadline.
func TestE2E_IngestionToEvaluateToAction(t *testing.T) {
	svc := startNATSService(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. Subscribers for the four action subjects. Each one records
	//    its received envelope so we can assert on it later. We
	//    subscribe before publishing anything so the JetStream
	//    consumer-group filters are in place when the first message
	//    flows.
	type record struct {
		subject string
		body    []byte
	}
	actionCh := make(chan record, 16)
	for _, sub := range []string{
		"es.action.label",
		"es.action.banner",
		"es.action.url_rewrite",
		"es.action.quarantine",
	} {
		subject := sub
		s, err := svc.Subscribe(ctx, subject,
			func(_ context.Context, m events.Message) error {
				actionCh <- record{subject: subject, body: append([]byte(nil), m.Data()...)}
				return nil
			},
			events.WithDurable("e2e-action-"+strings.ReplaceAll(strings.TrimPrefix(subject, "es.action."), "_", "-")),
		)
		if err != nil {
			t.Fatalf("subscribe %s: %v", subject, err)
		}
		defer s.Close()
	}

	// 2. The evaluator subscriber: drain es.evaluate.request, run
	//    the fake evaluator, fan out four action signals. This is
	//    a faithful (if compressed) simulation of what
	//    cmd/sn360-es/main.go does in StartConsumers.
	eval := &fakeEvaluator{}
	evalSub, err := svc.Subscribe(ctx, "es.evaluate.request",
		func(c context.Context, m events.Message) error {
			var req dto.EvaluateRequest
			if err := json.Unmarshal(m.Data(), &req); err != nil {
				return err
			}
			res := eval.Evaluate(c, req, req.Signals)
			body, _ := json.Marshal(res)
			for _, action := range []string{
				"es.action.label",
				"es.action.banner",
				"es.action.url_rewrite",
				"es.action.quarantine",
			} {
				// JetStream deduplicates by message-id within the
				// stream's dedup window. The four action subjects
				// share the same EvaluateResult.MessageID, so we
				// derive a unique dedup ID per action subject to
				// keep all four fan-out messages.
				if err := svc.Publish(c, action, body,
					events.WithTenantID(res.TenantID),
					events.WithMessageID(res.MessageID+":"+action),
					events.WithCorrelationID(res.CorrelationID),
				); err != nil {
					return err
				}
			}
			return nil
		},
		events.WithDurable("e2e-evaluate"),
	)
	if err != nil {
		t.Fatalf("subscribe es.evaluate.request: %v", err)
	}
	defer evalSub.Close()

	// 3. Construct the Poller against a fake provider. The
	//    provider returns one raw email; the Poller is expected to
	//    normalise it, publish an es.evaluate.request, and advance
	//    its internal checkpoint.
	mailbox := ingestion.Mailbox{
		TenantID: "tenant-e2e",
		Address:  "finance@acme.test",
	}
	prov := &fakeProvider{
		mailboxes: []ingestion.Mailbox{mailbox},
		emails: map[string][]ingestion.RawEmail{
			mailbox.Address: {{
				ProviderMessageID: "msg-e2e-001",
				TenantID:          mailbox.TenantID,
				Mailbox:           mailbox.Address,
				Sender:            "ceo-impostor@example.com",
				Recipients:        []string{mailbox.Address},
				Subject:           "URGENT: wire transfer",
				Body:              "Please wire $50k today",
				Headers: map[string]string{
					"Authentication-Results": "spf=fail dkim=none dmarc=fail",
				},
				ReceivedAt: time.Now().UTC(),
			}},
		},
	}
	poller, err := ingestion.New(ingestion.PollerConfig{
		Providers: []ingestion.MailboxProvider{prov},
		Publisher: svc,
		TenantIDs: []string{mailbox.TenantID},
		// Tight interval + concurrency=1 so RunOnce drains the
		// single mailbox synchronously.
		Interval:    50 * time.Millisecond,
		BatchSize:   16,
		Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("new poller: %v", err)
	}
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("run once: %v", err)
	}

	// 4. Wait for all four action subjects to fire. The fan-out
	//    fires four messages per evaluate request, so we expect
	//    four records on the channel.
	seen := map[string]int{}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for total := 0; total < 4; {
		select {
		case rec := <-actionCh:
			seen[rec.subject]++
			total++
			var res dto.EvaluateResult
			if err := json.Unmarshal(rec.body, &res); err != nil {
				t.Fatalf("decode %s payload: %v", rec.subject, err)
			}
			if res.MessageID != "msg-e2e-001" {
				t.Fatalf("%s: wrong message id %q", rec.subject, res.MessageID)
			}
			if res.Tier != constant.TierHighRisk {
				t.Fatalf("%s: wrong tier %q", rec.subject, res.Tier)
			}
			if res.Primary != constant.CategoryLikelyPhishing {
				t.Fatalf("%s: wrong primary %q", rec.subject, res.Primary)
			}
		case <-deadline.C:
			t.Fatalf("timed out after seeing %d/4 action signals: %v", total, seen)
		case <-ctx.Done():
			t.Fatalf("context cancelled while waiting for action signals: %v", ctx.Err())
		}
	}

	// 5. Final assertions: the poller called the provider exactly
	//    once and the evaluator ran exactly once.
	if got := prov.calls.Load(); got != 1 {
		t.Fatalf("expected provider FetchNew to be called once, got %d", got)
	}
	if got := eval.called.Load(); got != 1 {
		t.Fatalf("expected fake evaluator to be called once, got %d", got)
	}
	for _, sub := range []string{
		"es.action.label",
		"es.action.banner",
		"es.action.url_rewrite",
		"es.action.quarantine",
	} {
		if seen[sub] != 1 {
			t.Errorf("subject %s: expected 1 message, got %d", sub, seen[sub])
		}
	}
}

// TestE2E_IngestionEmptyMailboxDoesNotPublish proves the second
// half of the contract: when the provider has no new mail, the
// poller MUST NOT publish anything on the request subject. This
// asserts the "graceful no-op when no new messages" path is correct
// — a bug here would generate spurious empty evaluate requests on
// every poll cycle.
func TestE2E_IngestionEmptyMailboxDoesNotPublish(t *testing.T) {
	svc := startNATSService(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var received atomic.Int32
	sub, err := svc.Subscribe(ctx, "es.evaluate.request",
		func(_ context.Context, _ events.Message) error {
			received.Add(1)
			return nil
		},
		events.WithDurable("e2e-empty"),
	)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	mailbox := ingestion.Mailbox{
		TenantID: "tenant-empty",
		Address:  "nobody@acme.test",
	}
	prov := &fakeProvider{
		mailboxes: []ingestion.Mailbox{mailbox},
		emails:    map[string][]ingestion.RawEmail{}, // no messages
	}
	poller, err := ingestion.New(ingestion.PollerConfig{
		Providers:   []ingestion.MailboxProvider{prov},
		Publisher:   svc,
		TenantIDs:   []string{mailbox.TenantID},
		Interval:    50 * time.Millisecond,
		Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("new poller: %v", err)
	}
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("run once: %v", err)
	}

	// Give the bus a brief grace period to deliver anything the
	// poller might have published before asserting silence.
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
		t.Fatalf("context cancelled: %v", ctx.Err())
	}
	if got := received.Load(); got != 0 {
		t.Fatalf("expected zero evaluate.request messages, got %d", got)
	}
	if got := prov.calls.Load(); got != 1 {
		t.Fatalf("expected provider FetchNew to be called once, got %d", got)
	}
	_ = evaluate.NewEvaluator
}
