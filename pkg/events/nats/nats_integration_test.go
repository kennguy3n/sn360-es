//go:build integration
// +build integration

package nats_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	tcnats "github.com/testcontainers/testcontainers-go/modules/nats"

	"github.com/kennguy3n/sn360-es/pkg/events"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
)

// startNATS spins up a single-node JetStream-enabled NATS server via
// testcontainers-go and returns its URL. The container is torn down at
// test cleanup. Tests that cannot start Docker are skipped so the suite
// keeps working in restricted CI sandboxes.
func startNATS(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	c, err := tcnats.Run(ctx, "nats:2.10-alpine",
		tcnats.WithArgument("jetstream", ""),
	)
	if err != nil {
		if errors.Is(err, context.Canceled) || isDockerUnavailable(err) {
			t.Skipf("docker not available, skipping: %v", err)
		}
		t.Fatalf("start nats: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Terminate(context.Background())
	})
	url, err := c.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	return url
}

func isDockerUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{
		"docker", "Docker", "Cannot connect", "pull access denied",
		"permission denied while trying to connect to the Docker daemon",
		"no such host",
	} {
		if contains(msg, s) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s[:len(sub)] == sub || contains(s[1:], sub)))
}

func newService(t *testing.T, url string) *natsbus.Service {
	t.Helper()
	cfg := natsbus.DefaultConfig()
	cfg.URL = url
	cfg.Storage = "memory"
	cfg.Replicas = 1
	cfg.DedupWindow = 2 * time.Second
	svc, err := natsbus.NewService(context.Background(), cfg, "sn360-es-it", slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func TestNATSIntegration_HealthReportsConnected(t *testing.T) {
	url := startNATS(t)
	svc := newService(t, url)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := svc.Health(ctx); err != nil {
		t.Fatalf("Health on a fresh connection returned error: %v", err)
	}

	// Health must NOT touch the existing streams. Verify by reading
	// the evaluate stream's MsgCount before + after a couple of probes
	// and asserting it stays at zero.
	js := svc.Client().JetStream()
	stream, err := js.Stream(ctx, natsbus.StreamEvaluate)
	if err != nil {
		t.Fatalf("lookup evaluate stream: %v", err)
	}
	before, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("info before: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := svc.Health(ctx); err != nil {
			t.Fatalf("Health iter %d: %v", i, err)
		}
	}
	after, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("info after: %v", err)
	}
	if before.State.Msgs != after.State.Msgs {
		t.Fatalf("Health published messages to evaluate stream: msgs %d -> %d",
			before.State.Msgs, after.State.Msgs)
	}
}

func TestNATSIntegration_HealthReportsDisconnected(t *testing.T) {
	url := startNATS(t)
	svc := newService(t, url)

	// Close the underlying connection out from under the service. The
	// service-level Close drains and nils the connection, so a follow-up
	// Health call must report not connected rather than crashing.
	if err := svc.Client().Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := svc.Health(ctx); err == nil {
		t.Fatal("Health returned nil after the underlying connection was closed")
	}
}

func TestNATSIntegration_PublishSubscribeRoundtrip(t *testing.T) {
	url := startNATS(t)
	svc := newService(t, url)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	received := make(chan events.Message, 1)
	sub, err := svc.Subscribe(ctx, "es.evaluate.request",
		func(_ context.Context, m events.Message) error {
			received <- m
			return nil
		},
		events.WithDurable("it-roundtrip"),
		events.WithMaxDeliver(3),
	)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	if err := svc.Publish(ctx, "es.evaluate.request", []byte("hello"),
		events.WithCorrelationID("abc-123"),
		events.WithEventType("evaluate.request"),
		events.WithTenantID("tenant-1"),
	); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case msg := <-received:
		if string(msg.Data()) != "hello" {
			t.Fatalf("payload mismatch: %q", string(msg.Data()))
		}
		if got := msg.Headers()[events.HeaderCorrelationID]; got != "abc-123" {
			t.Fatalf("correlation header lost: %q", got)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for delivery")
	}
}

func TestNATSIntegration_DLQOnExhaustedDeliveries(t *testing.T) {
	url := startNATS(t)
	svc := newService(t, url)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var attempts atomic.Int32
	primary, err := svc.Subscribe(ctx, "es.evaluate.failing",
		func(_ context.Context, _ events.Message) error {
			attempts.Add(1)
			return errors.New("boom")
		},
		events.WithDurable("it-fail"),
		events.WithMaxDeliver(2),
		events.WithAckWait(500*time.Millisecond),
		events.WithDLQSubject("es.evaluate.dlq"),
	)
	if err != nil {
		t.Fatalf("subscribe primary: %v", err)
	}
	defer primary.Close()

	dlq := make(chan events.Message, 1)
	dlqSub, err := svc.Subscribe(ctx, "es.evaluate.dlq",
		func(_ context.Context, m events.Message) error {
			dlq <- m
			return nil
		},
		events.WithDurable("it-dlq"),
	)
	if err != nil {
		t.Fatalf("subscribe dlq: %v", err)
	}
	defer dlqSub.Close()

	if err := svc.Publish(ctx, "es.evaluate.failing", []byte("payload"),
		events.WithMessageID("dlq-once"),
	); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case msg := <-dlq:
		if string(msg.Data()) != "payload" {
			t.Fatalf("dlq payload mismatch: %q", string(msg.Data()))
		}
	case <-ctx.Done():
		t.Fatalf("dlq never delivered (attempts=%d)", attempts.Load())
	}
	if attempts.Load() < 2 {
		t.Fatalf("expected >=2 delivery attempts before DLQ, got %d", attempts.Load())
	}
}

func TestNATSIntegration_DedupWindowSuppressesDuplicates(t *testing.T) {
	url := startNATS(t)
	svc := newService(t, url)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var delivered atomic.Int32
	sub, err := svc.Subscribe(ctx, "es.evaluate.dedup",
		func(_ context.Context, _ events.Message) error {
			delivered.Add(1)
			return nil
		},
		events.WithDurable("it-dedup"),
	)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	for i := 0; i < 5; i++ {
		if err := svc.Publish(ctx, "es.evaluate.dedup", []byte(fmt.Sprintf("v=%d", i)),
			events.WithMessageID("same-id"),
		); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	// Allow time for redeliveries to land.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			if got := delivered.Load(); got != 1 {
				t.Fatalf("expected exactly one delivery within dedup window, got %d", got)
			}
			return
		case <-time.After(100 * time.Millisecond):
			if delivered.Load() > 1 {
				t.Fatalf("dedup window violated: delivered %d times", delivered.Load())
			}
		}
	}
}
