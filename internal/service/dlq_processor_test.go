package service

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// fakeMessage is the minimum events.Message surface DLQProcessor.retry()
// touches: Headers, Data, Ack. We do not exercise Subject / Nak /
// Metadata here so they are stubbed.
type fakeMessage struct {
	headers map[string]string
	data    []byte
	acked   atomic.Bool
}

func (f *fakeMessage) Data() []byte               { return f.data }
func (f *fakeMessage) Subject() string            { return "" }
func (f *fakeMessage) Headers() map[string]string { return f.headers }
func (f *fakeMessage) Ack() error                 { f.acked.Store(true); return nil }
func (f *fakeMessage) Nak(time.Duration) error    { return nil }
func (f *fakeMessage) Metadata() (events.MessageMetadata, error) {
	return events.MessageMetadata{}, nil
}

// fakeRepublisher implements the Republisher contract by recording the
// last publish call. We do not care about persistence; the retry()
// path under test only needs Publish to succeed.
type fakeRepublisher struct {
	called atomic.Bool
}

func (f *fakeRepublisher) Publish(_ context.Context, _ string, _ []byte, _ ...events.PublishOption) error {
	f.called.Store(true)
	return nil
}

// TestRetry_BackoffCapped proves a misconfigured Decider that asks
// for a 30-minute Backoff cannot pin the dispatch goroutine for
// 30 minutes. The synchronous wait inside retry() must be capped at
// maxRetryBackoff (5 seconds). We use a generous wall-clock slack
// (3s) on top of the cap to keep the test non-flaky on slow CI.
func TestRetry_BackoffCapped(t *testing.T) {
	p := &DLQProcessor{
		cfg: DLQProcessorConfig{
			MaxRetryAttempts: 3,
			Republisher:      &fakeRepublisher{},
		},
		log: slog.Default(),
	}
	msg := &fakeMessage{
		headers: map[string]string{
			events.HeaderOriginSubject: "evaluate.request",
			events.HeaderDeliveryCount: "1",
		},
		data: []byte("x"),
	}
	dec := Decision{
		Action:  ActionRetry,
		Reason:  "test",
		Backoff: 30 * time.Minute,
	}

	start := time.Now()
	if err := p.retry(context.Background(), msg, dec); err != nil {
		t.Fatalf("retry: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > maxRetryBackoff+3*time.Second {
		t.Fatalf("retry blocked for %v, want <= maxRetryBackoff+slack=%v; cap is not enforced", elapsed, maxRetryBackoff+3*time.Second)
	}
	if elapsed < maxRetryBackoff-1*time.Second {
		t.Fatalf("retry returned in %v, want >= ~%v; backoff did not apply", elapsed, maxRetryBackoff)
	}
}

// TestRetry_ContextCancelExitsImmediately proves the synchronous
// wait honours ctx.Done() so a graceful shutdown does not have to
// wait for the cap to elapse.
func TestRetry_ContextCancelExitsImmediately(t *testing.T) {
	p := &DLQProcessor{
		cfg: DLQProcessorConfig{
			MaxRetryAttempts: 3,
			Republisher:      &fakeRepublisher{},
		},
		log: slog.Default(),
	}
	msg := &fakeMessage{
		headers: map[string]string{
			events.HeaderOriginSubject: "evaluate.request",
			events.HeaderDeliveryCount: "1",
		},
		data: []byte("x"),
	}
	dec := Decision{
		Action:  ActionRetry,
		Reason:  "test",
		Backoff: maxRetryBackoff,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if err := p.retry(ctx, msg, dec); err == nil {
		t.Fatalf("retry returned nil with cancelled ctx; want ctx.Err()")
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Fatalf("retry took %v after cancel; want <1s", elapsed)
	}
}
