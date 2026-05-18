package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
)

type mockEventPublisher struct {
	mu       sync.Mutex
	messages [][]byte
}

func (m *mockEventPublisher) Publish(_ context.Context, _ string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, data)
	return nil
}

type mockLabelApplier struct {
	mu    sync.Mutex
	calls int
}

func (m *mockLabelApplier) EnsureTierLabels(_ context.Context, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return nil
}

func TestLabelRetryQueue_Enqueue(t *testing.T) {
	pub := &mockEventPublisher{}
	q := NewLabelRetryQueue(LabelRetryConfig{
		Publisher:  pub,
		MaxRetries: 3,
	})

	err := q.Enqueue(context.Background(), "t1", "user@example.com", []string{"SN360 / Tier 1"}, 0)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(pub.messages))
	}

	var evt LabelRetryEvent
	if err := json.Unmarshal(pub.messages[0], &evt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if evt.TenantID != "t1" {
		t.Errorf("TenantID = %q, want %q", evt.TenantID, "t1")
	}
	// Without encryptor, mailbox is base64-encoded.
	wantCT := base64.StdEncoding.EncodeToString([]byte("user@example.com"))
	if evt.MailboxCiphertext != wantCT {
		t.Errorf("MailboxCiphertext = %q, want %q", evt.MailboxCiphertext, wantCT)
	}
	if evt.Attempt != 1 {
		t.Errorf("Attempt = %d, want 1", evt.Attempt)
	}
}

func TestLabelRetryQueue_MaxRetriesExceeded(t *testing.T) {
	pub := &mockEventPublisher{}
	q := NewLabelRetryQueue(LabelRetryConfig{
		Publisher:  pub,
		MaxRetries: 3,
	})

	err := q.Enqueue(context.Background(), "t1", "user@example.com", []string{"SN360 / Tier 1"}, 3)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.messages) != 0 {
		t.Errorf("expected no messages when max retries exceeded, got %d", len(pub.messages))
	}
}

func TestLabelRetryQueue_ProcessRetry_Success(t *testing.T) {
	applier := &mockLabelApplier{}
	pub := &mockEventPublisher{}
	q := NewLabelRetryQueue(LabelRetryConfig{
		Publisher:  pub,
		Applier:    applier,
		MaxRetries: 3,
	})

	// Build event with base64-encoded mailbox (no encryptor fallback path).
	evt := LabelRetryEvent{
		TenantID:          "t1",
		MailboxCiphertext: base64.StdEncoding.EncodeToString([]byte("user@example.com")),
		LabelsMissing:     []string{"SN360 / Tier 1"},
		Attempt:           1,
	}
	data, _ := json.Marshal(evt)

	err := q.ProcessRetry(context.Background(), data)
	if err != nil {
		t.Fatalf("ProcessRetry: %v", err)
	}

	applier.mu.Lock()
	defer applier.mu.Unlock()
	if applier.calls != 1 {
		t.Errorf("applier called %d times, want 1", applier.calls)
	}
}

func TestLabelRetryQueue_ExponentialBackoff(t *testing.T) {
	pub := &mockEventPublisher{}
	q := NewLabelRetryQueue(LabelRetryConfig{
		Publisher:  pub,
		MaxRetries: 5,
	})

	for attempt := 0; attempt < 3; attempt++ {
		err := q.Enqueue(context.Background(), "t1", "user@example.com", []string{"label"}, attempt)
		if err != nil {
			t.Fatalf("Enqueue(%d): %v", attempt, err)
		}
	}

	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(pub.messages))
	}

	var events []LabelRetryEvent
	for _, msg := range pub.messages {
		var evt LabelRetryEvent
		_ = json.Unmarshal(msg, &evt)
		events = append(events, evt)
	}
	if events[0].Attempt != 1 || events[1].Attempt != 2 || events[2].Attempt != 3 {
		t.Errorf("unexpected attempts: %d, %d, %d", events[0].Attempt, events[1].Attempt, events[2].Attempt)
	}
}
