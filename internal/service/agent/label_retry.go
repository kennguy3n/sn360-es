package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// ErrRetryNotReady is returned by ProcessRetry when the event's
// NextRetryAt has not yet passed. Consumers should NAK the message
// with a delay (e.g. NakWithDelay on NATS JetStream) rather than
// immediately redelivering.
var ErrRetryNotReady = errors.New("label retry: not ready for retry yet")

// LabelRetryEvent is the event shape published when label creation
// fails for a mailbox. A consumer retries with exponential backoff.
type LabelRetryEvent struct {
	TenantID      string   `json:"tenant_id"`
	Mailbox       string   `json:"mailbox"`
	LabelsMissing []string `json:"labels_missing"`
	Attempt       int      `json:"attempt"`
	NextRetryAt   time.Time `json:"next_retry_at"`
}

// LabelRetryQueue manages retry logic for failed label creation.
type LabelRetryQueue struct {
	publisher  EventPublisher
	applier    LabelApplier
	maxRetries int
	logger     *slog.Logger
}

// LabelRetryConfig configures the label retry queue.
type LabelRetryConfig struct {
	Publisher  EventPublisher
	Applier   LabelApplier
	MaxRetries int
	Logger    *slog.Logger
}

// NewLabelRetryQueue constructs a retry queue.
func NewLabelRetryQueue(cfg LabelRetryConfig) *LabelRetryQueue {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &LabelRetryQueue{
		publisher:  cfg.Publisher,
		applier:    cfg.Applier,
		maxRetries: cfg.MaxRetries,
		logger:     cfg.Logger,
	}
}

// Enqueue publishes a retry event for a failed label application.
func (q *LabelRetryQueue) Enqueue(ctx context.Context, tenantID, mailbox string, missing []string, attempt int) error {
	if attempt >= q.maxRetries {
		q.logger.Warn("label retry: max retries exceeded",
			slog.String("tenant_id", tenantID),
			slog.String("mailbox", mailbox),
			slog.Int("attempts", attempt))
		return nil
	}
	backoff := time.Duration(1<<uint(attempt)) * 30 * time.Second
	evt := LabelRetryEvent{
		TenantID:      tenantID,
		Mailbox:       mailbox,
		LabelsMissing: missing,
		Attempt:       attempt + 1,
		NextRetryAt:   time.Now().UTC().Add(backoff),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("label retry: marshal: %w", err)
	}
	return q.publisher.Publish(ctx, "es.onboarding.label.retry", data)
}

// ProcessRetry handles a retry event by re-attempting label creation.
func (q *LabelRetryQueue) ProcessRetry(ctx context.Context, data []byte) error {
	var evt LabelRetryEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return fmt.Errorf("label retry: unmarshal: %w", err)
	}
	now := time.Now().UTC()
	if now.Before(evt.NextRetryAt) {
		// Return ErrRetryNotReady so the consumer can NAK with delay.
		// This avoids a busy-wait hot loop of re-publishing to the
		// same topic at message-bus speed.
		return ErrRetryNotReady
	}
	err := q.applier.EnsureTierLabels(ctx, evt.TenantID, evt.Mailbox)
	if err != nil {
		q.logger.Warn("label retry: attempt failed",
			slog.String("tenant_id", evt.TenantID),
			slog.String("mailbox", evt.Mailbox),
			slog.Int("attempt", evt.Attempt),
			slog.String("err", err.Error()))
		return q.Enqueue(ctx, evt.TenantID, evt.Mailbox, evt.LabelsMissing, evt.Attempt)
	}
	q.logger.Info("label retry: succeeded",
		slog.String("tenant_id", evt.TenantID),
		slog.String("mailbox", evt.Mailbox),
		slog.Int("attempt", evt.Attempt))
	return nil
}
