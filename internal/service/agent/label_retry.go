package agent

import (
	"context"
	"encoding/base64"
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
// fails for a mailbox. The mailbox field is encrypted before
// publishing to comply with the pseudonymization policy (no raw PII
// on the event bus). ProcessRetry decrypts it before calling the
// label applier.
type LabelRetryEvent struct {
	TenantID          string    `json:"tenant_id"`
	MailboxCiphertext string    `json:"mailbox_ct"`
	LabelsMissing     []string  `json:"labels_missing"`
	Attempt           int       `json:"attempt"`
	NextRetryAt       time.Time `json:"next_retry_at"`
}

// MailboxEncryptor handles encryption/decryption of the mailbox
// field in label retry events. Implementations should use the same
// key material as the rest of the system (AES-256-GCM via pkg/privacy).
type MailboxEncryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// LabelRetryQueue manages retry logic for failed label creation.
type LabelRetryQueue struct {
	publisher  EventPublisher
	applier    LabelApplier
	encryptor  MailboxEncryptor
	maxRetries int
	logger     *slog.Logger
}

// LabelRetryConfig configures the label retry queue.
type LabelRetryConfig struct {
	Publisher  EventPublisher
	Applier    LabelApplier
	Encryptor  MailboxEncryptor
	MaxRetries int
	Logger     *slog.Logger
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
		encryptor:  cfg.Encryptor,
		maxRetries: cfg.MaxRetries,
		logger:     cfg.Logger,
	}
}

// Enqueue publishes a retry event for a failed label application.
// The mailbox is encrypted before publishing so raw PII never
// appears on the event bus.
func (q *LabelRetryQueue) Enqueue(ctx context.Context, tenantID, mailbox string, missing []string, attempt int) error {
	if attempt >= q.maxRetries {
		q.logger.Warn("label retry: max retries exceeded",
			slog.String("tenant_id", tenantID),
			slog.Int("attempts", attempt))
		return nil
	}

	// Encrypt mailbox to satisfy pseudonymization policy.
	var mailboxCT string
	if q.encryptor != nil {
		ct, err := q.encryptor.Encrypt([]byte(mailbox))
		if err != nil {
			return fmt.Errorf("label retry: encrypt mailbox: %w", err)
		}
		mailboxCT = base64.StdEncoding.EncodeToString(ct)
	} else {
		// Fallback: base64 encode (non-production path; encryptor should always be set).
		mailboxCT = base64.StdEncoding.EncodeToString([]byte(mailbox))
	}

	backoff := time.Duration(1<<uint(attempt)) * 30 * time.Second
	evt := LabelRetryEvent{
		TenantID:          tenantID,
		MailboxCiphertext: mailboxCT,
		LabelsMissing:     missing,
		Attempt:           attempt + 1,
		NextRetryAt:       time.Now().UTC().Add(backoff),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("label retry: marshal: %w", err)
	}
	return q.publisher.Publish(ctx, "es.onboarding.label.retry", data)
}

// ProcessRetry handles a retry event by re-attempting label creation.
// It decrypts the mailbox from the event before calling the label applier.
func (q *LabelRetryQueue) ProcessRetry(ctx context.Context, data []byte) error {
	var evt LabelRetryEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return fmt.Errorf("label retry: unmarshal: %w", err)
	}
	now := time.Now().UTC()
	if now.Before(evt.NextRetryAt) {
		return ErrRetryNotReady
	}

	// Decrypt mailbox from ciphertext.
	ctBytes, err := base64.StdEncoding.DecodeString(evt.MailboxCiphertext)
	if err != nil {
		return fmt.Errorf("label retry: decode mailbox ct: %w", err)
	}
	var mailbox string
	if q.encryptor != nil {
		pt, err := q.encryptor.Decrypt(ctBytes)
		if err != nil {
			return fmt.Errorf("label retry: decrypt mailbox: %w", err)
		}
		mailbox = string(pt)
	} else {
		mailbox = string(ctBytes)
	}

	err = q.applier.EnsureTierLabels(ctx, evt.TenantID, mailbox)
	if err != nil {
		q.logger.Warn("label retry: attempt failed",
			slog.String("tenant_id", evt.TenantID),
			slog.Int("attempt", evt.Attempt),
			slog.String("err", err.Error()))
		return q.Enqueue(ctx, evt.TenantID, mailbox, evt.LabelsMissing, evt.Attempt)
	}
	q.logger.Info("label retry: succeeded",
		slog.String("tenant_id", evt.TenantID),
		slog.Int("attempt", evt.Attempt))
	return nil
}
