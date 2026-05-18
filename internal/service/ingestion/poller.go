// Package ingestion wires the polling engine that produces
// `es.evaluate.request` events from real mailboxes (Google Workspace,
// Microsoft 365). It is the canonical entry point for the evaluation
// pipeline — without it the binary only processes manually-published
// requests.
//
// Design notes:
//
//   - Per-mailbox concurrency: a worker pool drains a buffered channel
//     of mailbox jobs so polling a slow user does not block the
//     others.
//   - Distributed locking: each (tenant, mailbox) job acquires a
//     short-lived Redis lock so that running multiple replicas of
//     the binary does not double-poll the same mailbox.
//   - Checkpointing: per-(tenant, mailbox) "last polled" timestamps
//     are persisted via the CheckpointStore so a restart picks up
//     where the previous run stopped.
//   - Graceful degradation: failures on a single mailbox are logged
//     and skipped; the next cycle retries from the previous
//     checkpoint.
package ingestion

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// MailboxProvider is implemented by per-provider clients (Gmail,
// Outlook) and exposes the list-and-fetch surface the Poller needs.
type MailboxProvider interface {
	// Kind returns a stable identifier — "gmail" / "outlook" —
	// used in metrics and lock keys.
	Kind() string
	// ListMailboxes returns every mailbox the provider has access
	// to for the given tenant. Implementations should respect the
	// context for cancellation.
	ListMailboxes(ctx context.Context, tenantID string) ([]Mailbox, error)
	// FetchNew returns messages received after `since` (exclusive)
	// for the given mailbox. Implementations should cap the number
	// of returned messages at the supplied limit.
	FetchNew(ctx context.Context, mailbox Mailbox, since time.Time, limit int) ([]RawEmail, error)
}

// Mailbox identifies a user mailbox within a tenant.
type Mailbox struct {
	TenantID string
	Address  string
	UserID   string // provider-specific user id (e.g. Graph object id)
}

// RawEmail is the per-message payload returned by MailboxProvider.
// FetchNew. It contains everything the normalizer needs to build a
// dto.EvaluateRequest.
type RawEmail struct {
	ProviderMessageID string
	TenantID          string
	Mailbox           string
	Sender            string
	Recipients        []string
	CC                []string
	Subject           string
	Body              string
	HTMLBody          string
	Headers           map[string]string
	ReceivedAt        time.Time
}

// DistributedLock is the subset of pkg/storage/redis.DistributedLock
// the poller relies on. Splitting it out lets tests inject a memory
// implementation without pulling in Redis.
type DistributedLock interface {
	// Acquire tries to take the lock. Returns (true, nil) on
	// success; (false, nil) when another holder has it.
	Acquire(ctx context.Context) (bool, error)
	// Release best-effort releases the lock. Safe to call when not
	// held.
	Release(ctx context.Context) error
}

// LockFactory returns a fresh lock per (tenant, mailbox) job. The
// poller calls Acquire / Release exactly once per fetch.
type LockFactory func(key string) DistributedLock

// Normalizer turns a RawEmail into a dto.EvaluateRequest ready for
// the evaluator. The default implementation lives in normalizer.go.
type Normalizer interface {
	Normalize(ctx context.Context, raw RawEmail) (dto.EvaluateRequest, error)
}

// PollerConfig wires the poller. Defaults are applied for zero
// values; only Providers and Publisher are strictly required.
type PollerConfig struct {
	Providers  []MailboxProvider
	Publisher  events.EventService
	Logger     *slog.Logger
	Normalizer Normalizer
	Checkpoint CheckpointStore
	Locks      LockFactory
	// Interval between polling cycles.
	Interval time.Duration
	// BatchSize is the per-mailbox fetch ceiling.
	BatchSize int
	// Concurrency controls how many mailboxes are polled
	// concurrently across all providers.
	Concurrency int
	// LookbackOnFirstRun controls how far back to fetch when no
	// checkpoint exists. Defaults to 24h.
	LookbackOnFirstRun time.Duration
	// TenantIDs are the tenants to poll. When empty, providers'
	// ListMailboxes("") is invoked which is expected to enumerate
	// every reachable mailbox (typical for service-account
	// deployments).
	TenantIDs []string
	// Subject is the JetStream subject used for emitted events.
	// Defaults to "es.evaluate.request".
	Subject string
}

// Poller drives the periodic poll cycle.
type Poller struct {
	cfg PollerConfig
}

// New constructs a Poller and validates the config. Returns an error
// if the providers slice or publisher is missing.
func New(cfg PollerConfig) (*Poller, error) {
	if len(cfg.Providers) == 0 {
		return nil, errors.New("ingestion: at least one MailboxProvider is required")
	}
	if cfg.Publisher == nil {
		return nil, errors.New("ingestion: publisher is required")
	}
	if cfg.Normalizer == nil {
		cfg.Normalizer = NewDefaultNormalizer()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.LookbackOnFirstRun <= 0 {
		cfg.LookbackOnFirstRun = 24 * time.Hour
	}
	if cfg.Subject == "" {
		cfg.Subject = "es.evaluate.request"
	}
	return &Poller{cfg: cfg}, nil
}

// Run drives the poll loop until the context is cancelled. The first
// cycle starts immediately; subsequent cycles fire every Interval.
func (p *Poller) Run(ctx context.Context) error {
	if err := p.cycle(ctx); err != nil {
		p.cfg.Logger.Warn("ingestion: initial cycle failed", slog.Any("error", err))
	}
	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.cycle(ctx); err != nil {
				p.cfg.Logger.Warn("ingestion: cycle failed", slog.Any("error", err))
			}
		}
	}
}

// RunOnce executes a single poll cycle. Useful for tests and for
// triggering a manual catch-up from an admin endpoint.
func (p *Poller) RunOnce(ctx context.Context) error {
	return p.cycle(ctx)
}

// cycle drains every mailbox across every provider once.
func (p *Poller) cycle(ctx context.Context) error {
	jobs := make(chan job, p.cfg.Concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < p.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				p.pollMailbox(ctx, j)
			}
		}()
	}
	// Enumerate mailboxes and feed the workers.
	tenants := p.cfg.TenantIDs
	if len(tenants) == 0 {
		tenants = []string{""}
	}
	var enumErrs []error
	for _, tenant := range tenants {
		for _, prov := range p.cfg.Providers {
			mailboxes, err := prov.ListMailboxes(ctx, tenant)
			if err != nil {
				enumErrs = append(enumErrs, fmt.Errorf("list %s tenant=%q: %w", prov.Kind(), tenant, err))
				continue
			}
			for _, mbox := range mailboxes {
				jobs <- job{provider: prov, mailbox: mbox}
			}
		}
	}
	close(jobs)
	wg.Wait()
	if len(enumErrs) > 0 {
		return errors.Join(enumErrs...)
	}
	return nil
}

type job struct {
	provider MailboxProvider
	mailbox  Mailbox
}

// pollMailbox runs the lock-fetch-publish-checkpoint flow for one
// mailbox. Every step is logged and continued on failure so that one
// failing mailbox does not poison the cycle.
func (p *Poller) pollMailbox(ctx context.Context, j job) {
	logger := p.cfg.Logger.With(
		slog.String("provider", j.provider.Kind()),
		slog.String("tenant_id", j.mailbox.TenantID),
		slog.String("mailbox", j.mailbox.Address))
	// Acquire the per-mailbox lock so replicas do not double-poll.
	var lock DistributedLock
	if p.cfg.Locks != nil {
		lock = p.cfg.Locks(lockKey(j.provider.Kind(), j.mailbox))
		ok, err := lock.Acquire(ctx)
		if err != nil {
			logger.Warn("ingestion: lock acquire failed", slog.Any("error", err))
			return
		}
		if !ok {
			logger.Debug("ingestion: skipping; lock held by another replica")
			return
		}
		defer func() {
			if rerr := lock.Release(ctx); rerr != nil {
				logger.Warn("ingestion: lock release failed", slog.Any("error", rerr))
			}
		}()
	}
	// Resolve the checkpoint, fall back to the lookback window on
	// first run.
	since := time.Now().Add(-p.cfg.LookbackOnFirstRun)
	if p.cfg.Checkpoint != nil {
		got, ok, err := p.cfg.Checkpoint.Get(ctx, j.mailbox.TenantID, j.mailbox.Address)
		switch {
		case err != nil:
			logger.Warn("ingestion: checkpoint get failed", slog.Any("error", err))
		case ok && !got.IsZero():
			since = got
		}
	}
	emails, err := j.provider.FetchNew(ctx, j.mailbox, since, p.cfg.BatchSize)
	if err != nil {
		logger.Warn("ingestion: fetch failed", slog.Any("error", err))
		return
	}
	if len(emails) == 0 {
		logger.Debug("ingestion: no new messages")
		return
	}
	// Newest timestamp seen — used to advance the checkpoint at
	// the end of the cycle.
	newest := since
	for _, raw := range emails {
		req, nerr := p.cfg.Normalizer.Normalize(ctx, raw)
		if nerr != nil {
			logger.Warn("ingestion: normalize failed",
				slog.String("provider_message_id", raw.ProviderMessageID),
				slog.Any("error", nerr))
			continue
		}
		payload, merr := marshalRequest(req)
		if merr != nil {
			logger.Warn("ingestion: marshal failed",
				slog.String("provider_message_id", raw.ProviderMessageID),
				slog.Any("error", merr))
			continue
		}
		if perr := p.cfg.Publisher.Publish(ctx, p.cfg.Subject, payload,
			events.WithTenantID(req.TenantID),
			events.WithMessageID(req.MessageID),
			events.WithCorrelationID(req.CorrelationID),
			events.WithEventType("evaluate.request"),
		); perr != nil {
			logger.Warn("ingestion: publish failed",
				slog.String("provider_message_id", raw.ProviderMessageID),
				slog.Any("error", perr))
			continue
		}
		if raw.ReceivedAt.After(newest) {
			newest = raw.ReceivedAt
		}
	}
	// Advance the checkpoint to the newest received_at we
	// successfully published.
	if p.cfg.Checkpoint != nil && newest.After(since) {
		if err := p.cfg.Checkpoint.Set(ctx, j.mailbox.TenantID, j.mailbox.Address, newest); err != nil {
			logger.Warn("ingestion: checkpoint set failed", slog.Any("error", err))
		}
	}
	logger.Info("ingestion: polled mailbox",
		slog.Int("messages", len(emails)),
		slog.Time("checkpoint", newest))
}

// lockKey is the canonical Redis lock key for a (provider, mailbox)
// pair. We include the provider kind in the prefix so a tenant
// connected via both Gmail and Outlook can poll both concurrently.
func lockKey(provider string, m Mailbox) string {
	return "ingestion:lock:" + provider + ":" + m.TenantID + ":" + m.Address
}
