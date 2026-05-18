package onboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/ingestion"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// BackfillConfig wires the historical backfill job that runs during
// onboarding to seed the relationship graph, vendor discovery, and
// timing baselines from the last N days of mail.
type BackfillConfig struct {
	Providers  []ingestion.MailboxProvider
	Publisher  events.EventService
	Normalizer ingestion.Normalizer
	Logger     *slog.Logger
	// BackfillDays is how many days of history to fetch. Defaults to 14.
	BackfillDays int
	// BatchSize is the per-mailbox fetch ceiling per lookback chunk.
	BatchSize int
	// Subject is the JetStream subject for emitted events.
	Subject string
}

// BackfillJob runs a one-time historical backfill for the given tenant.
// It fetches the last BackfillDays of messages from all mailboxes and
// publishes them as evaluate requests with a "backfill" marker.
type BackfillJob struct {
	cfg BackfillConfig
}

// NewBackfillJob constructs the job.
func NewBackfillJob(cfg BackfillConfig) (*BackfillJob, error) {
	if len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("backfill: at least one provider is required")
	}
	if cfg.Publisher == nil {
		return nil, fmt.Errorf("backfill: publisher is required")
	}
	if cfg.Normalizer == nil {
		cfg.Normalizer = ingestion.NewDefaultNormalizer()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.BackfillDays <= 0 {
		cfg.BackfillDays = 14
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.Subject == "" {
		cfg.Subject = "es.evaluate.request"
	}
	return &BackfillJob{cfg: cfg}, nil
}

// BackfillResult summarises the outcome of a backfill run.
type BackfillResult struct {
	TenantID        string
	MailboxesPolled int
	MessagesFetched int
	MessagesEmitted int
	Errors          int
	Duration        time.Duration
}

// Run executes the backfill for a single tenant. This should be
// invoked once during the onboarding flow — typically from the
// post-consent trigger.
func (j *BackfillJob) Run(ctx context.Context, tenantID string) (BackfillResult, error) {
	start := time.Now()
	result := BackfillResult{TenantID: tenantID}
	since := time.Now().Add(-time.Duration(j.cfg.BackfillDays) * 24 * time.Hour)

	for _, prov := range j.cfg.Providers {
		mailboxes, err := prov.ListMailboxes(ctx, tenantID)
		if err != nil {
			j.cfg.Logger.Warn("backfill: list mailboxes failed",
				slog.String("provider", prov.Kind()),
				slog.String("tenant", tenantID),
				slog.Any("error", err))
			result.Errors++
			continue
		}

		for _, mb := range mailboxes {
			result.MailboxesPolled++
			emails, ferr := prov.FetchNew(ctx, mb, since, j.cfg.BatchSize)
			if ferr != nil {
				j.cfg.Logger.Warn("backfill: fetch failed",
					slog.String("provider", prov.Kind()),
					slog.String("mailbox", mb.Address),
					slog.Any("error", ferr))
				result.Errors++
				continue
			}
			result.MessagesFetched += len(emails)

			for _, raw := range emails {
				req, blob, nerr := ingestion.EvaluateRequestFromRaw(ctx, j.cfg.Normalizer, raw)
				if nerr != nil {
					result.Errors++
					continue
				}
				if perr := j.cfg.Publisher.Publish(ctx, j.cfg.Subject, blob,
					events.WithTenantID(req.TenantID),
					events.WithCorrelationID(req.CorrelationID),
					events.WithEventType("evaluate.request.backfill"),
				); perr != nil {
					j.cfg.Logger.Warn("backfill: publish failed",
						slog.String("message_id", req.MessageID),
						slog.Any("error", perr))
					result.Errors++
					continue
				}
				result.MessagesEmitted++
			}
		}
	}

	result.Duration = time.Since(start)
	j.cfg.Logger.Info("backfill: complete",
		slog.String("tenant", tenantID),
		slog.Int("mailboxes", result.MailboxesPolled),
		slog.Int("fetched", result.MessagesFetched),
		slog.Int("emitted", result.MessagesEmitted),
		slog.Int("errors", result.Errors),
		slog.Duration("duration", result.Duration))

	if j.cfg.Publisher != nil {
		summary, _ := json.Marshal(result)
		_ = j.cfg.Publisher.Publish(ctx, "es.onboarding.backfill.complete", summary,
			events.WithTenantID(tenantID),
			events.WithEventType("onboarding.backfill.complete"),
		)
	}
	return result, nil
}
