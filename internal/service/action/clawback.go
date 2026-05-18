package action

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// ClawbackEvent is the payload emitted when a retroactive clawback
// is triggered (e.g., a message's score was upgraded from Warning to
// Blocked via updated threat intel or user reports).
type ClawbackEvent struct {
	TenantID             string        `json:"tenant_id"`
	PseudonymizedMessage string        `json:"pseudonymized_message_id"`
	OldTier              constant.Tier `json:"old_tier"`
	NewTier              constant.Tier `json:"new_tier"`
	Reason               string        `json:"reason"`
	QuarantinedCount     int           `json:"quarantined_count"`
	OccurredAt           time.Time     `json:"occurred_at"`
}

// ClawbackConfig wires the ClawbackService.
type ClawbackConfig struct {
	Quarantiner MultiQuarantiner
	Recipients  TenantRecipientLookup
	Publisher   events.EventService
	Logger      *slog.Logger
	Clock       func() time.Time
}

// ClawbackService handles retroactive quarantine when a message's
// threat assessment is upgraded. It listens for score-upgrade events
// (e.g., from updated threat intel, user reports, or URL re-checks)
// and quarantines the message across all recipients.
type ClawbackService struct {
	quar       MultiQuarantiner
	recipients TenantRecipientLookup
	pub        events.EventService
	log        *slog.Logger
	now        func() time.Time
}

// NewClawbackService constructs the service.
func NewClawbackService(cfg ClawbackConfig) (*ClawbackService, error) {
	if cfg.Quarantiner == nil {
		return nil, fmt.Errorf("clawback: quarantiner is required")
	}
	if cfg.Recipients == nil {
		return nil, fmt.Errorf("clawback: recipient lookup is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &ClawbackService{
		quar:       cfg.Quarantiner,
		recipients: cfg.Recipients,
		pub:        cfg.Publisher,
		log:        cfg.Logger,
		now:        cfg.Clock,
	}, nil
}

// ScoreUpgradeRequest is the input for a retroactive clawback triggered
// by a score upgrade.
type ScoreUpgradeRequest struct {
	TenantID             string
	PseudonymizedMessage string
	OldTier              constant.Tier
	NewTier              constant.Tier
	Reason               string
}

// shouldClawback determines if the tier change warrants quarantine.
func shouldClawback(oldTier, newTier constant.Tier) bool {
	oldSeverity := tierSeverity(oldTier)
	newSeverity := tierSeverity(newTier)
	// Clawback when the new tier is strictly more severe than the old
	// and the new tier is at least HighRisk (we don't quarantine for
	// mere Warning upgrades).
	return newSeverity > oldSeverity && newSeverity >= 2
}

// tierSeverity maps tiers to a numeric severity for comparison.
func tierSeverity(t constant.Tier) int {
	switch t {
	case constant.TierTrusted:
		return 0
	case constant.TierInformational:
		return 0
	case constant.TierCaution:
		return 0
	case constant.TierWarning:
		return 1
	case constant.TierHighRisk:
		return 2
	case constant.TierBlocked:
		return 3
	default:
		return 0
	}
}

// HandleScoreUpgrade processes a score upgrade and retroactively
// quarantines the message across all recipients if warranted.
func (s *ClawbackService) HandleScoreUpgrade(ctx context.Context, req ScoreUpgradeRequest) error {
	if req.TenantID == "" || req.PseudonymizedMessage == "" {
		return fmt.Errorf("clawback: tenant_id and message_id are required")
	}

	if !shouldClawback(req.OldTier, req.NewTier) {
		s.log.DebugContext(ctx, "clawback: upgrade does not warrant clawback",
			slog.String("tenant_id", req.TenantID),
			slog.String("old_tier", string(req.OldTier)),
			slog.String("new_tier", string(req.NewTier)))
		return nil
	}

	recipients, err := s.recipients.Recipients(ctx, req.TenantID, req.PseudonymizedMessage)
	if err != nil {
		return fmt.Errorf("clawback: recipients lookup: %w", err)
	}

	quarantined := 0
	var lastErr error
	for _, r := range recipients {
		if err := s.quar.Quarantine(ctx, req.TenantID, req.PseudonymizedMessage, r, ""); err != nil {
			s.log.WarnContext(ctx, "clawback: quarantine failed",
				slog.String("tenant_id", req.TenantID),
				slog.String("recipient", r),
				slog.Any("error", err))
			lastErr = err
			continue
		}
		quarantined++
	}

	evt := ClawbackEvent{
		TenantID:             req.TenantID,
		PseudonymizedMessage: req.PseudonymizedMessage,
		OldTier:              req.OldTier,
		NewTier:              req.NewTier,
		Reason:               req.Reason,
		QuarantinedCount:     quarantined,
		OccurredAt:           s.now(),
	}

	if s.pub != nil {
		payload, merr := json.Marshal(evt)
		if merr != nil {
			return fmt.Errorf("clawback: marshal: %w", merr)
		}
		if perr := s.pub.Publish(ctx, "es.action.clawback.executed", payload,
			events.WithTenantID(req.TenantID),
			events.WithEventType("clawback.executed"),
		); perr != nil {
			s.log.WarnContext(ctx, "clawback: publish failed", slog.Any("error", perr))
		}
	}

	s.log.InfoContext(ctx, "clawback: executed",
		slog.String("tenant_id", req.TenantID),
		slog.String("message_id", req.PseudonymizedMessage),
		slog.String("old_tier", string(req.OldTier)),
		slog.String("new_tier", string(req.NewTier)),
		slog.Int("quarantined", quarantined),
		slog.Int("total_recipients", len(recipients)))

	if quarantined == 0 && len(recipients) > 0 {
		return fmt.Errorf("clawback: all %d quarantine attempts failed for tenant %s: %w",
			len(recipients), req.TenantID, lastErr)
	}
	return nil
}

// HandleReportConfirmed is a consumer for es.action.feedback.report_confirmed
// events. It triggers a clawback for confirmed phishing reports.
func (s *ClawbackService) HandleReportConfirmed(ctx context.Context, msg events.Message) error {
	var evt ReportEvent
	if err := json.Unmarshal(msg.Data(), &evt); err != nil {
		s.log.WarnContext(ctx, "clawback: unmarshal report event failed", slog.Any("error", err))
		return nil
	}
	if evt.TenantID == "" || evt.PseudonymizedMessage == "" {
		return nil
	}
	if !evt.Confirmed {
		return nil
	}

	newTier := constant.TierBlocked
	// When tier is unknown (legacy producers), default to Informational
	// so shouldClawback always fires. Defaulting to Warning would skip
	// clawback for Warning→Blocked, and defaulting to Trusted would be
	// correct but overly aggressive for messages that may already be
	// at HighRisk/Blocked (quarantine is idempotent but wastes API calls).
	oldTier := constant.TierInformational
	if evt.Tier != "" {
		oldTier = constant.Tier(evt.Tier)
	}

	return s.HandleScoreUpgrade(ctx, ScoreUpgradeRequest{
		TenantID:             evt.TenantID,
		PseudonymizedMessage: evt.PseudonymizedMessage,
		OldTier:              oldTier,
		NewTier:              newTier,
		Reason:               "user_report_confirmed",
	})
}
