package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// FeedbackAction enumerates the one-click actions a recipient can post
// back from the banner. Values are the exact strings accepted on the
// HTTP endpoint and emitted on the bus.
type FeedbackAction string

const (
	FeedbackReportPhishing FeedbackAction = "report_phishing"
	FeedbackMarkSafe       FeedbackAction = "mark_safe"
	FeedbackTrustSender    FeedbackAction = "trust_sender"
)

// Valid reports whether a is one of the well-known feedback actions.
func (a FeedbackAction) Valid() bool {
	switch a {
	case FeedbackReportPhishing, FeedbackMarkSafe, FeedbackTrustSender:
		return true
	}
	return false
}

// FeedbackEvent is the canonical payload published to
// `es.action.feedback.<action>` after a banner click is verified.
type FeedbackEvent struct {
	// SchemaVersion is the WS-7c wire-format version tag. See
	// internal/dto/schema_version.go for the contract.
	SchemaVersion        string         `json:"schema_version,omitempty"`
	TenantID             string         `json:"tenant_id"`
	PseudonymizedMessage string         `json:"pseudonymized_message_id"`
	Action               FeedbackAction `json:"action"`
	Tier                 string         `json:"tier,omitempty"`
	OccurredAt           time.Time      `json:"occurred_at"`
	// CorrelationID propagates upstream tracing across the bus.
	CorrelationID string `json:"correlation_id,omitempty"`
}

// FeedbackPublisher is the minimal contract the feedback service
// needs from the event bus. The concrete events.EventService satisfies
// it; tests can plug a fake in.
type FeedbackPublisher interface {
	Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error
}

// ReEvaluator triggers a fresh evaluation pass for mark_safe /
// trust_sender events. It is intentionally an interface (not a
// concrete service.Evaluator) so we don't pull the evaluator package
// into the HTTP handler import graph.
type ReEvaluator interface {
	ReEvaluate(ctx context.Context, tenantID, pseudoMessageID string) error
}

// FeedbackService processes verified one-click banner actions: it
// publishes a feedback event on the bus and, for mark_safe /
// trust_sender, triggers a fresh evaluation pass so the verdict gets
// updated in near-real-time.
type FeedbackService struct {
	logger    *slog.Logger
	verifier  *privacy.JWTIssuer
	publisher FeedbackPublisher
	reEval    ReEvaluator
	singleUse SingleUseStore
}

// NewFeedbackService wires up the dependencies. reEval may be nil if
// the caller does not want to trigger re-evaluation; in that case
// mark_safe / trust_sender still publish their events. singleUse is
// the replay-protection store and is required: a banner token is
// redeemable at most once, enforced by recording its `jti` before any
// side effect (see Process). Callers without Redis pass an
// InMemorySingleUseStore for single-instance enforcement.
func NewFeedbackService(logger *slog.Logger, verifier *privacy.JWTIssuer, publisher FeedbackPublisher, reEval ReEvaluator, singleUse SingleUseStore) *FeedbackService {
	if logger == nil {
		logger = slog.Default()
	}
	return &FeedbackService{logger: logger, verifier: verifier, publisher: publisher, reEval: reEval, singleUse: singleUse}
}

// FeedbackRequest is the validated form of an HTTP POST body. The
// raw token has already been verified by the time the request is
// constructed.
type FeedbackRequest struct {
	Token  string
	Action FeedbackAction
}

// Process validates the action and persists the feedback event. It
// returns the pseudonymised message ID on success so the caller can
// log audit metadata.
func (s *FeedbackService) Process(ctx context.Context, req FeedbackRequest) (string, error) {
	if s.verifier == nil {
		return "", errors.New("feedback: verifier not configured")
	}
	if s.publisher == nil {
		return "", errors.New("feedback: publisher not configured")
	}
	// The single-use store is mandatory: it is the replay guard, so a
	// missing one is a fail-closed misconfiguration rather than a
	// silently weaker code path.
	if s.singleUse == nil {
		return "", errors.New("feedback: single-use store not configured")
	}
	if !req.Action.Valid() {
		return "", fmt.Errorf("feedback: invalid action %q", req.Action)
	}
	// Restrict to banner-action scope: a banner-click token carries
	// the implicit ScopeBannerAction (empty `scp`), so this is
	// transparent for legitimate traffic, but it refuses a leaked
	// quarantine_release or admin_api token replayed against this
	// public endpoint. Without it, a quarantine_release token (empty
	// Action, so it sails past the Action check below) would publish
	// feedback and trigger a re-evaluation under the victim's tenant.
	claims, err := s.verifier.VerifyWithOptions(req.Token, privacy.VerifyOptions{
		AllowedScopes:    []string{privacy.ScopeBannerAction},
		ExpectedAudience: privacy.AudienceActionFeedback,
	})
	if err != nil {
		return "", fmt.Errorf("feedback: verify token: %w", err)
	}
	if claims.Action != "" && claims.Action != string(req.Action) {
		return "", fmt.Errorf("feedback: token bound to action %q, got %q", claims.Action, req.Action)
	}
	// Enforce single use before any side effect so a captured token
	// cannot be redeemed twice (at-most-once). The jti is recorded
	// for at least the token's remaining lifetime, so a replay within
	// the validity window is refused; the store reclaims it after.
	if err := s.consumeOnce(ctx, claims); err != nil {
		return "", err
	}
	evt := FeedbackEvent{
		TenantID:             claims.TenantID,
		PseudonymizedMessage: claims.PseudonymizedMessage,
		Action:               req.Action,
		Tier:                 claims.Tier,
		OccurredAt:           time.Now().UTC(),
		CorrelationID:        claims.ID,
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return "", fmt.Errorf("feedback: marshal: %w", err)
	}
	subject := "es.action.feedback." + string(req.Action)
	if err := s.publisher.Publish(ctx, subject, payload,
		events.WithEventType("action.feedback."+string(req.Action)),
		events.WithTenantID(claims.TenantID),
		events.WithMessageID(claims.ID),
		events.WithCorrelationID(claims.ID),
	); err != nil {
		return "", fmt.Errorf("feedback: publish: %w", err)
	}
	s.logger.InfoContext(ctx, "action.feedback published",
		slog.String("tenant_id", claims.TenantID),
		slog.String("action", string(req.Action)),
		slog.String("tier", claims.Tier),
	)
	if s.reEval != nil && (req.Action == FeedbackMarkSafe || req.Action == FeedbackTrustSender) {
		if err := s.reEval.ReEvaluate(ctx, claims.TenantID, claims.PseudonymizedMessage); err != nil {
			// Re-evaluation is best-effort; the feedback event has
			// already been recorded so we degrade gracefully.
			s.logger.WarnContext(ctx, "action.feedback: re-evaluate failed",
				slog.String("tenant_id", claims.TenantID),
				slog.Any("error", err),
			)
		}
	}
	return claims.PseudonymizedMessage, nil
}

// ErrTokenReplayed is returned by Process when a banner token is
// redeemed a second time. The handler maps it to the same uniform 400
// ("invalid request") the other token-rejection paths return, so a
// replay leaks nothing to the caller; it is a distinct error so the
// audit layer can record a replay attempt separately from a malformed
// or expired token.
var ErrTokenReplayed = errors.New("feedback: token already used")

// consumeOnce records the token's `jti` as consumed and refuses a
// replay. A store error fails closed (the action is rejected) because
// proceeding would silently disable replay protection. Tokens minted
// before the `jti` claim existed carry no id; they cannot be deduped
// and are allowed through with a warning during the (<= token-TTL)
// drain window, after which every token carries a jti.
func (s *FeedbackService) consumeOnce(ctx context.Context, claims *privacy.ActionClaims) error {
	if claims.ID == "" {
		s.logger.WarnContext(ctx, "action.feedback: token has no jti; replay protection skipped (legacy token)",
			slog.String("tenant_id", claims.TenantID),
		)
		return nil
	}
	ttl := time.Minute
	if exp := claims.ExpiresAt; exp != nil {
		if remaining := time.Until(exp.Time) + time.Minute; remaining > ttl {
			ttl = remaining
		}
	}
	alreadyUsed, err := s.singleUse.MarkConsumed(ctx, claims.ID, ttl)
	if err != nil {
		return fmt.Errorf("feedback: replay check: %w", err)
	}
	if alreadyUsed {
		return fmt.Errorf("%w (jti %s)", ErrTokenReplayed, claims.ID)
	}
	return nil
}
