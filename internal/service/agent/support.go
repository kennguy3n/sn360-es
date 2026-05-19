package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// SupportConfig wires the support agent's dependencies.
type SupportConfig struct {
	Lookup EvaluationLookup
	Audit  AuditLog
	Events EventPublisher
	// Explanations is the locale-aware explanation catalog. When nil,
	// ExplainVerdict and DefaultSuggestion fall back to hardcoded English.
	Explanations *ExplanationCatalog
	// SecOpsSubject is the NATS subject for low-confidence escalations
	// (default "es.action.escalation.created").
	SecOpsSubject string
	// ReleaseSubject is the NATS subject emitted when a user requests
	// quarantine release (default "es.action.quarantine.release").
	ReleaseSubject string
	// EscalationConfidence is the lower bound of the verdict confidence
	// below which the support agent escalates rather than answering.
	// Default 0.45.
	EscalationConfidence float64

	Logger *slog.Logger
}

// SupportAgent handles user queries about flagged emails. It is
// deliberately rule-based + templated (not LLM-driven) so explanations
// are deterministic and auditable.
type SupportAgent struct {
	cfg SupportConfig
	log *slog.Logger
}

// NewSupportAgent constructs a SupportAgent. Lookup is required.
func NewSupportAgent(cfg SupportConfig) (*SupportAgent, error) {
	if cfg.Lookup == nil {
		return nil, errors.New("agent: support requires Lookup")
	}
	if cfg.SecOpsSubject == "" {
		cfg.SecOpsSubject = "es.action.escalation.created"
	}
	if cfg.ReleaseSubject == "" {
		cfg.ReleaseSubject = "es.action.quarantine.release"
	}
	if cfg.EscalationConfidence <= 0 {
		cfg.EscalationConfidence = 0.45
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &SupportAgent{cfg: cfg, log: cfg.Logger}, nil
}

// Name implements Agent.
func (a *SupportAgent) Name() string { return "support" }

// Answer processes a query and returns a structured reply.
//
// Branches:
//   - action="explain" → fetch verdict, render explanation.
//   - action="release" → emit release-request event, return optimistic ack.
//   - action="escalate" or low-confidence verdict → emit secops escalation.
func (a *SupportAgent) Answer(ctx context.Context, q SupportQuery) (SupportReply, error) {
	if q.TenantID == "" || q.MessageID == "" {
		return SupportReply{}, errors.New("agent: support requires TenantID + MessageID")
	}
	log := a.log.With(slog.String("tenant_id", q.TenantID), slog.String("message_id", q.MessageID))

	verdict, err := a.cfg.Lookup.FindResult(ctx, q.TenantID, q.MessageID)
	if err != nil {
		return SupportReply{}, fmt.Errorf("support: lookup verdict: %w", err)
	}

	action := strings.ToLower(q.Action)
	if action == "" {
		action = "explain"
	}

	rep := SupportReply{}
	switch action {
	case "explain":
		rep = a.explain(q, verdict)
	case "release":
		rep, err = a.release(ctx, q, verdict)
		if err != nil {
			return rep, err
		}
	case "escalate":
		rep, err = a.escalate(ctx, q, verdict, "user_requested")
		if err != nil {
			return rep, err
		}
	default:
		return SupportReply{}, fmt.Errorf("support: unknown action %q", action)
	}

	// If the verdict itself was low-confidence, escalate too.
	if !rep.Escalated && verdictConfidence(verdict) < a.cfg.EscalationConfidence {
		esc, err := a.escalate(ctx, q, verdict, "low_confidence")
		if err == nil {
			rep.Suggestion = esc.Suggestion
			rep.Escalated = true
		}
	}

	if a.cfg.Audit != nil {
		_ = a.cfg.Audit.Record(ctx, AuditEntry{
			Agent:      a.Name(),
			TenantID:   q.TenantID,
			Action:     "support." + action,
			OccurredAt: time.Now().UTC(),
			Detail: map[string]any{
				"message_id": q.MessageID,
				"escalated":  rep.Escalated,
			},
		})
	}
	log.Info("agent.support: handled", slog.String("action", action), slog.Bool("escalated", rep.Escalated))
	return rep, nil
}

func (a *SupportAgent) explain(q SupportQuery, v dto.EvaluateResult) SupportReply {
	conf := verdictConfidence(v)
	cat := a.cfg.Explanations
	if cat == nil {
		cat = getDefaultExplanations()
	}
	exp := ExplainVerdictWith(cat, v, q.Locale)
	suggest := cat.TierSuggestion(v.Tier, q.Locale)
	return SupportReply{
		Explanation: exp,
		Confidence:  conf,
		Suggestion:  suggest,
	}
}

func (a *SupportAgent) release(ctx context.Context, q SupportQuery, v dto.EvaluateResult) (SupportReply, error) {
	if a.cfg.Events == nil {
		return SupportReply{}, errors.New("support: events publisher required for release")
	}
	// The consumer (handleQuarantineRelease) expects "pseudonymized_message_id"
	// and "requested_by". The MessageID here comes from the verdict lookup which
	// already stores the pseudonymised form, so the mapping is correct.
	payload := fmt.Sprintf(`{"tenant_id":%q,"pseudonymized_message_id":%q,"requested_by":%q}`,
		q.TenantID, q.MessageID, q.UserEmail)
	if err := a.cfg.Events.Publish(ctx, a.cfg.ReleaseSubject, []byte(payload)); err != nil {
		return SupportReply{}, fmt.Errorf("support: emit release: %w", err)
	}
	cat := a.cfg.Explanations
	if cat == nil {
		cat = getDefaultExplanations()
	}
	releaseSuggestion := "Your release request has been queued and will be processed within a few minutes."
	if cat != nil {
		releaseSuggestion = cat.ReleaseSuggestion(q.Locale)
	}
	now := time.Now().UTC()
	return SupportReply{
		Explanation: ExplainVerdictWith(cat, v, q.Locale),
		Confidence:  verdictConfidence(v),
		Suggestion:  releaseSuggestion,
		ReleasedAt:  &now,
		ReleasedAs:  constant.CategoryInternalTrusted,
	}, nil
}

func (a *SupportAgent) escalate(ctx context.Context, q SupportQuery, v dto.EvaluateResult, reason string) (SupportReply, error) {
	cat := a.cfg.Explanations
	if cat == nil {
		cat = getDefaultExplanations()
	}
	escSuggestion := "Escalated to your security team for review."
	if cat != nil {
		escSuggestion = cat.EscalatedSuggestion(q.Locale)
	}
	if a.cfg.Events == nil {
		return SupportReply{Escalated: true, Suggestion: escSuggestion}, nil
	}
	envelope := struct {
		TenantID string               `json:"tenant_id"`
		Incident dto.EscalationIncident `json:"incident"`
	}{
		TenantID: q.TenantID,
		Incident: dto.EscalationIncident{
			PseudoMessageID: q.MessageID,
			Tier:            string(v.Tier),
			Category:        string(v.Primary),
			Reason:          dto.EscalationReasonUserRequested,
			Score:           float64(v.Score),
			AISummary:       reason,
			DetectedAt:      time.Now().UTC(),
		},
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return SupportReply{}, fmt.Errorf("support: marshal escalation: %w", err)
	}
	if err := a.cfg.Events.Publish(ctx, a.cfg.SecOpsSubject, payload); err != nil {
		return SupportReply{}, fmt.Errorf("support: emit escalate: %w", err)
	}
	return SupportReply{
		Explanation: ExplainVerdictWith(cat, v, q.Locale),
		Confidence:  verdictConfidence(v),
		Suggestion:  escSuggestion,
		Escalated:   true,
	}, nil
}

// defaultExplanations is the package-level catalog loaded lazily.
var (
	defaultExplanationsOnce sync.Once
	defaultExplanations     *ExplanationCatalog
)

func getDefaultExplanations() *ExplanationCatalog {
	defaultExplanationsOnce.Do(func() {
		cat, err := DefaultExplanationCatalog()
		if err == nil {
			defaultExplanations = cat
		}
	})
	return defaultExplanations
}

// ExplainVerdict produces a plain-language explanation for an evaluation
// result in the requested locale. The output is deterministic so audit
// logs stay clean. Falls back to English when the locale is unavailable.
func ExplainVerdict(v dto.EvaluateResult, locale string) string {
	return ExplainVerdictWith(getDefaultExplanations(), v, locale)
}

// ExplainVerdictWith is the same as ExplainVerdict but uses the supplied
// catalog (useful for dependency injection in tests and SupportAgent).
func ExplainVerdictWith(cat *ExplanationCatalog, v dto.EvaluateResult, locale string) string {
	if cat == nil {
		return explainVerdictFallback(v)
	}
	var b strings.Builder
	b.WriteString(cat.TierExplanation(v.Tier, locale))
	if v.Primary != "" {
		b.WriteString(" ")
		b.WriteString(cat.PrimarySignalLabel(locale))
		b.WriteString(cat.CategoryName(v.Primary, locale))
		b.WriteString(".")
	}
	if len(v.ReasonCodes) > 0 {
		b.WriteString(" ")
		b.WriteString(cat.ContributingFactorsLabel(locale))
		b.WriteString(strings.Join(v.ReasonCodes, ", "))
		b.WriteString(".")
	}
	if v.Degraded {
		b.WriteString(" ")
		b.WriteString(cat.DegradedNotice(locale))
	}
	return b.String()
}

// explainVerdictFallback is the hardcoded English fallback used when the
// catalog fails to load.
func explainVerdictFallback(v dto.EvaluateResult) string {
	var b strings.Builder
	switch v.Tier {
	case constant.TierBlocked:
		b.WriteString("This message was blocked because our detection systems classified it as a likely threat.")
	case constant.TierHighRisk:
		b.WriteString("This message was flagged as high-risk and routed to your security team.")
	case constant.TierWarning:
		b.WriteString("This message looks suspicious — please review carefully before acting.")
	case constant.TierCaution:
		b.WriteString("This message has some unusual characteristics worth checking.")
	case constant.TierInformational:
		b.WriteString("This message is informational — first contact from an external sender.")
	case constant.TierTrusted:
		b.WriteString("This message comes from a trusted sender.")
	default:
		b.WriteString("Verdict pending.")
	}
	if v.Primary != "" {
		b.WriteString(" Primary signal: ")
		b.WriteString(humanCategory(v.Primary))
		b.WriteString(".")
	}
	if len(v.ReasonCodes) > 0 {
		b.WriteString(" Contributing factors: ")
		b.WriteString(strings.Join(v.ReasonCodes, ", "))
		b.WriteString(".")
	}
	if v.Degraded {
		b.WriteString(" Note: one or more detection services were unavailable during this evaluation.")
	}
	return b.String()
}

// DefaultSuggestion returns the standard call-to-action for a tier in
// the requested locale. Falls back to English.
func DefaultSuggestion(tier constant.Tier) string {
	return DefaultSuggestionLocale(tier, "en")
}

// DefaultSuggestionLocale returns the suggestion for a tier in the given locale.
func DefaultSuggestionLocale(tier constant.Tier, locale string) string {
	cat := getDefaultExplanations()
	if cat != nil {
		if s := cat.TierSuggestion(tier, locale); s != "" {
			return s
		}
	}
	// Hardcoded English fallback.
	switch tier {
	case constant.TierBlocked, constant.TierHighRisk:
		return "Do not interact with this message. Report it to your security team if anything looks legitimate."
	case constant.TierWarning:
		return "Verify the sender out-of-band before clicking links or replying."
	case constant.TierCaution:
		return "Treat any link or attachment with caution."
	case constant.TierInformational:
		return "First-time external sender — confirm before acting on requests."
	case constant.TierTrusted:
		return "No action required."
	default:
		return "No action required."
	}
}

func humanCategory(c constant.Category) string {
	switch c {
	case constant.CategoryLikelyPhishing:
		return "likely phishing"
	case constant.CategoryBECImpersonation:
		return "business-email-compromise / impersonation"
	case constant.CategoryLookalikeDomain:
		return "lookalike domain"
	case constant.CategorySuspiciousURL:
		return "suspicious URL"
	case constant.CategorySuspiciousAttachment:
		return "suspicious attachment"
	case constant.CategoryFirstContactExternal:
		return "first contact from outside your organisation"
	case constant.CategoryAccountTakeoverSuspected:
		return "account-takeover indicators"
	case constant.CategoryVendorCompromise:
		return "possible vendor compromise"
	case constant.CategoryCredentialHarvesting:
		return "credential harvesting"
	case constant.CategoryInvoiceFraud:
		return "invoice fraud"
	case constant.CategoryQRPhishing:
		return "QR-code phishing"
	case constant.CategoryScamFraud:
		return "scam / fraud"
	case constant.CategoryAuthFailed:
		return "failed sender authentication"
	case constant.CategoryInternalTrusted:
		return "internal trusted"
	case constant.CategoryVendorTrusted:
		return "trusted vendor"
	case constant.CategoryNewsletter:
		return "newsletter"
	default:
		return string(c)
	}
}

func verdictConfidence(v dto.EvaluateResult) float64 {
	if v.Tier2 != nil && v.Tier2.Confidence > 0 {
		return v.Tier2.Confidence
	}
	if v.Tier1 != nil && v.Tier1.Confidence > 0 {
		return v.Tier1.Confidence
	}
	if v.Tier0 != nil && v.Tier0.Bypass {
		return 1.0
	}
	return 0.5
}
