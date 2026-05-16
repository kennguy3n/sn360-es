// Package predict implements the pre-send / pre-open risk predictors
// exposed to mail-client add-ins. These run on the hot path (<300ms
// p95) and only consume metadata that the add-in can safely send (no
// raw email bodies). See PROPOSAL.md §6 "Pre-Send & Pre-Open Warnings".
package predict

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// WarningLevel matches the banner tier scale (0 = none .. 4 = critical).
type WarningLevel int

const (
	WarnNone     WarningLevel = 0
	WarnInfo     WarningLevel = 1
	WarnCaution  WarningLevel = 2
	WarnWarning  WarningLevel = 3
	WarnHigh     WarningLevel = 4
)

// String returns the canonical name of the warning level.
func (l WarningLevel) String() string {
	switch l {
	case WarnNone:
		return "none"
	case WarnInfo:
		return "info"
	case WarnCaution:
		return "caution"
	case WarnWarning:
		return "warning"
	case WarnHigh:
		return "high"
	}
	return "unknown"
}

// RecipientRequest is the request body for POST /v1/predict/recipient.
// PII is never sent — recipients are referenced by pseudonymised hashes
// and (optionally) their domains for lookalike checks.
type RecipientRequest struct {
	TenantID         string             `json:"tenant_id"`
	SenderHash       string             `json:"sender_hash"`
	Recipients       []RecipientCandidate `json:"recipients"`
	ThreadID         string             `json:"thread_id,omitempty"`
	ThreadIsInternal bool               `json:"thread_is_internal,omitempty"`
}

// RecipientCandidate represents a single recipient under consideration.
type RecipientCandidate struct {
	UserHash string `json:"user_hash"`
	Domain   string `json:"domain"`
	IsExternal bool `json:"is_external"`
	IsKnownContact bool `json:"is_known_contact"`
}

// RecipientWarning is the per-recipient finding returned to the add-in.
type RecipientWarning struct {
	UserHash string       `json:"user_hash"`
	Level    WarningLevel `json:"level"`
	Code     string       `json:"code"`
	Message  string       `json:"message"`
}

// RecipientResponse aggregates per-recipient warnings.
type RecipientResponse struct {
	OverallLevel WarningLevel       `json:"overall_level"`
	Warnings     []RecipientWarning `json:"warnings"`
	LatencyMs    int64              `json:"latency_ms"`
}

// LookalikeChecker reports whether the supplied recipient domain is a
// lookalike of a known internal or vendor domain.
type LookalikeChecker interface {
	IsLookalike(ctx context.Context, tenantID, domain string) (bool, string, error)
}

// RecipientServiceConfig wires the recipient predictor.
type RecipientServiceConfig struct {
	Lookalike LookalikeChecker
	Clock     func() time.Time
}

// RecipientService implements the pre-send recipient predictor.
type RecipientService struct {
	lookalike LookalikeChecker
	now       func() time.Time
}

// NewRecipientService constructs the service.
func NewRecipientService(cfg RecipientServiceConfig) *RecipientService {
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &RecipientService{lookalike: cfg.Lookalike, now: cfg.Clock}
}

// Predict evaluates the request and returns the warning bundle. It is
// safe for concurrent use.
func (s *RecipientService) Predict(ctx context.Context, req RecipientRequest) (RecipientResponse, error) {
	start := s.now()
	if req.TenantID == "" {
		return RecipientResponse{}, errors.New("predict: tenant_id is required")
	}
	if len(req.Recipients) == 0 {
		return RecipientResponse{}, errors.New("predict: at least one recipient is required")
	}
	out := RecipientResponse{}
	for _, r := range req.Recipients {
		w := s.checkRecipient(ctx, req, r)
		if w.Level > WarnNone {
			out.Warnings = append(out.Warnings, w)
			if w.Level > out.OverallLevel {
				out.OverallLevel = w.Level
			}
		}
	}
	out.LatencyMs = s.now().Sub(start).Milliseconds()
	return out, nil
}

func (s *RecipientService) checkRecipient(ctx context.Context, req RecipientRequest, r RecipientCandidate) RecipientWarning {
	domain := strings.ToLower(strings.TrimSpace(r.Domain))
	// Lookalike domain → high severity.
	if s.lookalike != nil && domain != "" {
		if hit, ref, err := s.lookalike.IsLookalike(ctx, req.TenantID, domain); err == nil && hit {
			return RecipientWarning{
				UserHash: r.UserHash,
				Level:    WarnHigh,
				Code:     "lookalike_recipient",
				Message:  "Recipient domain looks similar to " + ref + ". Double-check before sending.",
			}
		}
	}
	// External recipient added to a previously-internal thread.
	if req.ThreadIsInternal && r.IsExternal {
		return RecipientWarning{
			UserHash: r.UserHash,
			Level:    WarnWarning,
			Code:     "external_on_internal_thread",
			Message:  "You're adding an external recipient to a previously internal thread.",
		}
	}
	// Unusual external recipient (no prior contact history).
	if r.IsExternal && !r.IsKnownContact {
		return RecipientWarning{
			UserHash: r.UserHash,
			Level:    WarnCaution,
			Code:     "unusual_external_recipient",
			Message:  "This is the first time you're emailing this recipient.",
		}
	}
	return RecipientWarning{UserHash: r.UserHash, Level: WarnNone}
}

// OpenRequest is the request body for POST /v1/predict/open. It carries
// a pseudonymised message ID and the tier/category the message already
// received from the evaluation pipeline.
type OpenRequest struct {
	TenantID         string `json:"tenant_id"`
	PseudoMessageID  string `json:"pseudo_message_id"`
	Tier             string `json:"tier"`
	Category         string `json:"category"`
}

// OpenResponse is returned by the pre-open predictor.
type OpenResponse struct {
	ShowWarning bool         `json:"show_warning"`
	Level       WarningLevel `json:"level"`
	Code        string       `json:"code"`
	Message     string       `json:"message"`
	LatencyMs   int64        `json:"latency_ms"`
}

// OpenService implements the pre-open warning predictor.
type OpenService struct {
	now func() time.Time
}

// NewOpenService constructs the service.
func NewOpenService() *OpenService { return &OpenService{now: func() time.Time { return time.Now().UTC() }} }

// Predict returns the warning payload. For tiers below Warning, no
// warning is returned (and the add-in renders the message normally).
func (s *OpenService) Predict(_ context.Context, req OpenRequest) (OpenResponse, error) {
	start := s.now()
	if req.TenantID == "" {
		return OpenResponse{}, errors.New("predict: tenant_id is required")
	}
	if utf8.RuneCountInString(req.PseudoMessageID) == 0 {
		return OpenResponse{}, errors.New("predict: pseudo_message_id is required")
	}
	tier := strings.ToLower(strings.TrimSpace(req.Tier))
	out := OpenResponse{}
	switch tier {
	case "blocked":
		out = OpenResponse{ShowWarning: true, Level: WarnHigh, Code: "tier_blocked",
			Message: "This message was blocked by SN360. Open the quarantine to review."}
	case "high_risk", "highrisk":
		out = OpenResponse{ShowWarning: true, Level: WarnHigh, Code: "tier_high_risk",
			Message: "High risk: this message looks like a phishing attempt."}
	case "warning":
		out = OpenResponse{ShowWarning: true, Level: WarnWarning, Code: "tier_warning",
			Message: "Be careful — this message has suspicious indicators."}
	case "caution":
		out = OpenResponse{ShowWarning: true, Level: WarnCaution, Code: "tier_caution",
			Message: "Use caution. Verify before clicking links or sharing data."}
	default:
		// Informational and Trusted do not trigger pre-open warnings.
	}
	out.LatencyMs = s.now().Sub(start).Milliseconds()
	return out, nil
}

// StaticLookalikeChecker is a deterministic LookalikeChecker for tests
// and small deployments. Matches are configured ahead of time.
type StaticLookalikeChecker struct {
	matches map[string]string // domain → reference domain
}

// NewStaticLookalikeChecker constructs a checker. The map must be
// populated by the caller.
func NewStaticLookalikeChecker(m map[string]string) *StaticLookalikeChecker {
	out := &StaticLookalikeChecker{matches: map[string]string{}}
	for k, v := range m {
		out.matches[strings.ToLower(k)] = v
	}
	return out
}

// IsLookalike implements LookalikeChecker.
func (s *StaticLookalikeChecker) IsLookalike(_ context.Context, _ string, domain string) (bool, string, error) {
	ref, ok := s.matches[strings.ToLower(domain)]
	return ok, ref, nil
}
