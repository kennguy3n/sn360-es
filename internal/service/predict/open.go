package predict

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// OpenRequest is the request body for POST /v1/predict/open. It carries
// a pseudonymised message ID and (optionally) the tier/category the
// message already received from the evaluation pipeline. When Tier is
// empty the service falls back to a repository lookup keyed by tenant
// + pseudo_message_id.
type OpenRequest struct {
	TenantID        string `json:"tenant_id"`
	PseudoMessageID string `json:"pseudo_message_id"`
	UserHash        string `json:"user_hash,omitempty"`
	Tier            string `json:"tier,omitempty"`
	Category        string `json:"category,omitempty"`
}

// OpenResponse is returned by the pre-open predictor.
type OpenResponse struct {
	ShowWarning bool         `json:"show_warning"`
	Level       WarningLevel `json:"level"`
	Tier        string       `json:"tier,omitempty"`
	Code        string       `json:"code"`
	Reason      string       `json:"reason,omitempty"`
	Message     string       `json:"message"`
	LatencyMs   int64        `json:"latency_ms"`
}

// OpenLookup is the repository contract the OpenService uses when the
// add-in caller does not pre-supply Tier/Category. Implementations
// typically wrap repository.EvaluationResultRepository plus a Redis
// cache; tests use an in-memory fake.
type OpenLookup interface {
	// Lookup returns the recorded tier + primary category for the
	// pseudonymised message, or ok=false when none is on file.
	Lookup(ctx context.Context, tenantID, pseudoMessageID string) (tier, primary string, ok bool, err error)
}

// OpenServiceConfig wires the pre-open predictor.
type OpenServiceConfig struct {
	Lookup OpenLookup
	Clock  func() time.Time
}

// OpenService checks whether a message should show a pre-open warning.
// It is safe for concurrent use.
type OpenService struct {
	lookup OpenLookup
	now    func() time.Time
}

// NewOpenService constructs the service with optional repository
// lookup. Either OpenServiceConfig{} or OpenServiceConfig{Lookup: ...}
// is acceptable.
func NewOpenService(cfg OpenServiceConfig) *OpenService {
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &OpenService{lookup: cfg.Lookup, now: cfg.Clock}
}

// Predict returns the warning payload. For tiers below Warning, no
// warning is returned (and the add-in renders the message normally).
//
// When the caller does not supply a Tier and a repository lookup is
// wired, the service consults the lookup. If no record is found the
// response is empty (no warning) so add-ins fail-open on previously
// un-evaluated messages.
func (s *OpenService) Predict(ctx context.Context, req OpenRequest) (OpenResponse, error) {
	start := s.now()
	if req.TenantID == "" {
		return OpenResponse{}, errors.New("predict: tenant_id is required")
	}
	if utf8.RuneCountInString(req.PseudoMessageID) == 0 {
		return OpenResponse{}, errors.New("predict: pseudo_message_id is required")
	}
	tier := strings.ToLower(strings.TrimSpace(req.Tier))
	primary := strings.TrimSpace(req.Category)
	if tier == "" && s.lookup != nil {
		t, p, ok, err := s.lookup.Lookup(ctx, req.TenantID, req.PseudoMessageID)
		if err != nil {
			return OpenResponse{}, err
		}
		if ok {
			tier = strings.ToLower(strings.TrimSpace(t))
			if primary == "" {
				primary = p
			}
		}
	}
	out := OpenResponse{Tier: tier, Reason: sanitisePrimary(primary)}
	switch tier {
	case "blocked":
		out.ShowWarning = true
		out.Level = WarnHigh
		out.Code = "tier_blocked"
		out.Message = "This message was blocked by SN360. Open the quarantine to review."
	case "high_risk", "highrisk":
		out.ShowWarning = true
		out.Level = WarnHigh
		out.Code = "tier_high_risk"
		out.Message = "High risk: this message looks like a phishing attempt."
	case "warning":
		out.ShowWarning = true
		out.Level = WarnWarning
		out.Code = "tier_warning"
		out.Message = "Be careful — this message has suspicious indicators."
	case "caution":
		out.ShowWarning = true
		out.Level = WarnCaution
		out.Code = "tier_caution"
		out.Message = "Use caution. Verify before clicking links or sharing data."
	default:
		// Informational, Trusted, or unknown — no pre-open warning.
	}
	out.LatencyMs = s.now().Sub(start).Milliseconds()
	return out, nil
}

// sanitisePrimary reports the primary category in a UX-safe form. We
// only echo categories from the validated enum so a poisoned cache
// can't push arbitrary strings through the add-in surface.
func sanitisePrimary(primary string) string {
	if primary == "" {
		return ""
	}
	cat := constant.Category(primary)
	if !cat.Valid() {
		return ""
	}
	return string(cat)
}
