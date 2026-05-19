package predict

import (
	"context"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// URLRecheckResult captures a single URL re-check outcome.
type URLRecheckResult struct {
	URL      string `json:"url"`
	OldScore int    `json:"old_score"`
	NewScore int    `json:"new_score"`
	Upgraded bool   `json:"upgraded"`
}

// URLIntelChecker is the interface the pre-open URL re-checker uses.
// It is satisfied by the evaluate.URLScanner.
type URLIntelChecker interface {
	ScanURL(ctx context.Context, url string) (score int, verdict string, err error)
}

// MessageURLLookup retrieves the URLs associated with a pseudonymized
// message ID. Backed by the evaluation result repository.
type MessageURLLookup interface {
	LookupURLs(ctx context.Context, tenantID, pseudoMessageID string) ([]string, error)
}

// URLRecheckConfig wires the pre-open URL re-check service.
type URLRecheckConfig struct {
	Scanner URLIntelChecker
	URLs    MessageURLLookup
	Logger  *slog.Logger
	Clock   func() time.Time
	// UpgradeThreshold is the score above which a URL is considered
	// newly malicious. Defaults to 60.
	UpgradeThreshold int
}

// URLRecheckService re-checks URLs at pre-open time against updated
// threat intelligence. If any URL now scores higher than the original
// evaluation, the warning level is upgraded.
type URLRecheckService struct {
	scanner   URLIntelChecker
	urls      MessageURLLookup
	log       *slog.Logger
	now       func() time.Time
	threshold int
}

// NewURLRecheckService constructs the service.
func NewURLRecheckService(cfg URLRecheckConfig) *URLRecheckService {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.UpgradeThreshold <= 0 {
		cfg.UpgradeThreshold = 60
	}
	return &URLRecheckService{
		scanner:   cfg.Scanner,
		urls:      cfg.URLs,
		log:       cfg.Logger,
		now:       cfg.Clock,
		threshold: cfg.UpgradeThreshold,
	}
}

// Recheck scans all URLs associated with the message using current
// threat intelligence and returns whether the warning should be
// upgraded.
func (s *URLRecheckService) Recheck(ctx context.Context, tenantID, pseudoMessageID string, currentTier constant.Tier) (*OpenResponse, error) {
	if s.scanner == nil || s.urls == nil {
		return nil, nil
	}

	urls, err := s.urls.LookupURLs(ctx, tenantID, pseudoMessageID)
	if err != nil {
		s.log.WarnContext(ctx, "url_recheck: lookup URLs failed",
			slog.String("tenant", tenantID),
			slog.Any("error", err))
		return nil, nil
	}
	if len(urls) == 0 {
		return nil, nil
	}

	maxScore := 0
	var results []URLRecheckResult
	for _, u := range urls {
		score, _, serr := s.scanner.ScanURL(ctx, u)
		if serr != nil {
			s.log.WarnContext(ctx, "url_recheck: scan failed",
				slog.String("url", u),
				slog.Any("error", serr))
			continue
		}
		results = append(results, URLRecheckResult{
			URL:      u,
			NewScore: score,
			Upgraded: score >= s.threshold,
		})
		if score > maxScore {
			maxScore = score
		}
	}

	if maxScore < s.threshold {
		return nil, nil
	}

	// Determine the upgrade tier based on the max URL score.
	upgradeTier := constant.TierWarning
	if maxScore >= 80 {
		upgradeTier = constant.TierHighRisk
	}
	if maxScore >= 95 {
		upgradeTier = constant.TierBlocked
	}

	// Only upgrade, never downgrade.
	if upgradeTier.Severity() <= currentTier.Severity() {
		return nil, nil
	}

	s.log.InfoContext(ctx, "url_recheck: upgrading warning",
		slog.String("tenant", tenantID),
		slog.String("message", pseudoMessageID),
		slog.String("old_tier", string(currentTier)),
		slog.String("new_tier", string(upgradeTier)),
		slog.Int("max_url_score", maxScore))

	resp := &OpenResponse{
		ShowWarning: true,
		Tier:        string(upgradeTier),
		Code:        "url_recheck_upgrade",
		Reason:      "url_threat_intel_update",
		Message:     "Updated threat intelligence detected a newly flagged URL in this message.",
	}
	switch upgradeTier {
	case constant.TierBlocked:
		resp.Level = WarnHigh
	case constant.TierHighRisk:
		resp.Level = WarnHigh
	default:
		resp.Level = WarnWarning
	}
	return resp, nil
}

// EnhancedOpenServiceConfig extends OpenServiceConfig with URL re-check.
type EnhancedOpenServiceConfig struct {
	OpenServiceConfig
	URLRecheck *URLRecheckService
}

// EnhancedOpenService wraps OpenService with URL re-check at pre-open.
type EnhancedOpenService struct {
	base    *OpenService
	recheck *URLRecheckService
}

// NewEnhancedOpenService constructs the enhanced service.
func NewEnhancedOpenService(cfg EnhancedOpenServiceConfig) *EnhancedOpenService {
	return &EnhancedOpenService{
		base:    NewOpenService(cfg.OpenServiceConfig),
		recheck: cfg.URLRecheck,
	}
}

// Predict runs the base pre-open check and then optionally re-checks
// URLs against updated threat intelligence.
func (s *EnhancedOpenService) Predict(ctx context.Context, req OpenRequest) (OpenResponse, error) {
	resp, err := s.base.Predict(ctx, req)
	if err != nil {
		return resp, err
	}

	if s.recheck == nil {
		return resp, nil
	}

	currentTier := canonicaliseTier(resp.Tier)
	upgrade, rerr := s.recheck.Recheck(ctx, req.TenantID, req.PseudoMessageID, currentTier)
	if rerr != nil || upgrade == nil {
		return resp, nil
	}

	// Use the upgraded response, preserving the original latency.
	upgrade.LatencyMs = resp.LatencyMs
	return *upgrade, nil
}
