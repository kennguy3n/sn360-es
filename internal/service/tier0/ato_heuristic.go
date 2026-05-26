package tier0

import (
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// ATOHeuristicConfig controls the lightweight account-takeover check
// applied to internal-origin messages before they receive a bypass.
type ATOHeuristicConfig struct {
	// Enabled gates the entire heuristic. Defaults to true.
	Enabled bool
	// MinTimingHistorySize is the minimum number of observed sends
	// before the timing anomaly signal is trusted.
	MinTimingHistorySize int
	// LinkHeavyThreshold is the minimum link count for a "link-heavy"
	// classification on a sender that normally sends text-only.
	LinkHeavyThreshold int
	// ScoreThreshold: when the combined ATO heuristic score meets or
	// exceeds this value (0.0–1.0) the message is NOT bypassed.
	ScoreThreshold float64
}

// DefaultATOHeuristicConfig returns production defaults.
func DefaultATOHeuristicConfig() ATOHeuristicConfig {
	return ATOHeuristicConfig{
		Enabled:              true,
		MinTimingHistorySize: 5,
		LinkHeavyThreshold:   3,
		ScoreThreshold:       0.5,
	}
}

// ATOHeuristicResult is the output of CheckATO.
type ATOHeuristicResult struct {
	Flagged bool
	Score   float64
	Reasons []string
}

// ATOHeuristic performs a lightweight account-takeover check on
// internal messages before granting them the trusted bypass.
type ATOHeuristic struct {
	cfg ATOHeuristicConfig
}

// NewATOHeuristic constructs the heuristic with the given config.
func NewATOHeuristic(cfg ATOHeuristicConfig) *ATOHeuristic {
	return &ATOHeuristic{cfg: cfg}
}

// Check evaluates the ATO heuristic against an internal-origin message.
// The caller should only invoke this when the message has already been
// identified as internal (signals.IsInternal == true).
//
// signals is passed explicitly rather than read from req.Signals so the
// batch and per-message paths share one calling convention. The batch
// orchestrator stores signals on [evaluate.BatchMessage] as a separate
// field from the EvaluateRequest envelope — passing them positionally
// here lets every sub-check read from the authoritative source
// regardless of whether req.Signals has been populated by the caller.
//
// Signals checked:
//   - Timing anomaly: message sent far outside the sender's normal window.
//   - External recipients: an internal sender CC'ing external addresses.
//   - Link-heavy body: sender normally sends text-only but this message
//     is link-heavy.
//   - Auth failure on an internal sender (should never happen legitimately).
//   - High-privilege outbound: Critical/Max sender emailing freemail/disposable.
func (h *ATOHeuristic) Check(req dto.EvaluateRequest, signals dto.RiskSignals) ATOHeuristicResult {
	if !h.cfg.Enabled {
		return ATOHeuristicResult{}
	}

	var score float64
	var reasons []string

	// 1. Timing anomaly: use the pre-computed signals.
	score += h.checkTimingAnomaly(signals, &reasons)

	// 2. External recipients on an internal-origin message.
	score += h.checkExternalRecipients(req, signals, &reasons)

	// 3. Link-heavy body from text-only sender.
	score += h.checkLinkHeavy(req, signals, &reasons)

	// 4. Auth failure on internal sender.
	score += h.checkAuthFailure(signals, &reasons)

	// 5. High-privilege outbound: Critical/Max user sending to freemail
	// or disposable domains is an insider-threat signal regardless of
	// content.
	score += h.checkHighPrivilegeOutbound(signals, &reasons)

	// Apply sensitivity-based threshold adjustment: Critical/Max users
	// use a lower threshold (0.4 instead of default) so suspicious
	// behaviour triggers alerts more easily.
	threshold := h.cfg.ScoreThreshold
	if isHighPrivilegeSender(signals) {
		if threshold > 0.4 {
			threshold = 0.4
		}
	}

	if score > 1.0 {
		score = 1.0
	}

	return ATOHeuristicResult{
		Flagged: score >= threshold,
		Score:   score,
		Reasons: reasons,
	}
}

// checkTimingAnomaly inspects whether the send time is anomalous
// relative to the sender's historical pattern. We use pre-computed
// signals: TypicalSendHour and CurrentHourUTC.
//
// TypicalSendHour follows the same convention as
// repository.CommunicationHistory.TypicalHour (which the
// signal-builder copies into the DTO): a value in [0, 24) is a
// real modal hour computed by the relationship worker; anything
// outside that range is the "no baseline yet" sentinel. Concretely
// the worker writes -1 (repository.TypicalHourUnset) and the
// Postgres column defaults to -1 via migration 0007 — guarding on
// just `== 0` would miss the sentinel and let hourDistance(-1, …)
// produce a spurious timing_anomaly score the moment the
// signal-builder wire-up lands. The explicit out-of-range guard
// here lets the heuristic stay correct without depending on a
// translation step in the signal builder.
func (h *ATOHeuristic) checkTimingAnomaly(signals dto.RiskSignals, reasons *[]string) float64 {
	if signals.TypicalSendHour < 0 || signals.TypicalSendHour >= 24 {
		return 0 // Sentinel: no baseline data available.
	}
	if signals.CommunicationFrequency == 0 {
		return 0 // No history yet.
	}
	if signals.CommunicationFrequency < h.cfg.MinTimingHistorySize {
		return 0 // Insufficient history.
	}
	hourDist := hourDistance(signals.CurrentHourUTC, signals.TypicalSendHour)
	if hourDist >= 8 {
		*reasons = append(*reasons, "timing_anomaly")
		return 0.35
	}
	if hourDist >= 5 {
		*reasons = append(*reasons, "timing_unusual")
		return 0.15
	}
	return 0
}

// checkExternalRecipients detects internal-origin messages with external
// CC recipients — a common ATO exfiltration pattern.
func (h *ATOHeuristic) checkExternalRecipients(req dto.EvaluateRequest, signals dto.RiskSignals, reasons *[]string) float64 {
	if len(req.CC) == 0 {
		return 0
	}
	senderDomain := signals.SenderDomain
	if senderDomain == "" {
		return 0
	}
	externalCount := 0
	for _, cc := range req.CC {
		parts := strings.SplitN(cc, "@", 2)
		if len(parts) == 2 && !strings.EqualFold(parts[1], senderDomain) {
			externalCount++
		}
	}
	if externalCount > 0 {
		*reasons = append(*reasons, "internal_sender_external_cc")
		if externalCount >= 3 {
			return 0.35
		}
		return 0.2
	}
	return 0
}

// checkLinkHeavy detects internal messages with unusually many URLs.
func (h *ATOHeuristic) checkLinkHeavy(req dto.EvaluateRequest, signals dto.RiskSignals, reasons *[]string) float64 {
	if !signals.HasSuspiciousURL {
		return 0
	}
	linkCount := countLinks(req.Body)
	if linkCount >= h.cfg.LinkHeavyThreshold {
		*reasons = append(*reasons, "link_heavy_internal")
		return 0.25
	}
	return 0
}

// checkAuthFailure flags internal senders with failed authentication
// — should never happen for legitimate internal mail.
func (h *ATOHeuristic) checkAuthFailure(signals dto.RiskSignals, reasons *[]string) float64 {
	if signals.AnyAuthFailed() {
		*reasons = append(*reasons, "internal_auth_failed")
		// Auth failure on internal mail is highly suspicious — it should
		// never happen legitimately. Score high enough to flag on its own.
		return 0.6
	}
	return 0
}

// countLinks is a lightweight URL counter for the message body.
func countLinks(body string) int {
	count := 0
	for _, scheme := range []string{"http://", "https://"} {
		idx := 0
		for {
			pos := strings.Index(body[idx:], scheme)
			if pos == -1 {
				break
			}
			count++
			idx += pos + len(scheme)
		}
	}
	return count
}

// hourDistance returns the circular distance (0..12) between two hours.
func hourDistance(a, b int) int {
	a = ((a % 24) + 24) % 24
	b = ((b % 24) + 24) % 24
	d := a - b
	if d < 0 {
		d = -d
	}
	if d > 12 {
		d = 24 - d
	}
	return d
}

// checkHighPrivilegeOutbound flags when a Critical/Max sensitivity user
// sends email to freemail or disposable domains. The combination of
// high-privilege sender + personal email recipient is an insider-threat
// signal even without suspicious content.
func (h *ATOHeuristic) checkHighPrivilegeOutbound(signals dto.RiskSignals, reasons *[]string) float64 {
	if !isHighPrivilegeSender(signals) {
		return 0
	}
	var score float64

	// Freemail / disposable recipient.
	if signals.RecipientIsFreeDomain || signals.RecipientIsDisposableDomain {
		*reasons = append(*reasons, "high_privilege_to_freemail")
		score += 0.3
	}

	// Attachment to non-internal recipient. RecipientIsFreeDomain and
	// RecipientIsDisposableDomain are populated by the normalizer from
	// the recipient's domain, not the sender's.
	recipientIsExternal := signals.RecipientIsFreeDomain || signals.RecipientIsDisposableDomain ||
		(!signals.IsFromVendor && signals.RecipientDomain != "" &&
			!strings.EqualFold(signals.RecipientDomain, signals.SenderDomain))
	if signals.HasAttachment && recipientIsExternal {
		*reasons = append(*reasons, "high_privilege_external_attachment")
		score += 0.2
	}

	return score
}

// isHighPrivilegeSender returns true when the sender's sensitivity tier
// is "critical" or "max", indicating infrastructure-level or C-suite
// access.
func isHighPrivilegeSender(signals dto.RiskSignals) bool {
	s := strings.ToLower(signals.SenderSensitivity)
	return s == "critical" || s == "max"
}

// ReceivedAtOrNow returns ReceivedAt if set, otherwise Now.
func ReceivedAtOrNow(req dto.EvaluateRequest) time.Time {
	if !req.ReceivedAt.IsZero() {
		return req.ReceivedAt
	}
	return time.Now().UTC()
}
