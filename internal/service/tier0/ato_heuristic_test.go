package tier0

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// hourPtr returns a *int for a literal hour value. Used to
// construct dto.RiskSignals.TypicalSendHour fixtures: the field is
// a pointer type so the wire-format distinction between "no
// baseline" (nil) and "midnight" (non-nil pointing to 0) is
// unambiguous.
func hourPtr(v int) *int { return &v }

func TestATOHeuristic_Disabled(t *testing.T) {
	h := NewATOHeuristic(ATOHeuristicConfig{Enabled: false})
	r := h.Check(dto.EvaluateRequest{Signals: dto.RiskSignals{IsInternal: true}}, dto.RiskSignals{IsInternal: true})
	if r.Flagged {
		t.Fatal("disabled heuristic should never flag")
	}
}

func TestATOHeuristic_CleanInternalPassesThrough(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "alice@company.com",
		Signals: dto.RiskSignals{
			IsInternal:             true,
			SenderDomain:           "company.com",
			CommunicationFrequency: 10,
			TypicalSendHour:        hourPtr(14),
			CurrentHourUTC:         15,
		},
	}
	r := h.Check(req, req.Signals)
	if r.Flagged {
		t.Errorf("clean internal message should not flag, score=%.2f reasons=%v", r.Score, r.Reasons)
	}
}

// TestATOHeuristic_TimingAnomaly_NoBaselineDoesNotFlag locks in
// the no-baseline guard. With TypicalSendHour as *int, "no
// baseline yet" is represented by a nil pointer rather than the
// historical -1 sentinel that was easy to forget on the producer
// side. The test also covers the defence-in-depth out-of-[0,24)
// guard for producer bugs that wrap a stale sentinel value in a
// non-nil pointer (e.g. a misconfigured signal-builder that still
// copies repository.TypicalHourUnset through without translating).
func TestATOHeuristic_TimingAnomaly_NoBaselineDoesNotFlag(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "alice@company.com",
		Signals: dto.RiskSignals{
			IsInternal:             true,
			SenderDomain:           "company.com",
			CommunicationFrequency: 20,
			// TypicalSendHour intentionally left nil to
			// represent "no baseline available yet."
			CurrentHourUTC: 2,
		},
	}
	r := h.Check(req, req.Signals)
	if contains(r.Reasons, "timing_anomaly") || contains(r.Reasons, "timing_unusual") {
		t.Errorf("nil TypicalSendHour must NOT produce timing reasons; got %v", r.Reasons)
	}
	if r.Score > 0 {
		t.Errorf("nil TypicalSendHour must contribute zero score; got %.2f", r.Score)
	}

	// Defence-in-depth: a non-nil pointer carrying a producer-bug
	// out-of-range value still must not flag (the heuristic treats
	// it as no-baseline rather than feeding garbage into hourDistance).
	req.Signals.TypicalSendHour = hourPtr(-1)
	r = h.Check(req, req.Signals)
	if contains(r.Reasons, "timing_anomaly") || contains(r.Reasons, "timing_unusual") {
		t.Errorf("out-of-range TypicalSendHour=-1 must NOT produce timing reasons; got %v", r.Reasons)
	}
	req.Signals.TypicalSendHour = hourPtr(24)
	r = h.Check(req, req.Signals)
	if contains(r.Reasons, "timing_anomaly") || contains(r.Reasons, "timing_unusual") {
		t.Errorf("out-of-range TypicalSendHour=24 must NOT produce timing reasons; got %v", r.Reasons)
	}
}

func TestATOHeuristic_TimingAnomaly(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "alice@company.com",
		Signals: dto.RiskSignals{
			IsInternal:             true,
			SenderDomain:           "company.com",
			CommunicationFrequency: 20,
			TypicalSendHour:        hourPtr(10),
			CurrentHourUTC:         2, // 8 hours off → triggers timing_anomaly
		},
	}
	r := h.Check(req, req.Signals)
	if !contains(r.Reasons, "timing_anomaly") {
		t.Errorf("expected timing_anomaly in reasons, got %v", r.Reasons)
	}
}

func TestATOHeuristic_ExternalCC(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "alice@company.com",
		CC:     []string{"attacker@evil.com", "partner@external.com", "spy@other.com"},
		Signals: dto.RiskSignals{
			IsInternal:   true,
			SenderDomain: "company.com",
		},
	}
	r := h.Check(req, req.Signals)
	if !contains(r.Reasons, "internal_sender_external_cc") {
		t.Errorf("expected internal_sender_external_cc, got %v", r.Reasons)
	}
}

func TestATOHeuristic_AuthFailure(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "alice@company.com",
		Signals: dto.RiskSignals{
			IsInternal:    true,
			HasFailedAuth: true,
		},
	}
	r := h.Check(req, req.Signals)
	if !contains(r.Reasons, "internal_auth_failed") {
		t.Errorf("expected internal_auth_failed, got %v", r.Reasons)
	}
	if !r.Flagged {
		t.Error("auth failure on internal should flag")
	}
}

func TestATOHeuristic_LinkHeavy(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "alice@company.com",
		Body:   "Click https://evil.com/1 and https://evil.com/2 and https://evil.com/3",
		Signals: dto.RiskSignals{
			IsInternal:       true,
			HasSuspiciousURL: true,
		},
	}
	r := h.Check(req, req.Signals)
	if !contains(r.Reasons, "link_heavy_internal") {
		t.Errorf("expected link_heavy_internal, got %v", r.Reasons)
	}
}

func TestATOHeuristic_MultipleSignalsCombine(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "alice@company.com",
		CC:     []string{"external@evil.com"},
		Signals: dto.RiskSignals{
			IsInternal:             true,
			SenderDomain:           "company.com",
			CommunicationFrequency: 20,
			TypicalSendHour:        hourPtr(10),
			CurrentHourUTC:         2,
		},
	}
	r := h.Check(req, req.Signals)
	if !r.Flagged {
		t.Errorf("combined timing+cc should flag, score=%.2f reasons=%v", r.Score, r.Reasons)
	}
	if len(r.Reasons) < 2 {
		t.Errorf("expected >=2 reasons, got %v", r.Reasons)
	}
}

func TestGate_InternalATOBlocksBypass(t *testing.T) {
	cfg := DefaultGateConfig()
	ato := NewATOHeuristic(DefaultATOHeuristicConfig())
	g := NewGateWithATO(cfg, nil, ato)

	// Internal with auth failure → ATO flagged → no bypass.
	req := dto.EvaluateRequest{
		Sender: "alice@company.com",
		Signals: dto.RiskSignals{
			IsInternal:    true,
			HasFailedAuth: true,
		},
	}
	out := g.Apply(req, req.Signals)
	if out.Bypass {
		t.Error("ATO-flagged internal message should NOT bypass")
	}
	if !out.ForceEscalate {
		t.Error("ATO-flagged internal message should force escalate")
	}
	if out.Reason != "internal_ato_suspected" {
		t.Errorf("expected reason=internal_ato_suspected, got %q", out.Reason)
	}
}

func TestGate_CleanInternalStillBypasses(t *testing.T) {
	g := NewGate(DefaultGateConfig(), nil)
	req := dto.EvaluateRequest{
		Sender:  "alice@company.com",
		Signals: dto.RiskSignals{IsInternal: true},
	}
	out := g.Apply(req, req.Signals)
	if !out.Bypass {
		t.Error("clean internal should still bypass")
	}
	if out.Reason != "internal_trusted" {
		t.Errorf("expected reason=internal_trusted, got %q", out.Reason)
	}
}

func TestATOHeuristic_HighPrivilegeToFreemail(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "dba@company.com",
		Signals: dto.RiskSignals{
			IsInternal:            true,
			SenderDomain:          "company.com",
			RecipientDomain:       "gmail.com",
			SenderSensitivity:     "critical",
			RecipientIsFreeDomain: true,
		},
	}
	r := h.Check(req, req.Signals)
	if !contains(r.Reasons, "high_privilege_to_freemail") {
		t.Errorf("expected high_privilege_to_freemail, got %v", r.Reasons)
	}
}

func TestATOHeuristic_HighPrivilegeExternalAttachment(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "ceo@company.com",
		Signals: dto.RiskSignals{
			IsInternal:        true,
			SenderDomain:      "company.com",
			RecipientDomain:   "external-partner.com",
			SenderSensitivity: "max",
			HasAttachment:     true,
		},
	}
	r := h.Check(req, req.Signals)
	if !contains(r.Reasons, "high_privilege_external_attachment") {
		t.Errorf("expected high_privilege_external_attachment, got %v", r.Reasons)
	}
}

func TestATOHeuristic_HighPrivilegeLowerThreshold(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	// A critical sender with timing unusual (0.15) + freemail (0.3) =
	// 0.45 total. This exceeds the lowered 0.4 threshold for critical
	// senders but would NOT exceed the default 0.5 threshold.
	req := dto.EvaluateRequest{
		Sender: "sysadmin@company.com",
		Signals: dto.RiskSignals{
			IsInternal:             true,
			SenderDomain:           "company.com",
			RecipientDomain:        "gmail.com",
			SenderSensitivity:      "critical",
			RecipientIsFreeDomain:  true,
			CommunicationFrequency: 20,
			TypicalSendHour:        hourPtr(10),
			CurrentHourUTC:         5, // 5 hours off → timing_unusual (0.15)
		},
	}
	r := h.Check(req, req.Signals)
	if !r.Flagged {
		t.Errorf("critical sender with timing unusual + freemail should be flagged at lower threshold, score=%.2f reasons=%v", r.Score, r.Reasons)
	}
}

func TestATOHeuristic_NormalUserNotFlaggedAtSameScore(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	// A default-sensitivity sender with same timing anomaly (0.35) should
	// NOT be flagged because the default threshold is 0.5.
	req := dto.EvaluateRequest{
		Sender: "engineer@company.com",
		Signals: dto.RiskSignals{
			IsInternal:             true,
			SenderDomain:           "company.com",
			SenderSensitivity:      "default",
			CommunicationFrequency: 20,
			TypicalSendHour:        hourPtr(10),
			CurrentHourUTC:         2,
		},
	}
	r := h.Check(req, req.Signals)
	if r.Flagged {
		t.Errorf("default sender with only timing anomaly should not be flagged at default threshold, score=%.2f", r.Score)
	}
}

func TestATOHeuristic_DisposableDomainHighPrivilege(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	req := dto.EvaluateRequest{
		Sender: "admin@company.com",
		Signals: dto.RiskSignals{
			IsInternal:                  true,
			SenderDomain:                "company.com",
			RecipientDomain:             "tempmail.io",
			SenderSensitivity:           "critical",
			RecipientIsDisposableDomain: true,
		},
	}
	r := h.Check(req, req.Signals)
	if !contains(r.Reasons, "high_privilege_to_freemail") {
		t.Errorf("expected high_privilege_to_freemail for disposable domain, got %v", r.Reasons)
	}
}

// TestATOHeuristic_BatchPathSignalsArePositional protects the contract
// the batch orchestrator depends on: signals arrive as a separate
// argument and req.Signals may be the zero value. Every sub-check must
// read from the positional signals argument, otherwise an
// ATO-compromised internal sender in the batch path would silently get
// the trusted bypass.
//
// We pose the worst case — req.Signals is fully zero, the explicit
// signals argument carries every red flag — and assert the heuristic
// still flags. Before the gate.Apply / ATO refactor was completed,
// this test would have failed because ATO.Check read req.Signals.*.
func TestATOHeuristic_BatchPathSignalsArePositional(t *testing.T) {
	h := NewATOHeuristic(DefaultATOHeuristicConfig())
	// Authoritative signals carry the auth-failure red flag, which on
	// its own is worth 0.6 and trivially exceeds the default 0.5
	// threshold.
	signals := dto.RiskSignals{
		IsInternal:    true,
		SenderDomain:  "company.com",
		HasFailedAuth: true,
	}
	// The request envelope intentionally carries a zero Signals
	// value — this is what the batch orchestrator hands us.
	req := dto.EvaluateRequest{
		Sender:  "alice@company.com",
		Signals: dto.RiskSignals{}, // explicit zero
	}
	r := h.Check(req, signals)
	if !r.Flagged {
		t.Fatalf("ATO heuristic ignored the explicit signals argument; score=%.2f reasons=%v — every sub-check must read from the positional signals param, not req.Signals", r.Score, r.Reasons)
	}
	if !contains(r.Reasons, "internal_auth_failed") {
		t.Errorf("expected internal_auth_failed in reasons, got %v", r.Reasons)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
