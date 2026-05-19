package tier0

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestATOHeuristic_Disabled(t *testing.T) {
	h := NewATOHeuristic(ATOHeuristicConfig{Enabled: false})
	r := h.Check(dto.EvaluateRequest{Signals: dto.RiskSignals{IsInternal: true}})
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
			TypicalSendHour:        14,
			CurrentHourUTC:         15,
		},
	}
	r := h.Check(req)
	if r.Flagged {
		t.Errorf("clean internal message should not flag, score=%.2f reasons=%v", r.Score, r.Reasons)
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
			TypicalSendHour:        10,
			CurrentHourUTC:         2, // 8 hours off → triggers timing_anomaly
		},
	}
	r := h.Check(req)
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
	r := h.Check(req)
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
	r := h.Check(req)
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
	r := h.Check(req)
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
			TypicalSendHour:        10,
			CurrentHourUTC:         2,
		},
	}
	r := h.Check(req)
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
	out := g.Apply(req)
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
	out := g.Apply(req)
	if !out.Bypass {
		t.Error("clean internal should still bypass")
	}
	if out.Reason != "internal_trusted" {
		t.Errorf("expected reason=internal_trusted, got %q", out.Reason)
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
