package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// stubLookup is a deterministic EvaluationLookup.
type stubLookup struct {
	result dto.EvaluateResult
	err    error
}

func (s stubLookup) FindResult(_ context.Context, _, _ string) (dto.EvaluateResult, error) {
	return s.result, s.err
}

// supportEventSink captures publishes; it satisfies EventPublisher.
type supportEventSink struct {
	subjects []string
	bodies   []string
	err      error
}

func (s *supportEventSink) Publish(_ context.Context, subject string, data []byte) error {
	if s.err != nil {
		return s.err
	}
	s.subjects = append(s.subjects, subject)
	s.bodies = append(s.bodies, string(data))
	return nil
}

func TestNewSupportAgent_RequiresLookup(t *testing.T) {
	if _, err := NewSupportAgent(SupportConfig{}); err == nil {
		t.Fatal("expected error when Lookup is nil")
	}
}

func TestNewSupportAgent_AppliesDefaults(t *testing.T) {
	a, err := NewSupportAgent(SupportConfig{
		Lookup: stubLookup{},
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewSupportAgent: %v", err)
	}
	if a.cfg.SecOpsSubject != "es.action.escalate.secops" {
		t.Fatalf("SecOpsSubject default: %q", a.cfg.SecOpsSubject)
	}
	if a.cfg.ReleaseSubject != "es.action.release.request" {
		t.Fatalf("ReleaseSubject default: %q", a.cfg.ReleaseSubject)
	}
	if a.cfg.EscalationConfidence != 0.45 {
		t.Fatalf("EscalationConfidence default: %v", a.cfg.EscalationConfidence)
	}
}

func TestSupportAgent_Answer_ValidatesInput(t *testing.T) {
	a, _ := NewSupportAgent(SupportConfig{Lookup: stubLookup{}, Logger: discardLogger()})
	if _, err := a.Answer(context.Background(), SupportQuery{}); err == nil {
		t.Fatal("expected error for missing tenant/message")
	}
}

func TestSupportAgent_Answer_PropagatesLookupError(t *testing.T) {
	a, _ := NewSupportAgent(SupportConfig{
		Lookup: stubLookup{err: errors.New("boom")},
		Logger: discardLogger(),
	})
	if _, err := a.Answer(context.Background(), SupportQuery{
		TenantID:  "acme",
		MessageID: "pmid-1",
		Action:    "explain",
	}); err == nil {
		t.Fatal("expected lookup error to propagate")
	}
}

func TestSupportAgent_Answer_Explain_DeterministicExplanation(t *testing.T) {
	audit := &recordingAudit{}
	a, _ := NewSupportAgent(SupportConfig{
		Lookup: stubLookup{result: dto.EvaluateResult{
			Tier:        constant.TierWarning,
			Primary:     constant.CategoryLikelyPhishing,
			Score:       80,
			ReasonCodes: []string{"lookalike_domain", "urgency_lexicon"},
			Tier1:       &dto.Tier1Outcome{Confidence: 0.9},
		}},
		Audit:  audit,
		Logger: discardLogger(),
	})
	rep, err := a.Answer(context.Background(), SupportQuery{
		TenantID:  "acme",
		MessageID: "pmid-1",
		Action:    "explain",
	})
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !strings.Contains(rep.Explanation, "suspicious") {
		t.Fatalf("Explanation missing tier copy: %q", rep.Explanation)
	}
	if !strings.Contains(rep.Explanation, "likely phishing") {
		t.Fatalf("Explanation missing category: %q", rep.Explanation)
	}
	if !strings.Contains(rep.Explanation, "lookalike_domain") {
		t.Fatalf("Explanation missing reason codes: %q", rep.Explanation)
	}
	if rep.Confidence != 0.9 {
		t.Fatalf("Confidence: %v", rep.Confidence)
	}
	if rep.Escalated {
		t.Fatal("expected non-escalation for high confidence")
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "support.explain" {
		t.Fatalf("audit: %+v", audit.entries)
	}
}

func TestSupportAgent_Answer_LowConfidence_AutoEscalates(t *testing.T) {
	pub := &supportEventSink{}
	a, _ := NewSupportAgent(SupportConfig{
		Lookup: stubLookup{result: dto.EvaluateResult{
			Tier:    constant.TierCaution,
			Primary: constant.CategoryFirstContactExternal,
			Tier1:   &dto.Tier1Outcome{Confidence: 0.2},
		}},
		Events: pub,
		Logger: discardLogger(),
	})
	rep, err := a.Answer(context.Background(), SupportQuery{
		TenantID:  "acme",
		MessageID: "pmid-1",
		Action:    "explain",
	})
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !rep.Escalated {
		t.Fatal("expected auto-escalation for low confidence")
	}
	if len(pub.subjects) != 1 || pub.subjects[0] != "es.action.escalate.secops" {
		t.Fatalf("subjects: %+v", pub.subjects)
	}
	if !strings.Contains(pub.bodies[0], "low_confidence") {
		t.Fatalf("body should include low_confidence reason: %q", pub.bodies[0])
	}
}

func TestSupportAgent_Answer_Release_PublishesAndOptimistic(t *testing.T) {
	pub := &supportEventSink{}
	a, _ := NewSupportAgent(SupportConfig{
		Lookup: stubLookup{result: dto.EvaluateResult{
			Tier:  constant.TierBlocked,
			Tier2: &dto.Tier2Outcome{Confidence: 0.95},
		}},
		Events: pub,
		Logger: discardLogger(),
	})
	rep, err := a.Answer(context.Background(), SupportQuery{
		TenantID:  "acme",
		MessageID: "pmid-1",
		UserEmail: "user@acme.com",
		Action:    "release",
	})
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if rep.ReleasedAt == nil {
		t.Fatal("expected ReleasedAt set")
	}
	if len(pub.subjects) != 1 || pub.subjects[0] != "es.action.release.request" {
		t.Fatalf("subjects: %+v", pub.subjects)
	}
	if !strings.Contains(pub.bodies[0], `"tenant_id":"acme"`) {
		t.Fatalf("body missing tenant_id: %q", pub.bodies[0])
	}
	if !strings.Contains(pub.bodies[0], `"message_id":"pmid-1"`) {
		t.Fatalf("body missing message_id: %q", pub.bodies[0])
	}
}

func TestSupportAgent_Answer_Release_RequiresEvents(t *testing.T) {
	a, _ := NewSupportAgent(SupportConfig{
		Lookup: stubLookup{result: dto.EvaluateResult{
			Tier:  constant.TierBlocked,
			Tier2: &dto.Tier2Outcome{Confidence: 0.95},
		}},
		Logger: discardLogger(),
	})
	if _, err := a.Answer(context.Background(), SupportQuery{
		TenantID: "acme", MessageID: "pmid-1", Action: "release",
	}); err == nil {
		t.Fatal("expected error when Events is nil")
	}
}

func TestSupportAgent_Answer_Escalate_PublishesWithReason(t *testing.T) {
	pub := &supportEventSink{}
	a, _ := NewSupportAgent(SupportConfig{
		Lookup: stubLookup{result: dto.EvaluateResult{
			Tier:  constant.TierHighRisk,
			Tier2: &dto.Tier2Outcome{Confidence: 0.99},
		}},
		Events: pub,
		Logger: discardLogger(),
	})
	rep, err := a.Answer(context.Background(), SupportQuery{
		TenantID: "acme", MessageID: "pmid-1", Action: "escalate",
	})
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !rep.Escalated {
		t.Fatal("expected Escalated true")
	}
	if len(pub.subjects) != 1 || pub.subjects[0] != "es.action.escalate.secops" {
		t.Fatalf("subjects: %+v", pub.subjects)
	}
	if !strings.Contains(pub.bodies[0], "user_requested") {
		t.Fatalf("body missing reason: %q", pub.bodies[0])
	}
}

func TestSupportAgent_Answer_UnknownActionRejected(t *testing.T) {
	a, _ := NewSupportAgent(SupportConfig{
		Lookup: stubLookup{result: dto.EvaluateResult{Tier: constant.TierWarning}},
		Logger: discardLogger(),
	})
	if _, err := a.Answer(context.Background(), SupportQuery{
		TenantID: "acme", MessageID: "pmid-1", Action: "nuke",
	}); err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestSupportAgent_Answer_DefaultsActionToExplain(t *testing.T) {
	a, _ := NewSupportAgent(SupportConfig{
		Lookup: stubLookup{result: dto.EvaluateResult{
			Tier:  constant.TierTrusted,
			Tier2: &dto.Tier2Outcome{Confidence: 0.99},
		}},
		Logger: discardLogger(),
	})
	rep, err := a.Answer(context.Background(), SupportQuery{
		TenantID: "acme", MessageID: "pmid-1",
	})
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if !strings.Contains(strings.ToLower(rep.Explanation), "trusted") {
		t.Fatalf("Explanation should be the trusted explanation: %q", rep.Explanation)
	}
}

func TestExplainVerdict_AllTiers(t *testing.T) {
	cases := map[constant.Tier]string{
		constant.TierBlocked:        "blocked",
		constant.TierHighRisk:       "high-risk",
		constant.TierWarning:        "suspicious",
		constant.TierCaution:        "unusual",
		constant.TierInformational:  "informational",
		constant.TierTrusted:        "trusted",
	}
	for tier, fragment := range cases {
		t.Run(string(tier), func(t *testing.T) {
			got := ExplainVerdict(dto.EvaluateResult{Tier: tier}, "en")
			if !strings.Contains(strings.ToLower(got), fragment) {
				t.Fatalf("tier=%q expected fragment %q in %q", tier, fragment, got)
			}
		})
	}
}

func TestExplainVerdict_DegradedNote(t *testing.T) {
	out := ExplainVerdict(dto.EvaluateResult{
		Tier:     constant.TierWarning,
		Degraded: true,
	}, "en")
	if !strings.Contains(out, "unavailable") {
		t.Fatalf("expected degraded notice: %q", out)
	}
}

func TestDefaultSuggestion_AllTiers(t *testing.T) {
	cases := []constant.Tier{
		constant.TierBlocked,
		constant.TierHighRisk,
		constant.TierWarning,
		constant.TierCaution,
		constant.TierInformational,
		constant.TierTrusted,
	}
	for _, tier := range cases {
		t.Run(string(tier), func(t *testing.T) {
			if got := DefaultSuggestion(tier); got == "" {
				t.Fatalf("empty suggestion for %q", tier)
			}
		})
	}
}

func TestVerdictConfidence_PrefersTier2OverTier1(t *testing.T) {
	v := dto.EvaluateResult{
		Tier1: &dto.Tier1Outcome{Confidence: 0.2},
		Tier2: &dto.Tier2Outcome{Confidence: 0.9},
	}
	if got := verdictConfidence(v); got != 0.9 {
		t.Fatalf("got %v want 0.9", got)
	}
}

func TestVerdictConfidence_FallsBackToTier1(t *testing.T) {
	v := dto.EvaluateResult{Tier1: &dto.Tier1Outcome{Confidence: 0.7}}
	if got := verdictConfidence(v); got != 0.7 {
		t.Fatalf("got %v want 0.7", got)
	}
}

func TestVerdictConfidence_Tier0BypassMaxes(t *testing.T) {
	v := dto.EvaluateResult{Tier0: &dto.Tier0Outcome{Bypass: true}}
	if got := verdictConfidence(v); got != 1.0 {
		t.Fatalf("got %v want 1.0", got)
	}
}

func TestVerdictConfidence_DefaultMidpoint(t *testing.T) {
	if got := verdictConfidence(dto.EvaluateResult{}); got != 0.5 {
		t.Fatalf("got %v want 0.5", got)
	}
}
