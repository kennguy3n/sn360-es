package evaluate

import (
	"context"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// TestNoopEnricher_ReturnsBaseUnchanged pins the contract callers
// rely on: a partially-wired deployment that substitutes
// NoopEnricher (because the communication-histories repo or PII
// hasher is not configured) must see Tier 0 / Tier 1 evaluate
// against exactly the signals the producer published.
func TestNoopEnricher_ReturnsBaseUnchanged(t *testing.T) {
	hour := 7
	base := dto.RiskSignals{
		SenderDomain:           "x.com",
		IsExternal:             true,
		TypicalSendHour:        &hour,
		CommunicationFrequency: 11,
		IsFirstContact:         true,
		CurrentHourUTC:         4,
	}
	out := NoopEnricher{}.Enrich(context.Background(), dto.EvaluateRequest{}, base)
	if out.SenderDomain != "x.com" || !out.IsExternal {
		t.Fatalf("scalar fields lost: %+v", out)
	}
	if out.TypicalSendHour == nil || *out.TypicalSendHour != 7 {
		t.Fatalf("TypicalSendHour pointer lost: %+v", out.TypicalSendHour)
	}
	if out.CommunicationFrequency != 11 {
		t.Fatalf("CommunicationFrequency lost: %d", out.CommunicationFrequency)
	}
	if !out.IsFirstContact {
		t.Fatalf("IsFirstContact lost")
	}
	if out.CurrentHourUTC != 4 {
		t.Fatalf("CurrentHourUTC lost: %d", out.CurrentHourUTC)
	}
}

// TestNoopEnricher_SatisfiesInterface is a compile-time assertion
// disguised as a test: if NoopEnricher ever drifts from SignalEnricher,
// this stops compiling instead of silently substituting nil at
// runtime.
func TestNoopEnricher_SatisfiesInterface(t *testing.T) {
	var _ SignalEnricher = NoopEnricher{}
}
