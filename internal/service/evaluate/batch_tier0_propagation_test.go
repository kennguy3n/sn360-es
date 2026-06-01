package evaluate

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
)

// TestShouldFallbackToTier2_HonoursForceEscalate pins the parity
// invariants the batch path must hold against the per-message
// shouldRunTier2 (evaluator.go:521-535):
//
//   - SkipML / RspamdOnly Tier 0 outcomes MUST short-circuit and NOT
//     run Tier 2, even when Tier 1 returned Escalate (Tier 0 has
//     already decided the LLM should be skipped for cost/volume
//     reasons).
//   - ForceEscalate=true MUST run Tier 2 regardless of the Tier 1
//     verdict (the gate uses this to demand LLM corroboration of
//     low-severity TI matches per tier0/gate.go:306).
//   - With no Tier 0 signal, only Tier 1 verdict==Escalate triggers
//     Tier 2.
//
// Note on deliberate divergence from shouldRunTier2: the per-message
// path also routes verdict==Flag to Tier 2 (t1.Flag triggers Tier 2),
// while the batch path keeps Flag on the cheap Tier 1 verdict — the
// batch orchestrator is the volume / cost-controlled path and is
// intentionally more conservative about Tier 2 fan-out for the
// pure-Tier-1-Flag case. This test therefore asserts the SkipML /
// RspamdOnly / ForceEscalate rows of the parity table (where the
// batch path must match per-message) and the Pass / Escalate rows
// (where the batch path matches per-message because they don't
// involve Flag).
func TestShouldFallbackToTier2_HonoursForceEscalate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		verdict tier1.Verdict
		tier0   dto.Tier0Outcome
		want    bool
	}{
		{
			name:    "no_signal_tier1_pass_no_fallback",
			verdict: tier1.VerdictPass,
			tier0:   dto.Tier0Outcome{},
			want:    false,
		},
		{
			name:    "no_signal_tier1_escalate_runs_fallback",
			verdict: tier1.VerdictEscalate,
			tier0:   dto.Tier0Outcome{},
			want:    true,
		},
		{
			name:    "tier0_force_escalate_with_tier1_pass_runs_fallback",
			verdict: tier1.VerdictPass,
			tier0:   dto.Tier0Outcome{ForceEscalate: true, Reason: "ti_match"},
			want:    true,
		},
		{
			name:    "tier0_force_escalate_with_tier1_flag_runs_fallback",
			verdict: tier1.VerdictFlag,
			tier0:   dto.Tier0Outcome{ForceEscalate: true, Reason: "ti_match"},
			want:    true,
		},
		{
			name:    "tier0_force_escalate_with_tier1_escalate_runs_fallback",
			verdict: tier1.VerdictEscalate,
			tier0:   dto.Tier0Outcome{ForceEscalate: true, Reason: "ti_match"},
			want:    true,
		},
		{
			// SkipML must short-circuit even when Tier 1 says
			// Escalate: the gate's SkipML decision (e.g. high-
			// volume sender) is supposed to suppress LLM work,
			// and the per-message shouldRunTier2 returns false
			// here at evaluator.go:524. Without this row the
			// batch helper would silently diverge.
			name:    "tier0_skipml_with_tier1_escalate_no_fallback",
			verdict: tier1.VerdictEscalate,
			tier0:   dto.Tier0Outcome{SkipML: true, Reason: "high_volume_sender"},
			want:    false,
		},
		{
			// RspamdOnly carries the same suppression contract
			// as SkipML for the Tier 2 decision.
			name:    "tier0_rspamdonly_with_tier1_escalate_no_fallback",
			verdict: tier1.VerdictEscalate,
			tier0:   dto.Tier0Outcome{RspamdOnly: true, Reason: "rspamd_only"},
			want:    false,
		},
		{
			// Defensive belt-and-suspenders row: no gate path
			// today sets BOTH ForceEscalate and SkipML (TIChecker
			// doesn't touch SkipML, ATO/recurring don't touch
			// ForceEscalate), but if one ever does, SkipML must
			// win — per-message shouldRunTier2 checks SkipML
			// before ForceEscalate.
			name:    "tier0_skipml_plus_force_escalate_skipml_wins",
			verdict: tier1.VerdictEscalate,
			tier0:   dto.Tier0Outcome{SkipML: true, ForceEscalate: true},
			want:    false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := shouldFallbackToTier2(c.verdict, c.tier0)
			if got != c.want {
				t.Fatalf("shouldFallbackToTier2(verdict=%v, tier0=%+v) = %v, want %v",
					c.verdict, c.tier0, got, c.want)
			}
		})
	}
}

// TestShouldFallbackToTier2_AgreesWithShouldRunTier2 double-checks
// the parity claims above against the live per-message helper across
// every Tier 0 outcome shape that the batch helper should match
// (ForceEscalate, SkipML, RspamdOnly, no-signal). If shouldRunTier2
// ever changes one of these branches without a matching change in
// shouldFallbackToTier2, this test fails at the same moment the
// batch and per-message paths would silently start producing
// different verdicts for the same input.
//
// Verdict==Flag is excluded because the batch path is intentionally
// less aggressive than the per-message path on Tier 1 Flag (see the
// docstring on shouldFallbackToTier2 / TestShouldFallbackToTier2_
// HonoursForceEscalate).
func TestShouldFallbackToTier2_AgreesWithShouldRunTier2(t *testing.T) {
	t.Parallel()
	per := &Evaluator{}

	cases := []struct {
		name  string
		tier0 dto.Tier0Outcome
		v     tier1.Verdict
		t1    *dto.Tier1Outcome
	}{
		{
			name:  "force_escalate_pass",
			tier0: dto.Tier0Outcome{ForceEscalate: true, Reason: "ti_match"},
			v:     tier1.VerdictPass,
			t1:    &dto.Tier1Outcome{Pass: true},
		},
		{
			name:  "skipml_pass",
			tier0: dto.Tier0Outcome{SkipML: true, Reason: "high_volume_sender"},
			v:     tier1.VerdictPass,
			t1:    &dto.Tier1Outcome{Pass: true},
		},
		{
			name:  "skipml_escalate",
			tier0: dto.Tier0Outcome{SkipML: true, Reason: "high_volume_sender"},
			v:     tier1.VerdictEscalate,
			t1:    &dto.Tier1Outcome{Escalate: true},
		},
		{
			name:  "rspamd_only_escalate",
			tier0: dto.Tier0Outcome{RspamdOnly: true, Reason: "rspamd_only"},
			v:     tier1.VerdictEscalate,
			t1:    &dto.Tier1Outcome{Escalate: true},
		},
		{
			name:  "no_signal_pass",
			tier0: dto.Tier0Outcome{},
			v:     tier1.VerdictPass,
			t1:    &dto.Tier1Outcome{Pass: true},
		},
		{
			name:  "no_signal_escalate",
			tier0: dto.Tier0Outcome{},
			v:     tier1.VerdictEscalate,
			t1:    &dto.Tier1Outcome{Escalate: true},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			wantPer := per.shouldRunTier2(c.tier0, c.t1)
			gotBatch := shouldFallbackToTier2(c.v, c.tier0)
			if wantPer != gotBatch {
				t.Fatalf("divergence: per-message shouldRunTier2(tier0=%+v, t1=%+v) = %v, batch shouldFallbackToTier2(verdict=%v, tier0=%+v) = %v",
					c.tier0, c.t1, wantPer, c.v, c.tier0, gotBatch)
			}
		})
	}
}

// TestPropagateTier0OntoResult_TIMatchVisibleDownstream is the unit
// pin for the batch-path TI metadata fix. The batch orchestrator must
// surface the Tier 0 outcome (TIMatch struct + symbolic reason code)
// on the published EvaluateResult so consumers (action engine,
// audit logger, SIEM exporters) see the same `ti_match` signal the
// per-message path emits via evaluator.go:294.
func TestPropagateTier0OntoResult_TIMatchVisibleDownstream(t *testing.T) {
	t.Parallel()
	tim := &dto.TIMatch{
		Indicator:     "evil.example",
		IndicatorType: "domain",
		FeedName:      "urlhaus-recent",
		Severity:      40,
	}
	tier0 := dto.Tier0Outcome{
		Reason:        "ti_match",
		ForceEscalate: true,
		TIMatch:       tim,
	}
	res := dto.EvaluateResult{
		Score:       30,
		ReasonCodes: []string{"tier1_score"},
	}

	propagateTier0OntoResult(&res, tier0)

	if res.Tier0 == nil {
		t.Fatal("res.Tier0 is nil, want set")
	}
	if res.Tier0.TIMatch != tim {
		t.Errorf("res.Tier0.TIMatch = %+v, want %+v", res.Tier0.TIMatch, tim)
	}
	if !containsReason(res.ReasonCodes, "ti_match") {
		t.Errorf("res.ReasonCodes = %v, want to contain ti_match", res.ReasonCodes)
	}
	if !containsReason(res.ReasonCodes, "tier1_score") {
		t.Errorf("res.ReasonCodes = %v, want to preserve existing tier1_score", res.ReasonCodes)
	}
}

// TestPropagateTier0OntoResult_DoesNotOverwriteFallbackTier0 covers
// the Fallback-ran branch: when the per-message Evaluator was invoked
// as the batch's Tier-2 fallback it already set res.Tier0 to its own
// (potentially fresher) classification — e.g. an indicator GC'd
// between the batch's Tier 0 pass and Fallback's re-pass would
// correctly clear the match. propagateTier0OntoResult must respect
// the Fallback's value, not the captured snapshot.
func TestPropagateTier0OntoResult_DoesNotOverwriteFallbackTier0(t *testing.T) {
	t.Parallel()
	fresh := &dto.Tier0Outcome{Reason: "ti_match_fresh"}
	stale := dto.Tier0Outcome{Reason: "ti_match_stale", ForceEscalate: true}
	res := dto.EvaluateResult{Tier0: fresh}

	propagateTier0OntoResult(&res, stale)

	if res.Tier0 != fresh {
		t.Fatalf("res.Tier0 was overwritten by stale outcome; got %+v, want pointer-equal to %+v", res.Tier0, fresh)
	}
}

// TestPropagateTier0OntoResult_NoDuplicateReasonCode confirms a
// Fallback that already appended `ti_match` to res.ReasonCodes does
// not produce a duplicate entry when propagateTier0OntoResult runs
// afterwards. Duplicate reason codes break dashboard counters that
// sum by code.
func TestPropagateTier0OntoResult_NoDuplicateReasonCode(t *testing.T) {
	t.Parallel()
	tier0 := dto.Tier0Outcome{Reason: "ti_match", ForceEscalate: true}
	res := dto.EvaluateResult{
		ReasonCodes: []string{"ti_match", "tier1_score"},
		Tier0:       &tier0,
	}

	propagateTier0OntoResult(&res, tier0)

	count := 0
	for _, c := range res.ReasonCodes {
		if c == "ti_match" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("ti_match appears %d times in %v, want 1", count, res.ReasonCodes)
	}
}

// TestPropagateTier0OntoResult_EmptyOutcomeIsNoOp confirms the helper
// degrades cleanly when there was no Tier 0 hit. A zero Tier0Outcome
// carries no Reason and no TIMatch struct, so the only observable
// change is res.Tier0 going from nil to a pointer at the zero value.
// ReasonCodes must NOT pick up an empty string.
func TestPropagateTier0OntoResult_EmptyOutcomeIsNoOp(t *testing.T) {
	t.Parallel()
	res := dto.EvaluateResult{ReasonCodes: []string{"tier1_score"}}

	propagateTier0OntoResult(&res, dto.Tier0Outcome{})

	if res.Tier0 == nil {
		t.Fatal("res.Tier0 is nil after propagate, want zero-value pointer")
	}
	if res.Tier0.Reason != "" || res.Tier0.TIMatch != nil {
		t.Errorf("res.Tier0 picked up non-zero fields: %+v", res.Tier0)
	}
	if len(res.ReasonCodes) != 1 || res.ReasonCodes[0] != "tier1_score" {
		t.Errorf("res.ReasonCodes = %v, want [tier1_score] preserved", res.ReasonCodes)
	}
}

func containsReason(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
