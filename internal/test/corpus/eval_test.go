package corpus

import (
	"context"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
)

func newTestClients(t *testing.T) PipelineClients {
	t.Helper()
	gate := tier0.NewGate(tier0.DefaultGateConfig(), nil)
	decider, err := action.NewTierDecider(action.TierThresholds{})
	if err != nil {
		t.Fatalf("tier decider: %v", err)
	}
	return PipelineClients{
		Tier0:       gate,
		Categorizer: evaluate.NewRuleCategorizer(),
		TierDecider: testDecider{d: decider},
		Weights:     evaluate.DefaultWeights(),
	}
}

type testDecider struct{ d *action.TierDecider }

func (a testDecider) Decide(score int, primary constant.Category, _ dto.RiskSignals) constant.Tier {
	return a.d.Decide(dto.EvaluateResult{Score: score, Primary: primary})
}

func TestEvaluate_ProducesMetricsForSyntheticCorpus(t *testing.T) {
	fixtures := GenerateSyntheticN(DefaultSyntheticSeed, 40)
	report, err := Evaluate(context.Background(), newTestClients(t), fixtures, EvalOptions{
		CorpusVersion: "synthetic-test",
		Path:          "test",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if report.TotalFixtures != 40 {
		t.Errorf("expected 40 fixtures evaluated, got %d", report.TotalFixtures)
	}
	if !report.SyntheticOnly {
		t.Errorf("expected SyntheticOnly=true for all-synthetic corpus")
	}
	if !report.TierCoverage.Tier0Configured {
		t.Errorf("expected Tier0Configured=true")
	}
	if report.TierCoverage.Tier1Configured {
		t.Errorf("expected Tier1Configured=false when no Tier1 client provided")
	}
	if report.TierCoverage.FullPipeline() {
		t.Errorf("FullPipeline should be false when Tier1 missing")
	}
	// Per-label support sums to TotalFixtures.
	var totalSupport int
	for _, m := range report.PerLabel {
		totalSupport += m.Support
	}
	if totalSupport != report.TotalFixtures {
		t.Errorf("per-label support sum %d != total fixtures %d", totalSupport, report.TotalFixtures)
	}
}

func TestEvaluate_EmptyCorpusReturnsError(t *testing.T) {
	_, err := Evaluate(context.Background(), newTestClients(t), nil, EvalOptions{})
	if err == nil {
		t.Fatal("expected error on empty corpus")
	}
}

func TestEvaluate_RejectsMissingTier0(t *testing.T) {
	c := newTestClients(t)
	c.Tier0 = nil
	_, err := Evaluate(context.Background(), c, []Fixture{{ID: "x", Label: LabelPhish, RFC822: "abc"}}, EvalOptions{})
	if err == nil {
		t.Fatal("expected error when Tier0 is nil")
	}
}

func TestLabelFromResult_MapsBECCorrectly(t *testing.T) {
	res := dto.EvaluateResult{Primary: constant.CategoryBECImpersonation, Tier: constant.TierHighRisk}
	if got := LabelFromResult(res); got != LabelBEC {
		t.Errorf("expected LabelBEC, got %s", got)
	}
}

func TestLabelFromResult_MapsPhishCorrectly(t *testing.T) {
	res := dto.EvaluateResult{Primary: constant.CategoryLikelyPhishing, Tier: constant.TierHighRisk}
	if got := LabelFromResult(res); got != LabelPhish {
		t.Errorf("expected LabelPhish, got %s", got)
	}
}

func TestLabelFromResult_MapsBenignCorrectly(t *testing.T) {
	res := dto.EvaluateResult{Primary: constant.CategoryInternalTrusted, Tier: constant.TierTrusted}
	if got := LabelFromResult(res); got != LabelBenign {
		t.Errorf("expected LabelBenign, got %s", got)
	}
}

func TestCompareToBaseline_DetectsRegressions(t *testing.T) {
	baseline := Report{PerLabel: map[Label]LabelMetrics{
		LabelPhish:  {F1: 0.90},
		LabelBenign: {F1: 0.95},
	}}
	current := Report{PerLabel: map[Label]LabelMetrics{
		LabelPhish:  {F1: 0.40},
		LabelBenign: {F1: 0.93},
	}}
	regs := CompareToBaseline(current, baseline, 0.05)
	if len(regs) != 1 {
		t.Fatalf("expected 1 regression, got %d (%v)", len(regs), regs)
	}
	if regs[0].Label != LabelPhish {
		t.Errorf("expected phish regression, got %s", regs[0].Label)
	}
	if !regs[0].Catastrophic {
		t.Errorf("expected catastrophic flag for >25-pt drop")
	}
}

func TestCompareToBaseline_RespectsTolerance(t *testing.T) {
	baseline := Report{PerLabel: map[Label]LabelMetrics{LabelPhish: {F1: 0.90}}}
	current := Report{PerLabel: map[Label]LabelMetrics{LabelPhish: {F1: 0.86}}}
	regs := CompareToBaseline(current, baseline, 0.05)
	if len(regs) != 0 {
		t.Errorf("expected no regressions for 4-pt drop within 5-pt tolerance, got %v", regs)
	}
}
