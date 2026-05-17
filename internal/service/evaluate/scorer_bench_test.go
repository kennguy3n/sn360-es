package evaluate_test

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
)

// BenchmarkScore_AllWeights measures the cost of the canonical scorer
// path: every weight active, every component populated.
func BenchmarkScore_AllWeights(b *testing.B) {
	w := evaluate.Weights{AI: 0.6, Rspamd: 0.2, Attachments: 0.1, Links: 0.1}
	comp := evaluate.Components{AI: 82, Rspamd: 56, Attachments: 30, Links: 75}
	b.ReportAllocs()
	b.ResetTimer()
	var sink int
	for i := 0; i < b.N; i++ {
		sink = evaluate.Score(comp, w)
	}
	_ = sink
}

// BenchmarkScore_ZeroWeights pins the zero-weight degenerate path so
// regressions don't accidentally pay full weight-sum cost when all
// weights are zero (the scorer falls back to AI).
func BenchmarkScore_ZeroWeights(b *testing.B) {
	w := evaluate.Weights{}
	comp := evaluate.Components{AI: 82, Rspamd: 56, Attachments: 30, Links: 75}
	b.ReportAllocs()
	b.ResetTimer()
	var sink int
	for i := 0; i < b.N; i++ {
		sink = evaluate.Score(comp, w)
	}
	_ = sink
}

// BenchmarkScore_FromResult measures the combined cost of deriving
// Components from an EvaluateResult and then scoring them — that is
// the path the orchestrator actually walks.
func BenchmarkScore_FromResult(b *testing.B) {
	w := evaluate.DefaultWeights()
	res := dto.EvaluateResult{
		Score:  60,
		Tier1:  &dto.Tier1Outcome{Score: 70},
		Tier2:  &dto.Tier2Outcome{Score: 80},
		Rspamd: &dto.RspamdOutcome{Score: 12.5, Threshold: 15.0},
	}
	b.ReportAllocs()
	b.ResetTimer()
	var sink int
	for i := 0; i < b.N; i++ {
		comp := evaluate.FromResult(&res)
		sink = evaluate.Score(comp, w)
	}
	_ = sink
}
