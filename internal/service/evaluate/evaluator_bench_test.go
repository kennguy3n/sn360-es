package evaluate_test

import (
	"context"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/internal/testdata/corpus"
)

// BenchmarkEvaluator_SingleMessage runs the full pipeline on the
// first message from a fixed-seed corpus and reports ns/op + B/op +
// allocs/op. The corpus generator is the source of truth for shapes
// so this benchmark mirrors what production traffic looks like.
func BenchmarkEvaluator_SingleMessage(b *testing.B) {
	emails := corpus.Generate(corpus.Config{Seed: 42, Size: 32})
	ev := buildBenchEvaluator(b)
	req := emails[0].Request
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ev.Evaluate(ctx, req, req.Signals)
		if err != nil {
			b.Fatalf("evaluate: %v", err)
		}
	}
}

// BenchmarkEvaluator_BatchOf64 measures throughput by evaluating a
// rolling window of 64 corpus messages in lockstep. We don't run them
// in parallel because the evaluator itself fans out internally; what
// we're measuring here is steady-state per-message cost.
func BenchmarkEvaluator_BatchOf64(b *testing.B) {
	emails := corpus.Generate(corpus.Config{Seed: 42, Size: 64})
	ev := buildBenchEvaluator(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := emails[i%len(emails)].Request
		if _, err := ev.Evaluate(ctx, req, req.Signals); err != nil {
			b.Fatalf("evaluate: %v", err)
		}
	}
}

// BenchmarkEvaluator_Tier0Bypass measures the Tier 0 short-circuit
// path: an internal-trusted request that should never touch Tier 1 /
// Tier 2 / Rspamd. This is the cheapest path through the pipeline.
func BenchmarkEvaluator_Tier0Bypass(b *testing.B) {
	ev := buildBenchEvaluator(b)
	req := dto.EvaluateRequest{
		MessageID: "bench-bypass",
		TenantID:  "tenant-bench",
		Sender:    "ceo@acme.test",
		Recipient: "team@acme.test",
		Signals: dto.RiskSignals{
			IsInternal:           true,
			SenderDomain:         "acme.test",
			RecipientDomain:      "acme.test",
			RelationshipCategory: dto.RelationshipPartner,
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ev.Evaluate(ctx, req, req.Signals); err != nil {
			b.Fatalf("evaluate: %v", err)
		}
	}
}

// BenchmarkEvaluator_FullEscalation exercises the worst-case path
// (Tier 0 → Tier 1 → Tier 2 → Rspamd → categoriser → tier decider)
// using a request that escalates everything.
func BenchmarkEvaluator_FullEscalation(b *testing.B) {
	ev := buildBenchEvaluator(b)
	req := dto.EvaluateRequest{
		MessageID: "bench-escalate",
		TenantID:  "tenant-bench",
		Sender:    "ceo@paypa1.com",
		Recipient: "finance@acme.test",
		Subject:   "URGENT: wire transfer",
		Body:      "please wire $42k today to update vendor banking details",
		Signals: dto.RiskSignals{
			IsExternal:               true,
			HasLookalikeDomain:       true,
			HasSuspiciousURL:         true,
			HasInvoiceHint:           true,
			HasCredentialLex:         true,
			AuthFailed:               true,
			HasFailedAuth:            true,
			LooksLikeAccountTakeover: true,
			RelationshipCategory:     dto.RelationshipFirstTimeExternal,
			SenderDomain:             "paypa1.com",
			RecipientDomain:          "acme.test",
			DMARCResult:              "fail",
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ev.Evaluate(ctx, req, req.Signals); err != nil {
			b.Fatalf("evaluate: %v", err)
		}
	}
}

// buildBenchEvaluator wires a real Tier 0, real categoriser, real
// tier decider and the deterministic in-process Tier 1 / Tier 2 /
// Rspamd fakes used by the accuracy harness. The fakes are
// intentionally cheap so the benchmark surfaces orchestrator cost
// rather than fake-backend cost.
func buildBenchEvaluator(b testingTB) *evaluate.Evaluator {
	b.Helper()
	decider, err := action.NewTierDecider(action.TierThresholds{})
	if err != nil {
		b.Fatalf("tier decider: %v", err)
	}
	return evaluate.NewEvaluator(evaluate.Config{
		Tier0:       tier0.NewGate(tier0.DefaultGateConfig(), nil),
		Tier1:       benchTier1{},
		Tier2:       benchTier2{},
		Rspamd:      benchRspamd{},
		Categorizer: evaluate.NewRuleCategorizer(),
		TierDecider: benchDeciderAdapter{d: decider},
	})
}

// testingTB is the minimal subset of testing.TB used by the helper so
// the same wiring code can be shared with TestAccuracy_* (testing.T)
// and BenchmarkEvaluator_* (testing.B).
type testingTB interface {
	Helper()
	Fatalf(format string, args ...any)
}

type benchTier1 struct{}

func (benchTier1) Evaluate(_ context.Context, req dto.EvaluateRequest) (dto.Tier1Outcome, error) {
	return dto.Tier1Outcome{
		Score:      tier1ScoreFromSignals(req.Signals),
		Confidence: 0.75,
		ModelName:  "bench-tier1",
	}, nil
}

type benchTier2 struct{}

func (benchTier2) Evaluate(_ context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	return dto.Tier2Outcome{
		Score:      tier2ScoreFromSignals(req.Signals, hint.Score),
		Categories: tier2CategoriesFromSignals(req.Signals),
		Confidence: 0.7,
		ModelName:  "bench-tier2",
	}, nil
}

type benchRspamd struct{}

func (benchRspamd) Score(_ context.Context, req dto.EvaluateRequest) (dto.RspamdOutcome, error) {
	score := rspamdScoreFromSignals(req.Signals)
	return dto.RspamdOutcome{Score: score, Threshold: 15.0}, nil
}

type benchDeciderAdapter struct{ d *action.TierDecider }

func (a benchDeciderAdapter) Decide(score int, primary constant.Category, _ dto.RiskSignals) constant.Tier {
	return a.d.Decide(dto.EvaluateResult{Score: score, Primary: primary})
}

// tier1ScoreFromSignals is the bench-package mirror of the accuracy
// harness's tier1Score, duplicated here so the benchmark suite has no
// build-tag coupling to the accuracy_test.go file. It is intentionally
// small and stable so the benchmark output is reproducible.
func tier1ScoreFromSignals(s dto.RiskSignals) int {
	switch {
	case s.IsInternal:
		return 2
	case s.IsFromVendor:
		return 6
	case s.IsRecurringService:
		return 10
	}
	score := 5
	if s.IsExternal {
		score += 5
	}
	if s.HasSuspiciousURL {
		score += 20
	}
	if s.HasSuspiciousAttachment {
		score += 18
	}
	if s.HasLookalikeDomain {
		score += 22
	}
	if s.HasInvoiceHint {
		score += 12
	}
	if s.HasCredentialLex {
		score += 22
	}
	if s.HasQRCode {
		score += 18
	}
	if s.AuthFailed || s.HasFailedAuth {
		score += 12
	}
	if s.LooksLikeAccountTakeover {
		score += 25
	}
	if s.LooksLikeVendorCompromise {
		score += 25
	}
	if score > 99 {
		score = 99
	}
	return score
}

func tier2ScoreFromSignals(s dto.RiskSignals, t1 int) int {
	score := t1
	if s.LooksLikeAccountTakeover || s.LooksLikeVendorCompromise {
		score += 10
	}
	if s.HasLookalikeDomain && s.HasInvoiceHint {
		score += 10
	}
	if s.HasCredentialLex && s.AuthFailed {
		score += 8
	}
	if s.HasQRCode && s.HasSuspiciousURL {
		score += 6
	}
	if score > 100 {
		score = 100
	}
	return score
}

func tier2CategoriesFromSignals(s dto.RiskSignals) []constant.Category {
	cats := make([]constant.Category, 0, 3)
	if s.HasLookalikeDomain {
		cats = append(cats, constant.CategoryLookalikeDomain)
	}
	if s.HasCredentialLex {
		cats = append(cats, constant.CategoryCredentialHarvesting)
	}
	if s.HasQRCode {
		cats = append(cats, constant.CategoryQRPhishing)
	}
	if len(cats) == 0 && s.HasSuspiciousURL {
		cats = append(cats, constant.CategoryLikelyPhishing)
	}
	if len(cats) > 3 {
		cats = cats[:3]
	}
	return cats
}

func rspamdScoreFromSignals(s dto.RiskSignals) float64 {
	if s.IsInternal || s.IsFromVendor {
		return -1.5
	}
	score := 0.0
	if s.AuthFailed || s.HasFailedAuth {
		score += 4.5
	}
	if s.HasLookalikeDomain {
		score += 5.5
	}
	if s.HasSuspiciousURL {
		score += 3.5
	}
	if s.HasSuspiciousAttachment {
		score += 4.0
	}
	if s.IsDisposableDomain {
		score += 5.0
	}
	if s.HasQRCode {
		score += 4.5
	}
	if s.HasCredentialLex {
		score += 3.0
	}
	return score
}
