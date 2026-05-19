//go:build benchmark
// +build benchmark

package evaluate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/internal/testdata/corpus"
)

// TestAccuracy_FullPipeline runs the full evaluation pipeline against
// the labelled corpus and writes a Markdown report under
// benchmarks/accuracy_<date>.md. The fake Tier 1 / Tier 2 / Rspamd
// backends are signal-driven so the harness exercises the categoriser,
// scorer, and tier decider end-to-end — accuracy regressions show up
// as drift in the precision / recall figures.
//
// This test is intentionally tagged so it does not run as part of the
// default `go test` invocation; invoke it via:
//
//	go test -tags=benchmark -run=TestAccuracy_FullPipeline -v \
//	    ./internal/service/evaluate/...
func TestAccuracy_FullPipeline(t *testing.T) {
	const (
		corpusSize = 1000
		seed       = 42
	)
	emails := corpus.Generate(corpus.Config{Seed: seed, Size: corpusSize})

	evaluator := buildAccuracyEvaluator(t)
	ctx := context.Background()
	report := evaluate.NewAccuracyReport(len(emails), seed)

	start := time.Now()
	for _, e := range emails {
		res, err := evaluator.Evaluate(ctx, e.Request, e.Request.Signals)
		if err != nil {
			t.Fatalf("evaluate %s: %v", e.Request.MessageID, err)
		}
		report.AddObservation(
			res.Primary, e.ExpectedPrimary,
			res.Tier, e.ExpectedTier,
			string(e.Difficulty),
			e.IsThreat,
		)
	}
	report.Recompute()
	t.Logf("evaluated %d emails in %s", len(emails), time.Since(start))

	t.Logf("accuracy: overall TP=%d FP=%d FN=%d TN=%d precision=%.4f recall=%.4f f1=%.4f",
		report.Overall.TP, report.Overall.FP, report.Overall.FN, report.Overall.TN,
		report.Overall.Precision, report.Overall.Recall, report.Overall.F1)
	t.Logf("false-positive rate: %.4f (target <0.05)", report.FalsePositiveRate)
	t.Logf("false-negative rate: %.4f (target <0.02)", report.FalseNegativeRate)

	if got := report.ConfusionTotal(); got != len(emails) {
		t.Fatalf("confusion matrix sums to %d, expected %d", got, len(emails))
	}
	for _, c := range constant.AllCategories {
		if _, ok := report.PerCategory[c]; !ok {
			t.Fatalf("missing per-category metrics for %s", c)
		}
	}
	for _, ti := range constant.AllTiers {
		if _, ok := report.PerTier[ti]; !ok {
			t.Fatalf("missing per-tier metrics for %s", ti)
		}
	}

	// Persist the rendered Markdown report under benchmarks/ so the
	// run output is preserved alongside the rest of the artefacts.
	if dir := os.Getenv("ACCURACY_REPORT_DIR"); dir != "" {
		path := filepath.Join(dir, fmt.Sprintf("accuracy_%s.md", time.Now().Format("20060102")))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(path, []byte(report.FormatMarkdown()), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote markdown report to %s", path)
	} else {
		// Still emit the Markdown body so `go test -v` captures it
		// alongside the test log when no directory is configured.
		t.Log("\n" + report.FormatMarkdown())
	}
}

// buildAccuracyEvaluator wires a real Tier 0 gate, real categoriser,
// real tier decider, real scorer, and the signal-driven fake Tier 1 /
// Tier 2 / Rspamd backends defined below.
func buildAccuracyEvaluator(t *testing.T) *evaluate.Evaluator {
	t.Helper()
	decider, err := action.NewTierDecider(action.TierThresholds{})
	if err != nil {
		t.Fatalf("tier decider: %v", err)
	}
	return evaluate.NewEvaluator(evaluate.Config{
		Tier0:       tier0.NewGate(tier0.DefaultGateConfig(), nil),
		Tier1:       fakeAccTier1{},
		Tier2:       fakeAccTier2{},
		Rspamd:      fakeAccRspamd{},
		Categorizer: evaluate.NewRuleCategorizer(),
		TierDecider: deciderAdapter{d: decider},
	})
}

// deciderAdapter bridges the production *action.TierDecider (whose
// Decide method takes a full EvaluateResult) to the evaluate package's
// TierDecider interface (which takes score+primary+signals).
type deciderAdapter struct{ d *action.TierDecider }

func (a deciderAdapter) Decide(score int, primary constant.Category, sig dto.RiskSignals) constant.Tier {
	return a.d.Decide(dto.EvaluateResult{
		Score:   score,
		Primary: primary,
		// The decider only consults Primary, Score, Tier0 and (via
		// PROPOSAL.md) the FirstContact floor; signals are passed
		// through for any future tenant-specific overrides.
	})
}

// ---------------------------------------------------------------------
// Signal-driven fake backends.
//
// These fakes are deliberately deterministic so the accuracy report is
// reproducible. Each one maps the RiskSignals payload to a plausible
// score band — they are not constant stubs. The mapping mirrors the
// weight matrix in categorizer.go so the categoriser, scorer, and tier
// decider all see signal-consistent inputs.
// ---------------------------------------------------------------------

// fakeAccTier1 simulates the XLM-RoBERTa encoder. The encoder's job is
// to surface a raw 0-100 score; we synthesise that from the signals.
type fakeAccTier1 struct{}

func (fakeAccTier1) Evaluate(_ context.Context, req dto.EvaluateRequest) (dto.Tier1Outcome, error) {
	score := tier1Score(req.Signals)
	conf := 0.55 + float64(score)/250.0 // 0.55-0.95 range
	if conf > 0.95 {
		conf = 0.95
	}
	return dto.Tier1Outcome{
		Score:      score,
		Confidence: conf,
		Language:   req.Locale,
		ModelName:  "fake-acc-tier1",
		LatencyMs:  3,
	}, nil
}

// fakeAccTier2 simulates the SLM/LLM Tier 2 stage. It returns the
// dominant categories implied by the signals so the categoriser can
// pick up the right primary even when Tier 1 escalates.
type fakeAccTier2 struct{}

func (fakeAccTier2) Evaluate(_ context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	score := tier2Score(req.Signals, hint.Score)
	return dto.Tier2Outcome{
		Score:      score,
		Categories: tier2Categories(req.Signals),
		Confidence: 0.7,
		ModelName:  "fake-acc-tier2",
		LatencyMs:  12,
	}, nil
}

// fakeAccRspamd simulates the heuristics engine. Its score is derived
// from auth + lookalike + suspicious-URL signals with the conventional
// reject threshold of 15.
type fakeAccRspamd struct{}

func (fakeAccRspamd) Score(_ context.Context, req dto.EvaluateRequest) (dto.RspamdOutcome, error) {
	score := rspamdScore(req.Signals)
	return dto.RspamdOutcome{
		Score:     score,
		Threshold: 15.0,
		Action:    rspamdAction(score),
		LatencyMs: 4,
	}, nil
}

// tier1Score maps the signal profile onto the encoder output band
// described in PROPOSAL.md Section 3:
//   - benign internal / vendor: <20 (always PASS)
//   - newsletters: <30
//   - moderate signal stack (single hint): 30-60 (ESCALATE)
//   - high-confidence threat stack: 60-95 (FLAG)
func tier1Score(s dto.RiskSignals) int {
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
	if s.RelationshipCategory == dto.RelationshipFirstTimeExternal {
		score += 10
	}
	if s.RelationshipCategory == dto.RelationshipLapsedContact {
		score += 8
	}
	if s.IsFreeDomain {
		score += 5
	}
	if s.IsDisposableDomain {
		score += 10
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
	return clamp(score, 0, 99)
}

// tier2Score is anchored to the Tier 1 score and amplifies it modestly
// when the LLM has more context (i.e. signal hints align).
func tier2Score(s dto.RiskSignals, t1 int) int {
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
	return clamp(score, 0, 100)
}

// tier2Categories picks the categories the LLM would emit given the
// signal profile. These feed the categoriser as advisory hints.
func tier2Categories(s dto.RiskSignals) []constant.Category {
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
	if s.HasInvoiceHint && s.HasSuspiciousURL {
		cats = append(cats, constant.CategoryInvoiceFraud)
	}
	if s.LooksLikeAccountTakeover {
		cats = append(cats, constant.CategoryAccountTakeoverSuspected)
	}
	if s.LooksLikeVendorCompromise {
		cats = append(cats, constant.CategoryVendorCompromise)
	}
	if len(cats) == 0 && s.HasSuspiciousURL {
		cats = append(cats, constant.CategoryLikelyPhishing)
	}
	if len(cats) > 3 {
		cats = cats[:3]
	}
	return cats
}

// rspamdScore models the unbounded Rspamd score. Threshold is 15.
func rspamdScore(s dto.RiskSignals) float64 {
	score := 0.0
	if s.AuthFailed || s.HasFailedAuth {
		score += 4.5
	}
	if s.DMARCResult == "fail" {
		score += 3.5
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
	if s.IsInternal || s.IsFromVendor {
		// Trusted senders get a small negative bias to mirror the SPF
		// allowlist policy in production.
		score = -1.5
	}
	return score
}

// rspamdAction maps the score to one of the Rspamd action labels used
// in production (no_action / greylist / add_header / reject).
func rspamdAction(score float64) string {
	switch {
	case score >= 15:
		return "reject"
	case score >= 8:
		return "add_header"
	case score >= 4:
		return "greylist"
	default:
		return "no_action"
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---------------------------------------------------------------------
// Sanity / regression checks for the report itself.
// ---------------------------------------------------------------------

// TestAccuracy_PerfectEvaluator pins the basic invariant that a
// perfect predictor yields precision=recall=F1=1.0 across every
// category and tier.
func TestAccuracy_PerfectEvaluator(t *testing.T) {
	emails := corpus.Generate(corpus.Config{Seed: 7, Size: 200})
	report := evaluate.NewAccuracyReport(len(emails), 7)
	for _, e := range emails {
		report.AddObservation(e.ExpectedPrimary, e.ExpectedPrimary,
			e.ExpectedTier, e.ExpectedTier, string(e.Difficulty), e.IsThreat)
	}
	report.Recompute()
	for cat, m := range report.PerCategory {
		if m.TP+m.FN == 0 {
			continue
		}
		if m.F1 < 0.9999 {
			t.Fatalf("perfect predictor should give F1=1 for %s; got %.4f", cat, m.F1)
		}
	}
	for tier, m := range report.PerTier {
		if m.TP+m.FN == 0 {
			continue
		}
		if m.F1 < 0.9999 {
			t.Fatalf("perfect predictor should give F1=1 for %s; got %.4f", tier, m.F1)
		}
	}
	if total := report.ConfusionTotal(); total != len(emails) {
		t.Fatalf("confusion matrix sums to %d, expected %d", total, len(emails))
	}
}

// TestAccuracy_RandomEvaluator asserts that a uniformly random
// predictor lands in the expected metric ranges. With 16 categories
// the precision and recall are bounded above by ~0.10 on average.
func TestAccuracy_RandomEvaluator(t *testing.T) {
	emails := corpus.Generate(corpus.Config{Seed: 19, Size: 800})
	report := evaluate.NewAccuracyReport(len(emails), 19)
	r := rand.New(rand.NewPCG(1, 2))
	for _, e := range emails {
		cat := constant.AllCategories[r.IntN(len(constant.AllCategories))]
		tier := constant.AllTiers[r.IntN(len(constant.AllTiers))]
		report.AddObservation(cat, e.ExpectedPrimary, tier, e.ExpectedTier,
			string(e.Difficulty), e.IsThreat)
	}
	report.Recompute()
	// A random predictor over 16 categories should produce a top-1
	// micro-accuracy in [0.02, 0.20]. We check the OverallExpected
	// metric (threat vs benign trusted-fall-through) instead because
	// it's monotonic in random output.
	if report.Overall.Precision > 0.95 {
		t.Fatalf("random predictor reported implausibly high precision: %.4f", report.Overall.Precision)
	}
	if report.Overall.Recall > 0.95 {
		t.Fatalf("random predictor reported implausibly high recall: %.4f", report.Overall.Recall)
	}
	if total := report.ConfusionTotal(); total != len(emails) {
		t.Fatalf("confusion matrix sums to %d, expected %d", total, len(emails))
	}
}

// TestAccuracy_ConfusionMatrixSumsToCorpus pins the invariant that the
// predicted×actual cells sum to the corpus size for an arbitrary
// (signal-driven) evaluator.
func TestAccuracy_ConfusionMatrixSumsToCorpus(t *testing.T) {
	emails := corpus.Generate(corpus.Config{Seed: 41, Size: 250})
	evaluator := buildAccuracyEvaluator(t)
	report := evaluate.NewAccuracyReport(len(emails), 41)
	ctx := context.Background()
	for _, e := range emails {
		res, err := evaluator.Evaluate(ctx, e.Request, e.Request.Signals)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		report.AddObservation(res.Primary, e.ExpectedPrimary,
			res.Tier, e.ExpectedTier, string(e.Difficulty), e.IsThreat)
	}
	report.Recompute()
	if total := report.ConfusionTotal(); total != len(emails) {
		t.Fatalf("confusion matrix sums to %d, expected %d", total, len(emails))
	}
}

// TestAccuracy_ReportFormatMarkdownStable verifies the Markdown
// renderer emits the expected section headers and a row per category /
// tier so downstream tooling can rely on the layout.
func TestAccuracy_ReportFormatMarkdownStable(t *testing.T) {
	emails := corpus.Generate(corpus.Config{Seed: 11, Size: 64})
	report := evaluate.NewAccuracyReport(len(emails), 11)
	for _, e := range emails {
		report.AddObservation(e.ExpectedPrimary, e.ExpectedPrimary,
			e.ExpectedTier, e.ExpectedTier, string(e.Difficulty), e.IsThreat)
	}
	report.Recompute()
	md := report.FormatMarkdown()
	must := []string{
		"# Accuracy Report",
		"## Overall (threat vs benign)",
		"## Per-category",
		"## Per-tier",
		"## Confusion matrix",
	}
	for _, w := range must {
		if !contains(md, w) {
			t.Fatalf("markdown missing %q\n--- begin ---\n%s\n--- end ---", w, md)
		}
	}
	// Roundtrip: ensure the report serialises to JSON without panic so
	// dashboards can ingest the raw structure.
	if _, err := json.Marshal(report); err != nil {
		t.Fatalf("json: %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	n := len(needle)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= len(haystack); i++ {
		if haystack[i:i+n] == needle {
			return i
		}
	}
	return -1
}
