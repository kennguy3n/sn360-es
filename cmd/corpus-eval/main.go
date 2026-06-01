// Package main is the WS-4b corpus-evaluation harness binary. It
// loads a JSONL corpus, runs the production Tier 0 / Tier 1 / Tier 2
// evaluator end-to-end against every fixture, writes a structured
// JSON report, and optionally diffs the new report against a
// committed baseline to detect regressions.
//
// Usage:
//
//	corpus-eval -corpus=testdata/corpus-eval/synthetic.jsonl \
//	            -out=testdata/corpus-eval/reports/$(date -u +%Y%m%dT%H%M%SZ).json \
//	            -baseline=testdata/corpus-eval/baseline.json \
//	            -tolerance=0.05
//
// Tier 1 (encoder) and Tier 2 (SLM/LLM) are wired only when the
// corresponding URL flags / env vars are set. When they are not set
// — the typical CI scenario — the evaluator runs Tier 0 only and the
// report explicitly flags the partial-pipeline status; the WS-4b
// spec mandates this "no false confidence" behaviour over silently
// substituting mocks.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/internal/service/tier1"
	"github.com/kennguy3n/sn360-es/internal/test/corpus"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "gen-synthetic" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		if err := runGenSynthetic(); err != nil {
			fmt.Fprintln(os.Stderr, "corpus-eval gen-synthetic:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "corpus-eval:", err)
		os.Exit(1)
	}
}

// runGenSynthetic writes the deterministic synthetic corpus to
// disk. It is a sibling subcommand of the main evaluator so the
// generator and the harness share the same Fixture / JSONL writer
// codepaths (no risk of skewed shapes between the two).
func runGenSynthetic() error {
	var (
		out  = flag.String("out", "testdata/corpus-eval/synthetic.jsonl", "destination JSONL path")
		seed = flag.Uint64("seed", corpus.DefaultSyntheticSeed, "PRNG seed for fixture generation")
		size = flag.Int("size", corpus.DefaultSyntheticSize, "total number of fixtures (split evenly across labels)")
	)
	flag.Parse()
	fixtures := corpus.GenerateSyntheticN(*seed, *size)
	if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		return err
	}
	f, err := os.Create(*out) // #nosec G304 -- caller-controlled output path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := corpus.WriteJSONL(f, fixtures); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d synthetic fixtures to %s (seed=%d)\n", len(fixtures), *out, *seed)
	return nil
}

func run() error {
	var (
		corpusPath        = flag.String("corpus", "testdata/corpus-eval/synthetic.jsonl", "path to JSONL corpus file")
		outPath           = flag.String("out", "", "path to write the JSON report (default: testdata/corpus-eval/reports/<ts>.json)")
		baselinePath      = flag.String("baseline", "testdata/corpus-eval/baseline.json", "path to baseline JSON report for regression diff; empty disables diff")
		tolerance         = flag.Float64("tolerance", corpus.DefaultRegressionTolerance, "per-label F1 drop treated as a regression")
		encoderURL        = flag.String("encoder-url", os.Getenv("SN360_ENCODER_URL"), "encoder service URL (empty disables Tier 1)")
		failOnRegression  = flag.Bool("fail-on-regression", true, "exit non-zero when a regression exceeds tolerance")
		printReport       = flag.Bool("print", true, "print summary of the report to stdout")
		perFixtureTimeout = flag.Duration("fixture-timeout", 30*time.Second, "per-fixture evaluator timeout")
		tenantID          = flag.String("tenant-id", "ws4b-corpus-harness", "tenant ID applied to every evaluation request")
	)
	flag.Parse()

	if *outPath == "" {
		ts := time.Now().UTC().Format("20060102T150405Z")
		*outPath = filepath.Join("testdata", "corpus-eval", "reports", ts+".json")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("loading corpus", slog.String("path", *corpusPath))
	fixtures, err := corpus.Load(*corpusPath)
	if err != nil {
		return fmt.Errorf("load corpus: %w", err)
	}
	logger.Info("corpus loaded", slog.Int("fixtures", len(fixtures)))

	clients, err := buildClients(logger, *encoderURL)
	if err != nil {
		return fmt.Errorf("wire pipeline: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	report, err := corpus.Evaluate(ctx, clients, fixtures, corpus.EvalOptions{
		CorpusVersion:     deriveCorpusVersion(fixtures, *corpusPath),
		EvaluatorVersion:  gitRevParseHead(),
		Path:              *corpusPath,
		PerFixtureTimeout: *perFixtureTimeout,
		TenantID:          *tenantID,
	})
	if err != nil {
		return fmt.Errorf("evaluate corpus: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o750); err != nil {
		return fmt.Errorf("mkdir report dir: %w", err)
	}
	if err := corpus.WriteFile(*outPath, report); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	logger.Info("report written", slog.String("path", *outPath))

	if *printReport {
		printSummary(report)
	}

	regressions, baselineLoaded := compareBaseline(logger, report, *baselinePath, *tolerance)
	if baselineLoaded && len(regressions) > 0 {
		fmt.Fprintln(os.Stderr, "\n--- regressions ---")
		for _, r := range regressions {
			fmt.Fprintf(os.Stderr, "  label=%-7s baseline_f1=%.4f current_f1=%.4f delta=%.4f catastrophic=%v\n",
				r.Label, r.BaselineF1, r.CurrentF1, r.Delta, r.Catastrophic)
		}
		if *failOnRegression {
			return fmt.Errorf("%d label(s) regressed by more than %.2f F1", len(regressions), *tolerance)
		}
	}
	return nil
}

// buildClients wires the production evaluator. The harness honours
// the WS-4b "no silent mocks" invariant: when an upstream is not
// configured, the corresponding client is nil and the evaluator
// surfaces the degraded status in the report.
func buildClients(logger *slog.Logger, encoderURL string) (corpus.PipelineClients, error) {
	gate := tier0.NewGate(tier0.DefaultGateConfig(), nil)
	decider, err := action.NewTierDecider(action.TierThresholds{})
	if err != nil {
		return corpus.PipelineClients{}, fmt.Errorf("tier decider: %w", err)
	}

	clients := corpus.PipelineClients{
		Tier0:       gate,
		Categorizer: evaluate.NewRuleCategorizer(),
		TierDecider: deciderAdapter{d: decider},
		Weights:     evaluate.DefaultWeights(),
		Logger:      logger,
	}

	if encoderURL != "" {
		t1cfg := tier1.Config{
			URL:     encoderURL,
			Timeout: 5 * time.Second,
		}
		t1, terr := tier1.New(t1cfg)
		if terr != nil {
			logger.Warn("encoder URL set but client construction failed; Tier 1 will be skipped",
				slog.String("encoder_url", encoderURL),
				slog.Any("error", terr))
		} else {
			clients.Tier1 = evaluate.NewTier1Adapter(t1, tier1.DefaultThresholds())
			logger.Info("Tier 1 wired", slog.String("encoder_url", encoderURL))
		}
	} else {
		logger.Warn("SN360_ENCODER_URL not set; Tier 1 will be SKIPPED in this run")
	}

	// Tier 2 (SLM/LLM) wiring is deliberately omitted from the
	// harness binary: instantiating it requires either a local SLM
	// process or an external LLM API key, neither of which is
	// available in the default CI environment. The report
	// surfaces the absence via TierCoverage.Tier2Configured=false.
	logger.Warn("Tier 2 not wired; corpus harness runs Tier 0 + (optional) Tier 1 only")

	return clients, nil
}

// deciderAdapter bridges the production *action.TierDecider to the
// evaluate.TierDecider interface — same shim used elsewhere in the
// codebase (see internal/service/evaluate/accuracy_test.go).
type deciderAdapter struct{ d *action.TierDecider }

func (a deciderAdapter) Decide(score int, primary constant.Category, _ dto.RiskSignals) constant.Tier {
	return a.d.Decide(dto.EvaluateResult{Score: score, Primary: primary})
}

// printSummary writes a human-readable summary of the report to
// stdout. It exists so operators running the harness locally see
// something useful without having to jq the JSON.
func printSummary(r corpus.Report) {
	fmt.Println()
	fmt.Println("=== corpus-eval summary ===")
	fmt.Printf("corpus:           %s\n", r.CorpusPath)
	fmt.Printf("corpus_version:   %s\n", r.CorpusVersion)
	fmt.Printf("evaluator:        %s\n", r.EvaluatorVersion)
	fmt.Printf("evaluated_at:     %s\n", r.EvaluatedAt.Format(time.RFC3339))
	fmt.Printf("total_fixtures:   %d\n", r.TotalFixtures)
	fmt.Printf("aggregate_accuracy: %.4f\n", r.AggregateAccuracy)
	fmt.Printf("macro_f1:         %.4f\n", r.MacroF1)
	fmt.Printf("synthetic_only:   %v\n", r.SyntheticOnly)
	fmt.Printf("full_pipeline:    %v (tier0=%v tier1=%v/%v tier2=%v/%v rspamd=%v/%v)\n",
		r.TierCoverage.FullPipeline(),
		r.TierCoverage.Tier0Executed,
		r.TierCoverage.Tier1Configured, r.TierCoverage.Tier1Executed,
		r.TierCoverage.Tier2Configured, r.TierCoverage.Tier2Executed,
		r.TierCoverage.RspamdConfigured, r.TierCoverage.RspamdExecuted)
	if r.DegradedFixtures > 0 {
		fmt.Printf("degraded_fixtures: %d (%s)\n", r.DegradedFixtures, formatDegraded(r.DegradedReasons))
	}
	fmt.Println()
	fmt.Println("per-label metrics:")
	for _, l := range corpus.AllLabels {
		m := r.PerLabel[l]
		fmt.Printf("  %-7s support=%-4d tp=%-3d fp=%-3d fn=%-3d precision=%.4f recall=%.4f f1=%.4f\n",
			l, m.Support, m.TP, m.FP, m.FN, m.Precision, m.Recall, m.F1)
	}
	if len(r.Misclassifications) > 0 {
		fmt.Printf("\n%d misclassifications (first 10 shown):\n", len(r.Misclassifications))
		for i, mc := range r.Misclassifications {
			if i >= 10 {
				break
			}
			fmt.Printf("  %s: true=%s predicted=%s (predicted_primary=%s, score=%d, reasons=%v)\n",
				mc.ID, mc.Label, mc.PredictedLabel, mc.PredictedPrim, mc.Score, mc.ReasonCodes)
		}
	}
	if r.SyntheticOnly {
		fmt.Println()
		fmt.Println("NOTE: this run used a SYNTHETIC corpus. Headline numbers are NOT a substitute for")
		fmt.Println("a real-world labelled corpus. Replace testdata/corpus-eval/synthetic.jsonl with")
		fmt.Println("real fixtures and regenerate the baseline before reporting these figures externally.")
	}
}

func formatDegraded(m map[string]int) string {
	if len(m) == 0 {
		return "no services unavailable"
	}
	var parts []string
	for svc, n := range m {
		parts = append(parts, fmt.Sprintf("%s=%d", svc, n))
	}
	return strings.Join(parts, ",")
}

func compareBaseline(logger *slog.Logger, current corpus.Report, baselinePath string, tolerance float64) ([]corpus.Regression, bool) {
	if baselinePath == "" {
		return nil, false
	}
	baseline, err := corpus.LoadReport(baselinePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn("baseline report not found; skipping regression check", slog.String("path", baselinePath))
			return nil, false
		}
		logger.Warn("baseline report unavailable; skipping regression check",
			slog.String("path", baselinePath), slog.Any("error", err))
		return nil, false
	}
	regressions := corpus.CompareToBaseline(current, baseline, tolerance)
	return regressions, true
}

// deriveCorpusVersion synthesises the CorpusVersion string for the
// run. When every fixture metadata carries the synthetic version
// tag, we surface "<tag>-size=<N>"; otherwise we fall back to the
// file basename so curators can identify which corpus produced the
// report.
func deriveCorpusVersion(fixtures []corpus.Fixture, path string) string {
	syntheticTag := ""
	for _, fx := range fixtures {
		v := fx.Metadata["source"]
		if v == "" {
			syntheticTag = ""
			break
		}
		if syntheticTag == "" {
			syntheticTag = v
		} else if syntheticTag != v {
			syntheticTag = ""
			break
		}
	}
	if syntheticTag != "" {
		return fmt.Sprintf("%s-size=%d", syntheticTag, len(fixtures))
	}
	return filepath.Base(path)
}

// gitRevParseHead returns the current git HEAD SHA (short form),
// or the empty string if git is unavailable. It is best-effort
// metadata; harness correctness does not depend on git being
// reachable.
func gitRevParseHead() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--short", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
