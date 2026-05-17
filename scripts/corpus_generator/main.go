// Command corpus_generator produces synthetic test emails for the
// SN360-ES evaluation harness. The output is a directory of JSON files
// — one per category plus an aggregated `all.json` — that conform to
// scripts/corpus_schema.json and exercise the full Tier 0 / Tier 1 /
// Tier 2 detection pipeline.
//
// The generator imports internal/constant so the category and tier
// vocabularies stay in lock-step with the runtime code: changing a
// category name in internal/constant/categories.go automatically
// propagates here.
//
// Models referenced (NEVER change provider in any prompt or comment):
//   - Tier 1: XLM-RoBERTa encoder served by deployments/encoder/ on
//     port 8080.
//   - Tier 2: Ternary-Bonsai-8B-Q2_0 GGUF served by deployments/llm/
//     (kennguy3n/llama.cpp fork) on port 9000.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/scripts/corpus_generator/templates"
)

// CLI is the parsed command-line configuration.
type CLI struct {
	Categories       string
	CountPerCategory int
	DifficultySplit  string
	Locales          string
	LocaleSplit      string
	OutputDir        string
	Seed             int64
	LLMAssist        bool
	LLMURL           string
	Tier1URL         string
	ValidateOnly     bool
	ValidateModels   bool
}

func main() {
	cli, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "corpus_generator:", err)
		os.Exit(2)
	}
	if err := run(cli); err != nil {
		fmt.Fprintln(os.Stderr, "corpus_generator:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (CLI, error) {
	fs := flag.NewFlagSet("corpus_generator", flag.ContinueOnError)

	var cli CLI
	fs.StringVar(&cli.Categories, "categories", "all", "Comma-separated category names from internal/constant/categories.go, or 'all'.")
	fs.IntVar(&cli.CountPerCategory, "count-per-category", 470, "Total emails to generate per category (malicious + benign).")
	fs.StringVar(&cli.DifficultySplit, "difficulty-split", "33/34/33", "easy/medium/hard percentage split.")
	fs.StringVar(&cli.Locales, "locales", "en,th,ja,ko,zh,vi", "Comma-separated locales.")
	fs.StringVar(&cli.LocaleSplit, "locale-split", "80/4/4/4/4/4", "Per-locale percentage split aligned with -locales.")
	fs.StringVar(&cli.OutputDir, "output-dir", "./scripts/corpus/evaluation/", "Output directory for per-category JSON files.")
	fs.Int64Var(&cli.Seed, "seed", 42, "PRNG seed for deterministic generation.")
	fs.BoolVar(&cli.LLMAssist, "llm-assist", false, "Use Ternary-Bonsai-8B (via kennguy3n/llama.cpp) for hard-to-template categories.")
	fs.StringVar(&cli.LLMURL, "llm-url", "http://127.0.0.1:9000", "Ternary-Bonsai-8B server URL (matches AI.URL config).")
	fs.StringVar(&cli.Tier1URL, "tier1-url", "http://127.0.0.1:8080", "XLM-RoBERTa encoder URL (matches Tier1.URL config).")
	fs.BoolVar(&cli.ValidateOnly, "validate-only", false, "Skip generation, just validate existing corpus.")
	fs.BoolVar(&cli.ValidateModels, "validate-models", false, "After generation, run corpus through real Tier 1 + Tier 2 models.")

	if err := fs.Parse(args); err != nil {
		return cli, err
	}
	if cli.CountPerCategory <= 0 {
		return cli, errors.New("count-per-category must be positive")
	}
	return cli, nil
}

func run(cli CLI) error {
	cats, err := resolveCategories(cli.Categories)
	if err != nil {
		return err
	}
	difficulty, err := parsePercentSplit(cli.DifficultySplit, 3)
	if err != nil {
		return fmt.Errorf("difficulty-split: %w", err)
	}
	locales := splitNonEmpty(cli.Locales, ",")
	if len(locales) == 0 {
		return errors.New("at least one locale is required")
	}
	localeWeights, err := parsePercentSplit(cli.LocaleSplit, len(locales))
	if err != nil {
		return fmt.Errorf("locale-split: %w", err)
	}

	opts := GenerateOptions{
		Categories:       cats,
		CountPerCategory: cli.CountPerCategory,
		DifficultyPct:    [3]int{difficulty[0], difficulty[1], difficulty[2]},
		Locales:          locales,
		LocaleWeights:    localeWeights,
		OutputDir:        cli.OutputDir,
		Seed:             cli.Seed,
		Registry:         templates.DefaultRegistry(),
	}

	if cli.ValidateOnly {
		report, err := ValidateCorpus(opts.OutputDir)
		if err != nil {
			return fmt.Errorf("validate-only: %w", err)
		}
		fmt.Print(report.Render())
		if !report.OK {
			return errors.New("validation failed")
		}
		return nil
	}

	gen := NewGenerator(opts)
	if cli.LLMAssist {
		client := NewLLMClient(cli.LLMURL)
		gen.WithLLMAssist(client)
	}
	if err := gen.Run(); err != nil {
		return err
	}
	report, err := ValidateCorpus(opts.OutputDir)
	if err != nil {
		return fmt.Errorf("post-generation validation: %w", err)
	}
	fmt.Print(report.Render())
	if !report.OK {
		return errors.New("post-generation validation failed")
	}

	if cli.ValidateModels {
		mv := NewModelValidator(cli.Tier1URL, cli.LLMURL, opts.OutputDir)
		mvReport, err := mv.Run()
		if err != nil {
			return fmt.Errorf("model validation: %w", err)
		}
		fmt.Print(mvReport.Render())
	}
	return nil
}

func resolveCategories(spec string) ([]constant.Category, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "all") {
		return append([]constant.Category(nil), constant.AllCategories...), nil
	}
	wanted := splitNonEmpty(spec, ",")
	out := make([]constant.Category, 0, len(wanted))
	for _, w := range wanted {
		c := constant.Category(strings.TrimSpace(w))
		if !c.Valid() {
			return nil, fmt.Errorf("unknown category: %q", w)
		}
		out = append(out, c)
	}
	return out, nil
}

// parsePercentSplit parses a slash-separated list of integer
// percentages and returns them as a slice. It tolerates trailing
// totals within +/-2 of 100 to account for rounding.
func parsePercentSplit(spec string, expected int) ([]int, error) {
	parts := strings.Split(spec, "/")
	if len(parts) != expected {
		return nil, fmt.Errorf("expected %d parts, got %d", expected, len(parts))
	}
	out := make([]int, len(parts))
	total := 0
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("part %d: %w", i, err)
		}
		if n < 0 || n > 100 {
			return nil, fmt.Errorf("part %d out of range: %d", i, n)
		}
		out[i] = n
		total += n
	}
	if total < 98 || total > 102 {
		return nil, fmt.Errorf("percentages must sum to ~100, got %d", total)
	}
	return out, nil
}

func splitNonEmpty(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
