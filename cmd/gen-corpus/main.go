// Command gen-corpus serialises a deterministic labelled email corpus
// to a file on disk. The output is consumed by the accuracy benchmark
// suite under internal/service/evaluate/accuracy_test.go and by any
// external tools (perf-harness, ad-hoc evaluation runs) that need a
// stable set of labelled inputs.
//
// Usage:
//
//	gen-corpus -size=1000 -seed=42 -out=internal/testdata/corpus/corpus_1000.json
//	gen-corpus -size=500  -seed=7  -out=corpus.csv -format=csv
//
// Defaults match the values used by `make gen-corpus`.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kennguy3n/sn360-es/internal/testdata/corpus"
)

func main() {
	size := flag.Int("size", 1000, "number of labelled emails to generate")
	seed := flag.Int64("seed", 42, "PRNG seed; same seed → byte-identical output")
	minPerCategory := flag.Int("min-per-category", 50, "minimum number of emails generated per category")
	out := flag.String("out", "internal/testdata/corpus/corpus_1000.json", "output file path")
	format := flag.String("format", "", "output format: json | csv (inferred from -out suffix when unset)")
	flag.Parse()

	if err := run(*size, *seed, *minPerCategory, *out, *format); err != nil {
		fmt.Fprintf(os.Stderr, "gen-corpus: %v\n", err)
		os.Exit(1)
	}
}

func run(size int, seed int64, minPerCategory int, out, format string) error {
	if size <= 0 {
		return fmt.Errorf("size must be > 0, got %d", size)
	}
	if out == "" {
		return fmt.Errorf("-out is required")
	}

	// Format inference: explicit -format=csv wins; otherwise we look at
	// the suffix of -out so `-out=corpus.csv` does the obvious thing.
	if format == "" || format == "auto" {
		switch filepath.Ext(out) {
		case ".csv":
			format = "csv"
		default:
			format = "json"
		}
	}

	c := corpus.Generate(corpus.Config{
		Seed:           seed,
		Size:           size,
		MinPerCategory: minPerCategory,
	})

	if dir := filepath.Dir(out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create output directory %s: %w", dir, err)
		}
	}

	if err := corpus.WriteFile(out, c, format); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Fprintf(os.Stdout, "gen-corpus: wrote %d records to %s (format=%s, seed=%d)\n",
		len(c), out, format, seed)
	return nil
}
