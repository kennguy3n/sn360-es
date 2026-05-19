//go:build benchmark
// +build benchmark

package evaluate_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/testdata/corpus"
)

// promBuckets mirrors the histogram buckets exposed by the production
// evaluator's Prometheus latency histogram (see
// internal/observability/metrics.go). Keeping them aligned means the
// benchmark output is directly comparable to live data.
var promBuckets = []time.Duration{
	1 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2500 * time.Millisecond,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

// TestLatencyDistribution evaluates the corpus and prints a histogram
// of per-message latencies bucketed by the Prometheus buckets above.
// The output is suitable for committing under benchmarks/ for trend
// tracking.
//
// Invoke via:
//
//	go test -tags=benchmark -run=TestLatencyDistribution -v \
//	    ./internal/service/evaluate/...
func TestLatencyDistribution(t *testing.T) {
	const corpusSize = 5000
	emails := corpus.Generate(corpus.Config{Seed: 42, Size: corpusSize})
	ev := buildAccuracyEvaluator(t)
	ctx := context.Background()

	counts := make([]int, len(promBuckets)+1)
	var totalLatency time.Duration
	var maxLatency time.Duration
	for _, e := range emails {
		t0 := time.Now()
		if _, err := ev.Evaluate(ctx, e.Request, e.Request.Signals); err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		d := time.Since(t0)
		totalLatency += d
		if d > maxLatency {
			maxLatency = d
		}
		counts[bucketIndex(d)]++
	}

	report := renderLatencyHistogram(counts, len(emails), totalLatency, maxLatency)
	t.Log("\n" + report)
	if dir := os.Getenv("BENCH_PROFILE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		path := filepath.Join(dir, fmt.Sprintf("latency_distribution_%s.txt", time.Now().Format("20060102")))
		if err := os.WriteFile(path, []byte(report), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote latency distribution to %s", path)
	}
}

// bucketIndex returns the index in promBuckets+1 corresponding to the
// first bucket boundary that is >= d. The trailing bucket index
// (len(promBuckets)) represents "above the largest bucket".
func bucketIndex(d time.Duration) int {
	for i, b := range promBuckets {
		if d <= b {
			return i
		}
	}
	return len(promBuckets)
}

// renderLatencyHistogram formats the histogram as a plain-text table
// with a low-tech sparkline (`#` per ~2% of total) so the distribution
// is readable both in CI logs and committed artefacts.
func renderLatencyHistogram(counts []int, total int, totalLatency, maxLatency time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Latency Distribution (%d samples)\n", total)
	fmt.Fprintf(&b, "  Avg:  %s\n", totalLatency/time.Duration(total))
	fmt.Fprintf(&b, "  Max:  %s\n\n", maxLatency)
	fmt.Fprintf(&b, "  %-8s  %-12s  %-10s  %s\n", "le", "count", "pct", "histogram")
	fmt.Fprintf(&b, "  %s\n", strings.Repeat("-", 60))
	for i, c := range counts {
		var label string
		if i < len(promBuckets) {
			label = promBuckets[i].String()
		} else {
			label = "+Inf"
		}
		pct := 100.0 * float64(c) / float64(total)
		bar := strings.Repeat("#", int(pct/2)+1)
		if c == 0 {
			bar = ""
		}
		fmt.Fprintf(&b, "  %-8s  %-12d  %-9.2f%%  %s\n", label, c, pct, bar)
	}
	return b.String()
}
