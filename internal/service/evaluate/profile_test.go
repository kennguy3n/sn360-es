//go:build benchmark
// +build benchmark

package evaluate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/testdata/corpus"
)

// ResourceReport captures the wall-clock, allocation and goroutine
// footprint of a full corpus replay through the evaluator. It is the
// structured output of TestResourceProfile.
type ResourceReport struct {
	Timestamp      time.Time     `json:"timestamp"`
	CorpusSize     int           `json:"corpus_size"`
	TotalDuration  time.Duration `json:"total_duration"`
	AvgLatency     time.Duration `json:"avg_latency"`
	P50Latency     time.Duration `json:"p50_latency"`
	P95Latency     time.Duration `json:"p95_latency"`
	P99Latency     time.Duration `json:"p99_latency"`
	MaxLatency     time.Duration `json:"max_latency"`
	ThroughputEPS  float64       `json:"throughput_eps"`
	PeakMemoryMB   float64       `json:"peak_memory_mb"`
	TotalAllocsMB  float64       `json:"total_allocs_mb"`
	GCPauses       int           `json:"gc_pauses"`
	GCPauseMaxMs   float64       `json:"gc_pause_max_ms"`
	PeakGoroutines int           `json:"peak_goroutines"`
}

// FormatText renders the report as a human-readable plain-text block.
// The format is stable so make bench-profile output can be diffed
// across runs.
func (r *ResourceReport) FormatText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Resource Profile\n")
	fmt.Fprintf(&b, "================\n")
	fmt.Fprintf(&b, "Timestamp:        %s\n", r.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "Corpus size:      %d\n", r.CorpusSize)
	fmt.Fprintf(&b, "Total duration:   %s\n", r.TotalDuration)
	fmt.Fprintf(&b, "Avg latency:      %s\n", r.AvgLatency)
	fmt.Fprintf(&b, "p50 latency:      %s\n", r.P50Latency)
	fmt.Fprintf(&b, "p95 latency:      %s\n", r.P95Latency)
	fmt.Fprintf(&b, "p99 latency:      %s\n", r.P99Latency)
	fmt.Fprintf(&b, "max latency:      %s\n", r.MaxLatency)
	fmt.Fprintf(&b, "Throughput:       %.2f emails/sec\n", r.ThroughputEPS)
	fmt.Fprintf(&b, "Peak memory:      %.2f MB\n", r.PeakMemoryMB)
	fmt.Fprintf(&b, "Total alloc:      %.2f MB\n", r.TotalAllocsMB)
	fmt.Fprintf(&b, "GC pauses:        %d (max %.3f ms)\n", r.GCPauses, r.GCPauseMaxMs)
	fmt.Fprintf(&b, "Peak goroutines:  %d\n", r.PeakGoroutines)
	return b.String()
}

// TestResourceProfile replays the corpus through the evaluator and
// records the runtime footprint. It writes the report to
// $BENCH_PROFILE_DIR/profile_<date>.txt when set; otherwise the report
// is emitted via t.Log so `go test -v` captures it.
//
// Invoke via:
//
//	go test -tags=benchmark -run=TestResourceProfile -v \
//	    ./internal/service/evaluate/...
func TestResourceProfile(t *testing.T) {
	const corpusSize = 10000
	emails := corpus.Generate(corpus.Config{Seed: 42, Size: corpusSize})
	ev := buildAccuracyEvaluator(t)
	ctx := context.Background()

	runtime.GC()
	var baseline, peak runtime.MemStats
	runtime.ReadMemStats(&baseline)
	peakGoroutines := runtime.NumGoroutine()

	latencies := make([]time.Duration, 0, len(emails))
	start := time.Now()
	for _, e := range emails {
		t0 := time.Now()
		if _, err := ev.Evaluate(ctx, e.Request, e.Request.Signals); err != nil {
			t.Fatalf("evaluate %s: %v", e.Request.MessageID, err)
		}
		latencies = append(latencies, time.Since(t0))
		if g := runtime.NumGoroutine(); g > peakGoroutines {
			peakGoroutines = g
		}
		if len(latencies)%500 == 0 {
			var cur runtime.MemStats
			runtime.ReadMemStats(&cur)
			if cur.HeapAlloc > peak.HeapAlloc {
				peak = cur
			}
		}
	}
	total := time.Since(start)

	var final runtime.MemStats
	runtime.ReadMemStats(&final)
	if final.HeapAlloc > peak.HeapAlloc {
		peak = final
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	report := &ResourceReport{
		Timestamp:      time.Now().UTC(),
		CorpusSize:     len(emails),
		TotalDuration:  total,
		AvgLatency:     totalDuration(latencies) / time.Duration(len(latencies)),
		P50Latency:     percentile(latencies, 0.50),
		P95Latency:     percentile(latencies, 0.95),
		P99Latency:     percentile(latencies, 0.99),
		MaxLatency:     latencies[len(latencies)-1],
		ThroughputEPS:  float64(len(latencies)) / total.Seconds(),
		PeakMemoryMB:   bytesToMB(peak.HeapAlloc),
		TotalAllocsMB:  bytesToMB(final.TotalAlloc - baseline.TotalAlloc),
		GCPauses:       int(final.NumGC - baseline.NumGC),
		GCPauseMaxMs:   float64(maxGCPause(final)) / float64(time.Millisecond),
		PeakGoroutines: peakGoroutines,
	}

	t.Log("\n" + report.FormatText())
	if dir := os.Getenv("BENCH_PROFILE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		path := filepath.Join(dir, fmt.Sprintf("profile_%s.txt", time.Now().Format("20060102")))
		if err := os.WriteFile(path, []byte(report.FormatText()), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		jsonPath := filepath.Join(dir, fmt.Sprintf("profile_%s.json", time.Now().Format("20060102")))
		blob, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(jsonPath, blob, 0o644); err != nil {
			t.Fatalf("write %s: %v", jsonPath, err)
		}
		t.Logf("wrote profile to %s and %s", path, jsonPath)
	}
}

// percentile returns the p-th percentile (0 <= p <= 1) using the
// nearest-rank method on a pre-sorted slice.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	idx := int(float64(len(sorted)) * p)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// totalDuration is a tiny helper because time.Duration is signed and
// summing into a single Duration overflows for very large corpora; we
// use it only for averages on samples of <=10k.
func totalDuration(d []time.Duration) time.Duration {
	var sum time.Duration
	for _, x := range d {
		sum += x
	}
	return sum
}

func bytesToMB(b uint64) float64 {
	return float64(b) / 1024.0 / 1024.0
}

// maxGCPause returns the max value in the rolling-256 GC pause buffer
// exposed by runtime.MemStats.
func maxGCPause(m runtime.MemStats) uint64 {
	var max uint64
	for _, p := range m.PauseNs {
		if p > max {
			max = p
		}
	}
	return max
}
