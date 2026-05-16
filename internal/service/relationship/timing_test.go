package relationship

import (
	"testing"
	"time"
)

func TestTimingAnalyzer_InsufficientBaseline(t *testing.T) {
	a := NewTimingAnalyzer(TimingAnalyzerConfig{}, nil)
	for i := 0; i < 3; i++ {
		_ = a.Record("sender-1", time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC))
	}
	sig, err := a.AnalyzeTiming("sender-1", time.Date(2026, 5, 1, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("AnalyzeTiming: %v", err)
	}
	if sig.IsAnomalous {
		t.Fatalf("should not be anomalous with insufficient baseline")
	}
	if sig.Reason != "insufficient_baseline" {
		t.Fatalf("reason: %q", sig.Reason)
	}
}

func TestTimingAnalyzer_DetectsOffHoursSender(t *testing.T) {
	a := NewTimingAnalyzer(TimingAnalyzerConfig{}, nil)
	// Baseline: sender consistently sends at 10am UTC.
	for i := 0; i < 30; i++ {
		_ = a.Record("sender-1", time.Date(2026, 4, 1+i, 10, 0, 0, 0, time.UTC))
	}
	// Suspicious: 3am UTC message.
	sig, _ := a.AnalyzeTiming("sender-1", time.Date(2026, 5, 1, 3, 0, 0, 0, time.UTC))
	if !sig.IsAnomalous {
		t.Fatalf("expected anomalous signal, got score=%.2f", sig.Score)
	}
}

func TestTimingAnalyzer_NoAnomalyForConsistentSender(t *testing.T) {
	a := NewTimingAnalyzer(TimingAnalyzerConfig{}, nil)
	for i := 0; i < 30; i++ {
		_ = a.Record("sender-1", time.Date(2026, 4, 1+i, 10, 0, 0, 0, time.UTC))
	}
	sig, _ := a.AnalyzeTiming("sender-1", time.Date(2026, 5, 1, 10, 30, 0, 0, time.UTC))
	if sig.IsAnomalous {
		t.Fatalf("did not expect anomaly for in-window send (score=%.2f)", sig.Score)
	}
}

func TestTimingAnalyzer_RejectsEmptySender(t *testing.T) {
	a := NewTimingAnalyzer(TimingAnalyzerConfig{}, nil)
	if err := a.Record("", time.Now()); err == nil {
		t.Fatal("expected error for empty sender_hash")
	}
	if _, err := a.AnalyzeTiming("", time.Now()); err == nil {
		t.Fatal("expected error for empty sender_hash")
	}
}

func TestHourDistance(t *testing.T) {
	cases := []struct {
		a, b, want int
	}{
		{10, 10, 0},
		{10, 12, 2},
		{0, 23, 1},
		{1, 13, 12},
		{2, 14, 12},
	}
	for _, c := range cases {
		if got := hourDistance(c.a, c.b); got != c.want {
			t.Fatalf("hourDistance(%d,%d) = %d; want %d", c.a, c.b, got, c.want)
		}
	}
}
