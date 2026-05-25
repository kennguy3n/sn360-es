package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubResults is a deterministic ResultRepository.
type stubResults struct {
	feedback   []Feedback
	weights    ScoreWeights
	thresholds Thresholds
	fbErr      error
	wErr       error
	tErr       error
}

func (s stubResults) RecentFeedback(_ context.Context, _ string, _ time.Time) ([]Feedback, error) {
	return s.feedback, s.fbErr
}

func (s stubResults) CurrentWeights(_ context.Context, _ string) (ScoreWeights, error) {
	return s.weights, s.wErr
}

func (s stubResults) CurrentThresholds(_ context.Context, _ string) (Thresholds, error) {
	return s.thresholds, s.tErr
}

// recordingConfig2 captures persistence calls without the onboarding fixture's
// lock contention, and supports injected failures.
type recordingConfig2 struct {
	mu         sync.Mutex
	weights    []ScoreWeights
	thresholds []Thresholds
	wErr       error
	tErr       error
}

func (c *recordingConfig2) UpdateWeights(_ context.Context, _ string, w ScoreWeights) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wErr != nil {
		return c.wErr
	}
	c.weights = append(c.weights, w)
	return nil
}

func (c *recordingConfig2) UpdateThresholds(_ context.Context, _ string, t Thresholds) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tErr != nil {
		return c.tErr
	}
	c.thresholds = append(c.thresholds, t)
	return nil
}

func balancedWeights() ScoreWeights {
	return ScoreWeights{AI: 0.60, Rspamd: 0.10, Attachments: 0.15, Links: 0.15}
}

func defaultThresholds() Thresholds {
	return Thresholds{
		Tier1PassBelow: 20,
		Tier1FlagAbove: 70,
		BannerBlocked:  85,
		BannerHighRisk: 70,
		BannerWarning:  50,
		BannerCaution:  30,
		BannerInfo:     10,
	}
}

func TestNewTuningAgent_RequiresResultsAndConfig(t *testing.T) {
	if _, err := NewTuningAgent(TuningConfig{Config: &recordingConfig2{}}); err == nil {
		t.Fatal("expected error when Results is nil")
	}
	if _, err := NewTuningAgent(TuningConfig{Results: stubResults{}}); err == nil {
		t.Fatal("expected error when Config is nil")
	}
}

func TestNewTuningAgent_AppliesDefaults(t *testing.T) {
	a, err := NewTuningAgent(TuningConfig{
		Results: stubResults{},
		Config:  &recordingConfig2{},
		Logger:  discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewTuningAgent: %v", err)
	}
	if a.cfg.Window != 7*24*time.Hour {
		t.Fatalf("Window default: %v", a.cfg.Window)
	}
	if a.cfg.MinSampleSize != 25 {
		t.Fatalf("MinSampleSize default: %d", a.cfg.MinSampleSize)
	}
	if a.cfg.MaxWeightShiftPerRun != 0.05 {
		t.Fatalf("MaxWeightShiftPerRun default: %v", a.cfg.MaxWeightShiftPerRun)
	}
	if a.cfg.MaxThresholdShiftPerRun != 5 {
		t.Fatalf("MaxThresholdShiftPerRun default: %d", a.cfg.MaxThresholdShiftPerRun)
	}
	if a.cfg.FPRateTarget != 0.05 || a.cfg.FNRateTarget != 0.02 {
		t.Fatalf("rate targets: fp=%v fn=%v", a.cfg.FPRateTarget, a.cfg.FNRateTarget)
	}
}

func TestTuningAgent_Decide_NoopBelowSampleFloor(t *testing.T) {
	a, _ := NewTuningAgent(TuningConfig{
		Results:       stubResults{},
		Config:        &recordingConfig2{},
		MinSampleSize: 25,
		Logger:        discardLogger(),
	})
	d := a.Decide(TuningSnapshot{TotalEvaluations: 10})
	if d.NewWeights != nil || d.NewThresholds != nil {
		t.Fatal("expected no-op when below sample floor")
	}
	if len(d.Notes) != 1 || !strings.Contains(d.Notes[0], "below floor") {
		t.Fatalf("notes: %+v", d.Notes)
	}
}

func TestTuningAgent_Decide_FPHigh_ShiftsWeightsAndRaisesThresholds(t *testing.T) {
	a, _ := NewTuningAgent(TuningConfig{
		Results: stubResults{},
		Config:  &recordingConfig2{},
		Logger:  discardLogger(),
	})
	snap := TuningSnapshot{
		TotalEvaluations:  100,
		FalsePositives:    20, // 20% > target 5%
		FalseNegatives:    1,
		CurrentWeights:    balancedWeights(),
		CurrentThresholds: defaultThresholds(),
	}
	d := a.Decide(snap)
	if d.NewWeights == nil {
		t.Fatal("expected NewWeights set")
	}
	if d.NewWeights.AI >= 0.60 {
		t.Fatalf("AI should decrease, got %v", d.NewWeights.AI)
	}
	if d.NewWeights.Rspamd <= 0.10 {
		t.Fatalf("Rspamd should increase, got %v", d.NewWeights.Rspamd)
	}
	if d.NewThresholds == nil {
		t.Fatal("expected NewThresholds set (fp rate exceeds target+0.01)")
	}
	if d.NewThresholds.BannerWarning <= defaultThresholds().BannerWarning {
		t.Fatalf("BannerWarning should rise: %d", d.NewThresholds.BannerWarning)
	}
}

func TestTuningAgent_Decide_FNHigh_ShiftsWeightsAndLowersThresholds(t *testing.T) {
	a, _ := NewTuningAgent(TuningConfig{
		Results: stubResults{},
		Config:  &recordingConfig2{},
		Logger:  discardLogger(),
	})
	snap := TuningSnapshot{
		TotalEvaluations:  100,
		FalsePositives:    1,
		FalseNegatives:    15, // 15% > target 2%
		CurrentWeights:    balancedWeights(),
		CurrentThresholds: defaultThresholds(),
	}
	d := a.Decide(snap)
	if d.NewWeights == nil || d.NewWeights.AI <= 0.60 {
		t.Fatalf("AI weight should increase: %+v", d.NewWeights)
	}
	if d.NewThresholds == nil {
		t.Fatal("expected NewThresholds set")
	}
	if d.NewThresholds.BannerWarning >= defaultThresholds().BannerWarning {
		t.Fatalf("BannerWarning should drop: %d", d.NewThresholds.BannerWarning)
	}
}

func TestTuningAgent_Decide_WithinTarget_NoChange(t *testing.T) {
	a, _ := NewTuningAgent(TuningConfig{
		Results: stubResults{},
		Config:  &recordingConfig2{},
		Logger:  discardLogger(),
	})
	snap := TuningSnapshot{
		TotalEvaluations:  100,
		FalsePositives:    2, // 2%
		FalseNegatives:    1, // 1%
		CurrentWeights:    balancedWeights(),
		CurrentThresholds: defaultThresholds(),
	}
	d := a.Decide(snap)
	if d.NewWeights != nil || d.NewThresholds != nil {
		t.Fatalf("expected no-op decision, got %+v", d)
	}
	if len(d.Notes) == 0 || !strings.Contains(d.Notes[0], "within target band") {
		t.Fatalf("notes: %+v", d.Notes)
	}
}

func TestTuningAgent_Decide_WeightShiftCappedByMax(t *testing.T) {
	a, _ := NewTuningAgent(TuningConfig{
		Results:              stubResults{},
		Config:               &recordingConfig2{},
		MaxWeightShiftPerRun: 0.03,
		Logger:               discardLogger(),
	})
	// FP rate = 50% — would otherwise want to shift 0.45.
	snap := TuningSnapshot{
		TotalEvaluations:  100,
		FalsePositives:    50,
		FalseNegatives:    1,
		CurrentWeights:    balancedWeights(),
		CurrentThresholds: defaultThresholds(),
	}
	d := a.Decide(snap)
	if d.NewWeights == nil {
		t.Fatal("expected NewWeights set")
	}
	// Weights are normalised; we test the AI delta indirectly via the ratio.
	// The shift before clamp should be ≤ MaxWeightShiftPerRun.
	// With MaxWeightShiftPerRun=0.03, AI should not drop below 0.60-0.03=0.57.
	if d.NewWeights.AI < 0.60-0.03-0.001 {
		t.Fatalf("weight shift exceeded cap: %+v", d.NewWeights)
	}
}

func TestTuningAgent_Tune_PersistsAndAudits(t *testing.T) {
	cfgStore := &recordingConfig2{}
	audit := &recordingAudit{}
	repo := stubResults{
		feedback: func() []Feedback {
			out := make([]Feedback, 0, 50)
			for i := 0; i < 30; i++ {
				out = append(out, Feedback{Action: FeedbackMarkSafe})
			}
			for i := 0; i < 5; i++ {
				out = append(out, Feedback{Action: FeedbackReportPhishing})
			}
			return out
		}(),
		weights:    balancedWeights(),
		thresholds: defaultThresholds(),
	}
	a, _ := NewTuningAgent(TuningConfig{
		Results: repo,
		Config:  cfgStore,
		Audit:   audit,
		Logger:  discardLogger(),
	})
	d, err := a.Tune(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Tune: %v", err)
	}
	if d.TenantID != "acme" {
		t.Fatalf("TenantID: %q", d.TenantID)
	}
	if len(cfgStore.weights) != 1 {
		t.Fatalf("expected one weight persist, got %d", len(cfgStore.weights))
	}
	if len(cfgStore.thresholds) != 1 {
		t.Fatalf("expected one threshold persist, got %d", len(cfgStore.thresholds))
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "tuning.decision" {
		t.Fatalf("audit: %+v", audit.entries)
	}
}

func TestTuningAgent_Tune_RequiresTenantID(t *testing.T) {
	a, _ := NewTuningAgent(TuningConfig{
		Results: stubResults{},
		Config:  &recordingConfig2{},
		Logger:  discardLogger(),
	})
	if _, err := a.Tune(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty tenant")
	}
}

func TestTuningAgent_Tune_PropagatesLookupErrors(t *testing.T) {
	cases := map[string]stubResults{
		"feedback":   {fbErr: errors.New("fb")},
		"weights":    {wErr: errors.New("w")},
		"thresholds": {tErr: errors.New("t")},
	}
	for name, repo := range cases {
		t.Run(name, func(t *testing.T) {
			a, _ := NewTuningAgent(TuningConfig{
				Results: repo,
				Config:  &recordingConfig2{},
				Logger:  discardLogger(),
			})
			if _, err := a.Tune(context.Background(), "acme"); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestTuningAgent_Tune_PersistFailureReturnsError(t *testing.T) {
	repo := stubResults{
		feedback: func() []Feedback {
			out := make([]Feedback, 0, 30)
			for i := 0; i < 30; i++ {
				out = append(out, Feedback{Action: FeedbackMarkSafe})
			}
			return out
		}(),
		weights:    balancedWeights(),
		thresholds: defaultThresholds(),
	}
	a, _ := NewTuningAgent(TuningConfig{
		Results: repo,
		Config:  &recordingConfig2{wErr: errors.New("write boom")},
		Logger:  discardLogger(),
	})
	if _, err := a.Tune(context.Background(), "acme"); err == nil {
		t.Fatal("expected UpdateWeights error to propagate")
	}
}

func TestClampThresholds_PreservesOrdering(t *testing.T) {
	in := Thresholds{
		BannerBlocked:  85,
		BannerHighRisk: 95, // illegal — above Blocked
		BannerWarning:  90,
		BannerCaution:  92,
		BannerInfo:     88,
	}
	got := clampThresholds(in)
	if got.BannerBlocked <= got.BannerHighRisk ||
		got.BannerHighRisk <= got.BannerWarning ||
		got.BannerWarning <= got.BannerCaution ||
		got.BannerCaution <= got.BannerInfo {
		t.Fatalf("ordering broken: %+v", got)
	}
}

// TestClampThresholds_PreservesTier1Ordering pins the Tier1
// pass/flag ordering invariant that mirrors the DB-side CHECK in
// migrations/0013_score_engine_tier1_thresholds.up.sql. Without the
// application-side clamp, a future iteration of the tuning agent's
// Decide() that adjusted Tier1 thresholds independently could write
// an inverted pair (PassBelow >= FlagAbove), which the column-scoped
// UpdateThresholds UPDATE would reject at the DB layer with a CHECK
// constraint violation. The clamp lets the agent surface a clamped
// pair instead of a hard write failure.
func TestClampThresholds_PreservesTier1Ordering(t *testing.T) {
	cases := []struct {
		name             string
		in               Thresholds
		wantPassLessThan int // PassBelow must be strictly less than this value
		wantFlagMin      int // FlagAbove must be >= this value
		wantPassNonNeg   bool
		wantFlagInRange  bool
	}{
		{
			name: "equal pair shifts pass-below down",
			in: Thresholds{
				Tier1PassBelow: 50,
				Tier1FlagAbove: 50,
				BannerBlocked:  85, BannerHighRisk: 70, BannerWarning: 50, BannerCaution: 30, BannerInfo: 15,
			},
			wantPassLessThan: 50,
			wantFlagMin:      50,
			wantPassNonNeg:   true,
			wantFlagInRange:  true,
		},
		{
			name: "inverted pair (pass above flag) recovers ordering",
			in: Thresholds{
				Tier1PassBelow: 80,
				Tier1FlagAbove: 30,
				BannerBlocked:  85, BannerHighRisk: 70, BannerWarning: 50, BannerCaution: 30, BannerInfo: 15,
			},
			wantPassLessThan: 30,
			wantFlagMin:      30,
			wantPassNonNeg:   true,
			wantFlagInRange:  true,
		},
		{
			name: "both at zero floor — promote flag to keep ordering valid",
			in: Thresholds{
				Tier1PassBelow: 0,
				Tier1FlagAbove: 0,
				BannerBlocked:  85, BannerHighRisk: 70, BannerWarning: 50, BannerCaution: 30, BannerInfo: 15,
			},
			wantPassLessThan: 1,
			wantFlagMin:      1,
			wantPassNonNeg:   true,
			wantFlagInRange:  true,
		},
		{
			name: "valid pair untouched",
			in: Thresholds{
				Tier1PassBelow: 20,
				Tier1FlagAbove: 60,
				BannerBlocked:  85, BannerHighRisk: 70, BannerWarning: 50, BannerCaution: 30, BannerInfo: 15,
			},
			wantPassLessThan: 60,
			wantFlagMin:      60,
			wantPassNonNeg:   true,
			wantFlagInRange:  true,
		},
		{
			name: "out-of-range values clamped first then re-ordered",
			in: Thresholds{
				Tier1PassBelow: 150,
				Tier1FlagAbove: -10,
				BannerBlocked:  85, BannerHighRisk: 70, BannerWarning: 50, BannerCaution: 30, BannerInfo: 15,
			},
			// clamp sets PassBelow=100, FlagAbove=0, then the ordering pass shifts both
			// to (0, 1) since 100-1 < 0 would underflow the second guard.
			wantPassLessThan: 1,
			wantFlagMin:      1,
			wantPassNonNeg:   true,
			wantFlagInRange:  true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := clampThresholds(tc.in)
			if got.Tier1PassBelow >= got.Tier1FlagAbove {
				t.Fatalf("Tier1 ordering broken after clamp: PassBelow=%d FlagAbove=%d (must satisfy DB CHECK pass_below < flag_above)",
					got.Tier1PassBelow, got.Tier1FlagAbove)
			}
			if got.Tier1PassBelow >= tc.wantPassLessThan {
				t.Errorf("Tier1PassBelow=%d not strictly less than %d", got.Tier1PassBelow, tc.wantPassLessThan)
			}
			if got.Tier1FlagAbove < tc.wantFlagMin {
				t.Errorf("Tier1FlagAbove=%d below minimum %d", got.Tier1FlagAbove, tc.wantFlagMin)
			}
			if tc.wantPassNonNeg && got.Tier1PassBelow < 0 {
				t.Errorf("Tier1PassBelow=%d must be >= 0 (DB column is INT NOT NULL CHECK >= 0)", got.Tier1PassBelow)
			}
			if tc.wantFlagInRange && (got.Tier1FlagAbove < 0 || got.Tier1FlagAbove > 100) {
				t.Errorf("Tier1FlagAbove=%d outside [0,100]", got.Tier1FlagAbove)
			}
		})
	}
}

func TestClampWeights_NormalisesAndClips(t *testing.T) {
	got := clampWeights(ScoreWeights{AI: 1.4, Rspamd: -0.2, Attachments: 0.5, Links: 0.5})
	sum := got.AI + got.Rspamd + got.Attachments + got.Links
	if got.Rspamd != 0 {
		t.Fatalf("negative not clipped: %+v", got)
	}
	if sum < 0.999 || sum > 1.001 {
		t.Fatalf("weights not renormalised: %+v sum=%v", got, sum)
	}
}

func TestSummariseNotes(t *testing.T) {
	if got := summariseNotes(nil); got != "" {
		t.Fatalf("empty notes: %q", got)
	}
	if got := summariseNotes([]string{"a"}); got != "a" {
		t.Fatalf("one note: %q", got)
	}
	if got := summariseNotes([]string{"a", "b", "c"}); got != "a; b; c" {
		t.Fatalf("multi: %q", got)
	}
}

func TestMinInt(t *testing.T) {
	if minInt(2, 5) != 2 {
		t.Fatal("a<b")
	}
	if minInt(7, 5) != 5 {
		t.Fatal("a>b")
	}
}
