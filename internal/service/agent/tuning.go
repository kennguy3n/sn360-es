package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"
)

// TuningConfig wires the tuning agent's dependencies.
type TuningConfig struct {
	Results ResultRepository
	Config  ConfigStore
	Audit   AuditLog

	// Window is how far back the agent looks for feedback (default 7d).
	Window time.Duration
	// MinSampleSize is the minimum feedback events required before
	// the agent makes any change (default 25). Below this we keep the
	// current config to avoid overfitting to small samples.
	MinSampleSize int
	// MaxWeightShiftPerRun caps the per-run delta to any single weight
	// so feedback noise can't whipsaw the score engine (default 0.05).
	MaxWeightShiftPerRun float64
	// MaxThresholdShiftPerRun caps the per-run delta to any single
	// banner threshold (default 5 points).
	MaxThresholdShiftPerRun int
	// FPRateTarget / FNRateTarget are the rates we aim for; the
	// distance between observed and target determines the delta sign
	// and magnitude (defaults: FP 0.05, FN 0.02).
	FPRateTarget float64
	FNRateTarget float64

	Logger *slog.Logger
}

// TuningAgent runs on a schedule and adjusts per-tenant weights +
// thresholds based on user feedback.
type TuningAgent struct {
	cfg TuningConfig
	log *slog.Logger
}

// NewTuningAgent constructs a TuningAgent. Results + Config are required.
func NewTuningAgent(cfg TuningConfig) (*TuningAgent, error) {
	if cfg.Results == nil {
		return nil, errors.New("agent: tuning requires Results")
	}
	if cfg.Config == nil {
		return nil, errors.New("agent: tuning requires Config")
	}
	if cfg.Window <= 0 {
		cfg.Window = 7 * 24 * time.Hour
	}
	if cfg.MinSampleSize <= 0 {
		cfg.MinSampleSize = 25
	}
	if cfg.MaxWeightShiftPerRun <= 0 {
		cfg.MaxWeightShiftPerRun = 0.05
	}
	if cfg.MaxThresholdShiftPerRun <= 0 {
		cfg.MaxThresholdShiftPerRun = 5
	}
	if cfg.FPRateTarget <= 0 {
		cfg.FPRateTarget = 0.05
	}
	if cfg.FNRateTarget <= 0 {
		cfg.FNRateTarget = 0.02
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &TuningAgent{cfg: cfg, log: cfg.Logger}, nil
}

// Name implements Agent.
func (a *TuningAgent) Name() string { return "tuning" }

// Tune runs a single tuning pass for tenantID. It returns a TuningDecision
// that summarises the action taken (may be a no-op).
func (a *TuningAgent) Tune(ctx context.Context, tenantID string) (TuningDecision, error) {
	if tenantID == "" {
		return TuningDecision{}, errors.New("agent: tuning tenantID required")
	}
	log := a.log.With(slog.String("tenant_id", tenantID))
	now := time.Now().UTC()
	windowStart := now.Add(-a.cfg.Window)

	feedback, err := a.cfg.Results.RecentFeedback(ctx, tenantID, windowStart)
	if err != nil {
		return TuningDecision{}, fmt.Errorf("tuning: recent feedback: %w", err)
	}

	weights, err := a.cfg.Results.CurrentWeights(ctx, tenantID)
	if err != nil {
		return TuningDecision{}, fmt.Errorf("tuning: current weights: %w", err)
	}
	thresholds, err := a.cfg.Results.CurrentThresholds(ctx, tenantID)
	if err != nil {
		return TuningDecision{}, fmt.Errorf("tuning: current thresholds: %w", err)
	}

	snap := TuningSnapshot{
		TenantID:          tenantID,
		WindowStart:       windowStart,
		WindowEnd:         now,
		TotalEvaluations:  len(feedback),
		CurrentWeights:    weights,
		CurrentThresholds: thresholds,
	}
	for _, f := range feedback {
		switch f.Action {
		case FeedbackMarkSafe, FeedbackTrustSender:
			snap.FalsePositives++
		case FeedbackReportPhishing:
			snap.FalseNegatives++
		}
	}

	decision := a.Decide(snap)
	decision.TenantID = tenantID
	decision.DecidedAt = now

	if decision.NewWeights != nil {
		if err := a.cfg.Config.UpdateWeights(ctx, tenantID, *decision.NewWeights); err != nil {
			return decision, fmt.Errorf("tuning: persist weights: %w", err)
		}
	}
	if decision.NewThresholds != nil {
		if err := a.cfg.Config.UpdateThresholds(ctx, tenantID, *decision.NewThresholds); err != nil {
			return decision, fmt.Errorf("tuning: persist thresholds: %w", err)
		}
	}
	if a.cfg.Audit != nil {
		_ = a.cfg.Audit.Record(ctx, AuditEntry{
			Agent:      a.Name(),
			TenantID:   tenantID,
			Action:     "tuning.decision",
			Reason:     summariseNotes(decision.Notes),
			OccurredAt: now,
			Detail: map[string]any{
				"total":        snap.TotalEvaluations,
				"fp":           snap.FalsePositives,
				"fn":           snap.FalseNegatives,
				"new_weights":  decision.NewWeights,
				"new_thresholds": decision.NewThresholds,
			},
		})
	}
	log.Info("agent.tuning: decision",
		slog.Int("total", snap.TotalEvaluations),
		slog.Int("fp", snap.FalsePositives),
		slog.Int("fn", snap.FalseNegatives),
		slog.Any("notes", decision.Notes))
	return decision, nil
}

// Decide is the pure-function tuning policy, exposed so tests can pin
// every transition. It NEVER mutates the snapshot. Rules:
//
//   - If TotalEvaluations < MinSampleSize → no-op.
//   - If FP rate > target by ≥1pp → lower banner sensitivity (raise
//     BannerWarning / BannerCaution / BannerInfo).
//   - If FN rate > target by ≥0.5pp → raise banner sensitivity (lower
//     BannerWarning / BannerCaution).
//   - If FP > FN and FP rate > target → shift weight from AI → Rspamd
//     (AI was over-confident); else if FN > FP and FN rate > target →
//     shift from Rspamd → AI.
//   - All deltas are capped by Max{Weight,Threshold}ShiftPerRun.
func (a *TuningAgent) Decide(snap TuningSnapshot) TuningDecision {
	dec := TuningDecision{}
	if snap.TotalEvaluations < a.cfg.MinSampleSize {
		dec.Notes = append(dec.Notes, fmt.Sprintf("samples=%d below floor=%d", snap.TotalEvaluations, a.cfg.MinSampleSize))
		return dec
	}
	total := float64(snap.TotalEvaluations)
	fpRate := float64(snap.FalsePositives) / total
	fnRate := float64(snap.FalseNegatives) / total

	weights := snap.CurrentWeights
	thresholds := snap.CurrentThresholds
	weightsChanged := false
	thresholdsChanged := false

	// Weight shift: favour Rspamd when AI is producing too many FPs and
	// favour AI when Rspamd is missing things.
	if fpRate > a.cfg.FPRateTarget && snap.FalsePositives > snap.FalseNegatives {
		delta := math.Min(a.cfg.MaxWeightShiftPerRun, fpRate-a.cfg.FPRateTarget)
		weights.AI -= delta
		weights.Rspamd += delta
		dec.Notes = append(dec.Notes, fmt.Sprintf("fp_rate=%.3f > target=%.3f → AI−=%.3f Rspamd+=%.3f", fpRate, a.cfg.FPRateTarget, delta, delta))
		weightsChanged = true
	}
	if fnRate > a.cfg.FNRateTarget && snap.FalseNegatives > snap.FalsePositives {
		delta := math.Min(a.cfg.MaxWeightShiftPerRun, fnRate-a.cfg.FNRateTarget)
		weights.Rspamd -= delta
		weights.AI += delta
		dec.Notes = append(dec.Notes, fmt.Sprintf("fn_rate=%.3f > target=%.3f → Rspamd−=%.3f AI+=%.3f", fnRate, a.cfg.FNRateTarget, delta, delta))
		weightsChanged = true
	}
	weights = clampWeights(weights)

	// Threshold shift: raise to suppress noise, lower to catch more.
	if fpRate > a.cfg.FPRateTarget+0.01 {
		delta := minInt(a.cfg.MaxThresholdShiftPerRun, int(math.Ceil((fpRate-a.cfg.FPRateTarget)*100)))
		thresholds.BannerWarning += delta
		thresholds.BannerCaution += delta
		thresholds.BannerInfo += delta
		dec.Notes = append(dec.Notes, fmt.Sprintf("fp_rate high → banner thresholds +%d", delta))
		thresholdsChanged = true
	}
	if fnRate > a.cfg.FNRateTarget+0.005 {
		delta := minInt(a.cfg.MaxThresholdShiftPerRun, int(math.Ceil((fnRate-a.cfg.FNRateTarget)*200)))
		thresholds.BannerWarning -= delta
		thresholds.BannerCaution -= delta
		dec.Notes = append(dec.Notes, fmt.Sprintf("fn_rate high → banner thresholds −%d", delta))
		thresholdsChanged = true
	}
	thresholds = clampThresholds(thresholds)

	if weightsChanged {
		dec.NewWeights = &weights
	}
	if thresholdsChanged {
		dec.NewThresholds = &thresholds
	}
	if !weightsChanged && !thresholdsChanged {
		dec.Notes = append(dec.Notes, "within target band; no change")
	}
	return dec
}

func clampWeights(w ScoreWeights) ScoreWeights {
	clamp := func(v float64) float64 {
		if v < 0 {
			return 0
		}
		if v > 1 {
			return 1
		}
		return v
	}
	w.AI = clamp(w.AI)
	w.Rspamd = clamp(w.Rspamd)
	w.Attachments = clamp(w.Attachments)
	w.Links = clamp(w.Links)
	// Renormalise so AI + Rspamd + Attachments + Links == 1 ± epsilon.
	sum := w.AI + w.Rspamd + w.Attachments + w.Links
	if sum > 0 {
		w.AI /= sum
		w.Rspamd /= sum
		w.Attachments /= sum
		w.Links /= sum
	}
	return w
}

func clampThresholds(t Thresholds) Thresholds {
	clamp := func(v, lo, hi int) int {
		if v < lo {
			return lo
		}
		if v > hi {
			return hi
		}
		return v
	}
	t.Tier1PassBelow = clamp(t.Tier1PassBelow, 0, 100)
	t.Tier1FlagAbove = clamp(t.Tier1FlagAbove, 0, 100)
	t.BannerBlocked = clamp(t.BannerBlocked, 50, 100)
	t.BannerHighRisk = clamp(t.BannerHighRisk, 40, 99)
	t.BannerWarning = clamp(t.BannerWarning, 20, 90)
	t.BannerCaution = clamp(t.BannerCaution, 10, 80)
	t.BannerInfo = clamp(t.BannerInfo, 0, 60)
	// Preserve ordering: Blocked > HighRisk > Warning > Caution > Info.
	if t.BannerHighRisk >= t.BannerBlocked {
		t.BannerHighRisk = t.BannerBlocked - 1
	}
	if t.BannerWarning >= t.BannerHighRisk {
		t.BannerWarning = t.BannerHighRisk - 1
	}
	if t.BannerCaution >= t.BannerWarning {
		t.BannerCaution = t.BannerWarning - 1
	}
	if t.BannerInfo >= t.BannerCaution {
		t.BannerInfo = t.BannerCaution - 1
	}
	return t
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func summariseNotes(notes []string) string {
	if len(notes) == 0 {
		return ""
	}
	out := notes[0]
	for _, n := range notes[1:] {
		out += "; " + n
	}
	return out
}
