package corpus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
)

// PipelineClients carries the production evaluator wiring the harness
// needs. The harness deliberately accepts the clients as injected
// values rather than constructing them internally: the WS-4b spec
// requires the harness to drive the EXACT production evaluator, but
// the production wiring (encoder URL, KMS keys, Tier 2 model path,
// circuit-breaker config) is process-level state managed by
// cmd/sn360-es. Threading the clients through lets us reuse them
// from cmd/corpus-eval/main.go without copying the wiring code.
//
// Any of Tier1 / Tier2 / Rspamd may be nil: the evaluator handles
// nil clients gracefully by marking the corresponding stage as
// "degraded" in the result. The harness reports both the count of
// degraded fixtures and which stages were skipped so consumers
// don't read full-pipeline metrics off a degraded run.
type PipelineClients struct {
	Tier0       evaluate.Tier0Gate
	Tier1       evaluate.Tier1Client
	Tier2       evaluate.Tier2Client
	Rspamd      evaluate.RspamdClient
	Categorizer evaluate.Categorizer
	TierDecider evaluate.TierDecider
	Weights     evaluate.Weights
	// ScoringLoader optionally provides per-tenant scoring overrides.
	// Nil falls back to Weights + the threshold defaults.
	ScoringLoader evaluate.TenantScoringConfigLoader
	// Logger, when non-nil, is forwarded to the evaluator. Nil
	// falls back to slog.Default().
	Logger *slog.Logger
}

// Validate ensures the harness has at minimum a Tier 0 gate (required
// by the evaluator) and a Categorizer + TierDecider (without which
// the orchestrator cannot produce a verdict). Tier 1 / Tier 2 /
// Rspamd are optional — they degrade gracefully.
func (p PipelineClients) Validate() error {
	if p.Tier0 == nil {
		return errors.New("corpus eval: Tier0 gate is required")
	}
	if p.Categorizer == nil {
		return errors.New("corpus eval: Categorizer is required")
	}
	if p.TierDecider == nil {
		return errors.New("corpus eval: TierDecider is required")
	}
	return nil
}

// EvalOptions controls per-run knobs.
type EvalOptions struct {
	// CorpusVersion is round-tripped into Report.CorpusVersion. The
	// synthetic generator populates it with "synthetic-seed=N-size=M";
	// custom corpora can use whatever string identifies them.
	CorpusVersion string
	// EvaluatorVersion is round-tripped into Report.EvaluatorVersion
	// (typically git rev-parse HEAD).
	EvaluatorVersion string
	// Path is round-tripped into Report.CorpusPath.
	Path string
	// PerFixtureTimeout caps a single evaluator call. Zero falls
	// back to 30 s — enough headroom for Tier 2 SLM inference but
	// short enough that a hung downstream doesn't wedge the
	// harness.
	PerFixtureTimeout time.Duration
	// TenantID, when non-empty, overrides the harness's synthetic
	// tenant id on every fixture.
	TenantID string
	// Now returns the current time. Tests override it for
	// reproducible Report.EvaluatedAt values.
	Now func() time.Time
}

// Evaluate runs the full Tier 0 → Tier 1 → Tier 2 cascade against
// every fixture and returns the structured Report.
//
// The function is allocation-friendly but not parallel: the
// evaluator itself fans out per-stage goroutines internally, so
// running multiple fixtures concurrently risks bursting the encoder
// service. Per-fixture latency dominates corpus latency anyway
// (Tier 2 SLM ~ hundreds of ms), so the sequential loop is the
// pragmatic choice.
func Evaluate(ctx context.Context, clients PipelineClients, fixtures []Fixture, opts EvalOptions) (Report, error) {
	if err := clients.Validate(); err != nil {
		return Report{}, err
	}
	if len(fixtures) == 0 {
		return Report{}, errors.New("corpus eval: empty fixture set")
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.PerFixtureTimeout == 0 {
		opts.PerFixtureTimeout = 30 * time.Second
	}

	cfg := evaluate.Config{
		Tier0:        clients.Tier0,
		Tier1:        clients.Tier1,
		Tier2:        clients.Tier2,
		Rspamd:       clients.Rspamd,
		Categorizer:  clients.Categorizer,
		TierDecider:  clients.TierDecider,
		Weights:      clients.Weights,
		TenantConfig: clients.ScoringLoader,
		Logger:       clients.Logger,
	}
	if cfg.Weights.Total() == 0 {
		cfg.Weights = evaluate.DefaultWeights()
	}
	evaluator := evaluate.NewEvaluator(cfg)

	report := Report{
		CorpusVersion: opts.CorpusVersion,
		CorpusPath:    opts.Path,
		EvaluatedAt:   opts.Now(),
		TotalFixtures: 0,
		PerLabel: map[Label]LabelMetrics{
			LabelPhish:  {},
			LabelSpam:   {},
			LabelBenign: {},
			LabelBEC:    {},
		},
		PerTier:          map[constant.Tier]TierMetrics{},
		Confusion:        newConfusion(),
		DegradedReasons:  map[string]int{},
		EvaluatorVersion: opts.EvaluatorVersion,
		TierCoverage: TierCoverage{
			Tier0Configured:  clients.Tier0 != nil,
			Tier1Configured:  clients.Tier1 != nil,
			Tier2Configured:  clients.Tier2 != nil,
			RspamdConfigured: clients.Rspamd != nil,
		},
	}
	// Pre-populate PerTier so every known tier has a row in the
	// report even when zero fixtures landed there. This keeps the
	// baseline-vs-current diff stable across runs.
	for _, t := range constant.AllTiers {
		report.PerTier[t] = TierMetrics{Tier: t}
	}

	syntheticCount := 0
	for _, fx := range fixtures {
		fxCtx, cancel := context.WithTimeout(ctx, opts.PerFixtureTimeout)
		req, err := BuildRequest(fxCtx, fx, BuildOpts{TenantID: opts.TenantID})
		if err != nil {
			cancel()
			return Report{}, fmt.Errorf("build request for %s: %w", fx.ID, err)
		}
		res, err := evaluator.Evaluate(fxCtx, req, req.Signals)
		cancel()
		if err != nil {
			return Report{}, fmt.Errorf("evaluate %s: %w", fx.ID, err)
		}

		report.TotalFixtures++
		if fx.Metadata["source"] != "" && isSyntheticSource(fx.Metadata["source"]) {
			syntheticCount++
		}

		// Tier coverage: a tier "executed" iff the evaluator
		// produced an outcome for it (nil outcome means it was
		// skipped by Tier 0 or unavailable).
		if res.Tier0 != nil {
			report.TierCoverage.Tier0Executed = true
		}
		if res.Tier1 != nil {
			report.TierCoverage.Tier1Executed = true
		}
		if res.Tier2 != nil {
			report.TierCoverage.Tier2Executed = true
		}
		if res.Rspamd != nil {
			report.TierCoverage.RspamdExecuted = true
		}
		if res.Degraded {
			report.DegradedFixtures++
			for _, svc := range res.DegradedServices {
				report.DegradedReasons[svc]++
			}
		}

		predicted := LabelFromResult(res)
		expectedTier := fx.ExpectedTier
		if expectedTier == "" {
			expectedTier = fx.Label.ExpectedTier()
		}

		// Update confusion matrix + per-label TP/FP/FN.
		report.Confusion[fx.Label][predicted]++
		recordLabel(report.PerLabel, fx.Label, predicted)

		// Per-tier accuracy is keyed on EXPECTED tier so the row
		// labels stay aligned with the corpus's curator-intended
		// dispositions; "correct" means the predicted tier
		// matched the expected.
		if expectedTier != "" {
			pt := report.PerTier[expectedTier]
			pt.Tier = expectedTier
			pt.Total++
			if res.Tier == expectedTier {
				pt.Correct++
			}
			report.PerTier[expectedTier] = pt
		}

		if predicted != fx.Label {
			report.Misclassifications = append(report.Misclassifications, MisclassifiedFixture{
				ID:              fx.ID,
				Label:           fx.Label,
				PredictedLabel:  predicted,
				ExpectedTier:    expectedTier,
				PredictedTier:   res.Tier,
				ExpectedPrimary: fx.ExpectedPrimary,
				PredictedPrim:   res.Primary,
				Score:           res.Score,
				ReasonCodes:     append([]string(nil), res.ReasonCodes...),
				Degraded:        res.Degraded,
				Metadata:        fx.Metadata,
			})
		}
	}

	if syntheticCount == report.TotalFixtures && report.TotalFixtures > 0 {
		report.SyntheticOnly = true
	}

	// Compute precision / recall / F1 from the populated TP / FP / FN
	// counters. Empty support → zero metrics (rather than NaN) so the
	// JSON shape is diffable.
	correct := 0
	macroSum := 0.0
	macroCount := 0
	for label, m := range report.PerLabel {
		if m.TP+m.FP > 0 {
			m.Precision = float64(m.TP) / float64(m.TP+m.FP)
		}
		if m.TP+m.FN > 0 {
			m.Recall = float64(m.TP) / float64(m.TP+m.FN)
		}
		if m.Precision+m.Recall > 0 {
			m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
		}
		m.Support = m.TP + m.FN
		correct += m.TP
		report.PerLabel[label] = m
		if m.Support > 0 {
			macroSum += m.F1
			macroCount++
		}
	}
	if report.TotalFixtures > 0 {
		report.AggregateAccuracy = float64(correct) / float64(report.TotalFixtures)
	}
	if macroCount > 0 {
		report.MacroF1 = macroSum / float64(macroCount)
	}
	for t, pt := range report.PerTier {
		if pt.Total > 0 {
			pt.Accuracy = float64(pt.Correct) / float64(pt.Total)
		}
		report.PerTier[t] = pt
	}

	// Stable sort of misclassifications + gaps so the JSON is
	// byte-deterministic across runs against the same corpus.
	sort.SliceStable(report.Misclassifications, func(i, j int) bool {
		return report.Misclassifications[i].ID < report.Misclassifications[j].ID
	})

	return report, nil
}

// LabelFromResult maps an EvaluateResult back into one of the four
// canonical labels. The mapping is intentionally chosen so that the
// label-derived predictions correspond to the tiers in
// Label.ExpectedTier — i.e. a result that produced TierHighRisk with
// primary BECImpersonation is labelled "bec" rather than "phish".
//
// The order matters: BEC is checked before Phish because the
// CategoryAccountTakeoverSuspected / CategoryInvoiceFraud overlap
// could otherwise pull a BEC-style result into the phish bucket.
func LabelFromResult(r dto.EvaluateResult) Label {
	switch r.Primary {
	case constant.CategoryBECImpersonation,
		constant.CategoryInvoiceFraud,
		constant.CategoryVendorCompromise,
		constant.CategoryAccountTakeoverSuspected:
		return LabelBEC
	case constant.CategoryLikelyPhishing,
		constant.CategoryLookalikeDomain,
		constant.CategorySuspiciousURL,
		constant.CategorySuspiciousAttachment,
		constant.CategoryCredentialHarvesting,
		constant.CategoryQRPhishing,
		constant.CategoryAuthFailed:
		return LabelPhish
	case constant.CategoryInternalTrusted,
		constant.CategoryVendorTrusted,
		constant.CategoryNewsletter,
		constant.CategoryFirstContactExternal:
		return LabelBenign
	case constant.CategoryScamFraud:
		return LabelSpam
	}
	// Fall back to tier-based labelling when the primary category
	// didn't survive (e.g. Tier 0 didn't fire and the categorizer
	// returned Newsletter as a safe default for unsigned mail).
	switch r.Tier {
	case constant.TierBlocked, constant.TierHighRisk:
		return LabelPhish
	case constant.TierWarning:
		return LabelPhish
	case constant.TierCaution:
		return LabelSpam
	case constant.TierInformational, constant.TierTrusted:
		return LabelBenign
	}
	return LabelSpam
}

func recordLabel(perLabel map[Label]LabelMetrics, truth, predicted Label) {
	if truth == predicted {
		m := perLabel[truth]
		m.TP++
		perLabel[truth] = m
		return
	}
	// Predicted got it wrong: bump FP for the predicted label and
	// FN for the ground truth.
	mp := perLabel[predicted]
	mp.FP++
	perLabel[predicted] = mp
	mt := perLabel[truth]
	mt.FN++
	perLabel[truth] = mt
}

func newConfusion() map[Label]map[Label]int {
	c := map[Label]map[Label]int{}
	for _, l := range AllLabels {
		c[l] = map[Label]int{}
		for _, k := range AllLabels {
			c[l][k] = 0
		}
	}
	return c
}

func isSyntheticSource(src string) bool {
	// The synthetic generator embeds the version tag in metadata.source
	// (e.g. "ws4b-synthetic-v1"). Anything matching that prefix counts
	// as synthetic; everything else is treated as real corpus data.
	const prefix = "ws4b-synthetic-"
	if len(src) < len(prefix) {
		return false
	}
	return src[:len(prefix)] == prefix
}
