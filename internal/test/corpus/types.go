// Package corpus implements the WS-4b real-world corpus harness — a
// repeatable end-to-end regression test that drives the production
// Tier 0 / Tier 1 / Tier 2 evaluator against a held-out corpus of
// labelled emails and reports precision / recall / F1 per label, per
// tier, and aggregate.
//
// The package is intentionally corpus-agnostic: the harness loads any
// JSONL stream whose entries match the Fixture shape (one JSON object
// per line). The repository ships a deterministic synthetic corpus
// under testdata/corpus-eval/synthetic.jsonl that exercises the four
// canonical labels (phish, spam, benign, BEC) — the synthetic data is
// a scaffold for the harness, NOT a substitute for a real-world
// labelled corpus.
//
// Layering:
//
//   - types.go (this file): wire-format types + label vocabulary
//   - loader.go: JSONL parser + RFC822 → dto.EvaluateRequest mapping
//   - synthetic.go: deterministic synthetic fixture generator
//   - report.go: confusion matrix + per-label / per-tier metrics
//   - eval.go: production-evaluator wiring + per-fixture eval loop
//
// The harness binary lives at cmd/corpus-eval/main.go; the adversarial
// fuzz suite lives in the sibling internal/test/adversarial package.
package corpus

import (
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// Label is the ground-truth label assigned to a fixture by the corpus
// curator. The vocabulary is deliberately narrow — four buckets that
// map cleanly onto SN360-ES tiers — because precision/recall on a
// hundred-fixture corpus is noisy enough already; finer-grained
// categories would dilute the per-bucket sample to the point of
// meaninglessness.
type Label string

const (
	// LabelPhish covers credential-harvest, lookalike-domain,
	// suspicious-URL, QR-code phishing, and general "click-to-give-
	// up-credentials" attacks. Expected tier: HighRisk or Warning.
	LabelPhish Label = "phish"
	// LabelSpam covers unsolicited bulk mail, promotional spam, and
	// low-effort scams that lack BEC's targeted social engineering.
	// Expected tier: Caution or Warning.
	LabelSpam Label = "spam"
	// LabelBenign covers legitimate business mail, newsletters from
	// known senders, and internal traffic. Expected tier: Trusted
	// or Informational.
	LabelBenign Label = "benign"
	// LabelBEC (Business Email Compromise) covers wire-fraud,
	// invoice-fraud, CEO impersonation, and vendor-compromise
	// attacks — targeted social engineering with no payload.
	// Expected tier: HighRisk or Blocked.
	LabelBEC Label = "bec"
)

// AllLabels lists every label in a fixed order used by every report,
// so confusion matrices and per-label tables are deterministic.
var AllLabels = []Label{LabelPhish, LabelSpam, LabelBenign, LabelBEC}

// Valid reports whether l is one of the known labels.
func (l Label) Valid() bool {
	for _, k := range AllLabels {
		if k == l {
			return true
		}
	}
	return false
}

// ExpectedTier returns the disposition tier the production pipeline
// is expected to produce for a fixture with this label. It is the
// reference value used when the fixture file does NOT pin an explicit
// expected_tier — the harness consults the fixture-level pin first
// and only falls back to this default when absent.
//
// The mapping reflects the SN360-ES tier vocabulary (constant.Tier)
// and intentionally chooses the more lenient option for each bucket
// (Warning rather than HighRisk for phish, Caution rather than
// Warning for spam) so the synthetic corpus doesn't generate false
// regressions when the scoring weights drift within their tuning
// envelope.
func (l Label) ExpectedTier() constant.Tier {
	switch l {
	case LabelPhish, LabelBEC:
		return constant.TierHighRisk
	case LabelSpam:
		return constant.TierCaution
	case LabelBenign:
		return constant.TierTrusted
	default:
		return ""
	}
}

// Fixture is a single labelled email in the corpus JSONL stream.
//
// The wire format is one JSON object per line:
//
//	{
//	  "id": "fixture-001",
//	  "label": "phish",
//	  "rfc822": "<base64-encoded RFC822 message>",
//	  "expected_tier": "HighRisk",   // optional; falls back to Label.ExpectedTier()
//	  "expected_primary": "LIKELY_PHISHING", // optional; soft check, never gates regression
//	  "metadata": {"source": "ws4b-synthetic-v1", "attack_type": "credential-harvest"}
//	}
//
// `rfc822` is base64 (StdEncoding) rather than raw text because JSONL
// rows are line-delimited — a raw RFC822 message contains CRLF, which
// would break the one-record-per-line invariant.
type Fixture struct {
	// ID is the stable identifier for the fixture (e.g.
	// "fixture-001"). The harness uses it to name misclassifications
	// in the report so the curator can look up the exact email body
	// that drove the failure.
	ID string `json:"id"`
	// Label is the ground-truth bucket the curator assigned. Required.
	Label Label `json:"label"`
	// RFC822 is the base64-encoded RFC822 message bytes. Required.
	// The harness decodes it and feeds it into the evaluator via
	// the same RFC822→EvaluateRequest mapping the ingestion
	// service uses in production.
	RFC822 string `json:"rfc822"`
	// ExpectedTier optionally pins the disposition tier this
	// fixture should produce. When empty the harness falls back to
	// Label.ExpectedTier(). The pin overrides the label-derived
	// default so a phish fixture that is intentionally hard-to-
	// detect can be marked as expected-Caution instead of
	// expected-HighRisk.
	ExpectedTier constant.Tier `json:"expected_tier,omitempty"`
	// ExpectedPrimary optionally pins the primary category. This
	// is a soft check — the harness reports primary-category
	// mismatches in the misclassifications list but never gates a
	// regression on them, because primary categories are inherently
	// noisier than the bucketed label.
	ExpectedPrimary constant.Category `json:"expected_primary,omitempty"`
	// Metadata is opaque to the harness; it is round-tripped into
	// the report so curators can correlate fixtures with their
	// upstream provenance (test source, attack family, CVE, etc.).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Validate reports whether the fixture has the minimum fields required
// for evaluation. It is run by the loader on each line; a fixture that
// fails Validate causes the loader to return an error (no silent skip).
func (f Fixture) Validate() error {
	if f.ID == "" {
		return errMissing("id")
	}
	if !f.Label.Valid() {
		return errInvalidLabel(string(f.Label))
	}
	if f.RFC822 == "" {
		return errMissing("rfc822")
	}
	if f.ExpectedTier != "" && f.ExpectedTier.Severity() < 0 {
		return errInvalidTier(string(f.ExpectedTier))
	}
	return nil
}

// MisclassifiedFixture is the per-fixture record the harness emits
// for every fixture whose predicted label did not match the ground
// truth, or whose predicted tier deviated from the expected one. The
// curator uses these rows to (a) re-label fixtures whose ground truth
// is wrong and (b) drive the evaluator improvement backlog.
type MisclassifiedFixture struct {
	ID              string            `json:"id"`
	Label           Label             `json:"label"`
	PredictedLabel  Label             `json:"predicted_label"`
	ExpectedTier    constant.Tier     `json:"expected_tier"`
	PredictedTier   constant.Tier     `json:"predicted_tier"`
	ExpectedPrimary constant.Category `json:"expected_primary,omitempty"`
	PredictedPrim   constant.Category `json:"predicted_primary"`
	Score           int               `json:"score"`
	ReasonCodes     []string          `json:"reason_codes,omitempty"`
	Degraded        bool              `json:"degraded,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// LabelMetrics carries precision / recall / F1 / support for a single
// label. Support is the number of fixtures whose ground-truth label
// equals this label (i.e. the TP+FN sum).
type LabelMetrics struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Support   int     `json:"support"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// TierMetrics carries the per-tier accuracy figures (Predicted tier
// == Expected tier, on the subset of fixtures whose ground-truth tier
// is t).
type TierMetrics struct {
	Tier     constant.Tier `json:"tier"`
	Total    int           `json:"total"`
	Correct  int           `json:"correct"`
	Accuracy float64       `json:"accuracy"`
}

// PipelineGap is a finding the harness surfaces during evaluation —
// e.g. an adversarial perturbation type that the pipeline neither
// classifies correctly nor flags with a specific reason code. These
// gaps are reported in the JSON output so they show up as follow-up
// tickets rather than silent regressions.
type PipelineGap struct {
	Source       string `json:"source"`               // "corpus" or "adversarial"
	Kind         string `json:"kind"`                 // e.g. "missing_reason_code"
	Detail       string `json:"detail"`               // free-form description
	FixtureID    string `json:"fixture_id,omitempty"` // when sourced from a single fixture
	Perturbation string `json:"perturbation,omitempty"`
}

// Report is the structured JSON the harness writes to
// testdata/corpus-eval/reports/{timestamp}.json (gitignored).
//
// The baseline checked into testdata/corpus-eval/baseline.json is one
// of these reports, captured by the corpus curator from a known-good
// run. The CI job re-runs the harness, compares the new report to the
// baseline, and fails on per-label F1 regressions exceeding the
// configured tolerance.
type Report struct {
	// CorpusVersion identifies the source of the fixture set. For
	// the synthetic corpus it carries the generator seed and size
	// (e.g. "synthetic-seed=4242-size=200").
	CorpusVersion string `json:"corpus_version"`
	// CorpusPath is the JSONL file the harness was pointed at.
	CorpusPath string `json:"corpus_path"`
	// SyntheticOnly reports whether the corpus consists exclusively
	// of synthetic fixtures (every metadata entry carries
	// "source": "ws4b-synthetic-vN"). When true, every consumer of
	// the report — dashboards, PR descriptions, alerting — MUST
	// surface that the headline figures are synthetic and not
	// drawn from a real-world labelled corpus. The invariant from
	// the WS-4b spec: "No false confidence".
	SyntheticOnly bool `json:"synthetic_only"`
	// EvaluatorVersion is git SHA of the evaluator at the time of
	// the run, when available. The harness shells out to `git rev-
	// parse HEAD`; when unavailable (CI tarball, no git) the field
	// is left blank.
	EvaluatorVersion string `json:"evaluator_version,omitempty"`
	// EvaluatedAt is the run timestamp in UTC, RFC3339.
	EvaluatedAt time.Time `json:"evaluated_at"`
	// TotalFixtures is the count of fixtures successfully evaluated.
	TotalFixtures int `json:"total_fixtures"`
	// PerLabel is the precision/recall/F1 per ground-truth label.
	// Keyed by Label so the JSON shape is stable for diffing.
	PerLabel map[Label]LabelMetrics `json:"per_label"`
	// PerTier is the per-tier accuracy. Keyed by constant.Tier.
	PerTier map[constant.Tier]TierMetrics `json:"per_tier"`
	// AggregateAccuracy is the count of correctly-labelled fixtures
	// divided by TotalFixtures.
	AggregateAccuracy float64 `json:"aggregate_accuracy"`
	// MacroF1 is the unweighted mean of PerLabel F1 scores.
	MacroF1 float64 `json:"macro_f1"`
	// Confusion is the confusion matrix: rows are ground-truth
	// labels, columns are predicted labels. Confusion[truth][pred]
	// is the count of fixtures whose true label was `truth` and
	// whose predicted label was `pred`.
	Confusion map[Label]map[Label]int `json:"confusion"`
	// Misclassifications lists every fixture whose predicted label
	// did not match the ground truth. Sorted by ID for determinism.
	Misclassifications []MisclassifiedFixture `json:"misclassifications,omitempty"`
	// Gaps lists pipeline gaps surfaced during evaluation. See
	// PipelineGap. Sorted by (Kind, FixtureID).
	Gaps []PipelineGap `json:"gaps,omitempty"`
	// DegradedFixtures counts fixtures whose evaluator output set
	// res.Degraded = true (e.g. Tier 1 unreachable). The harness
	// uses this to surface "this run was Tier 0 only" in the report
	// rather than silently reporting reduced-pipeline metrics as
	// headline.
	DegradedFixtures int `json:"degraded_fixtures"`
	// DegradedReasons aggregates res.DegradedServices across the
	// corpus so the report shows "tier1: 200, tier2: 200" when the
	// encoder + SLM were both unavailable for the full run.
	DegradedReasons map[string]int `json:"degraded_reasons,omitempty"`
	// TierCoverage records which of Tier 1 / Tier 2 actually ran on
	// at least one fixture. This is the explicit "synthetic 98% F1
	// is from Tier 0 only" signal the WS-4b spec calls out as a
	// no-false-confidence invariant: when both Tier 1 and Tier 2
	// are skipped, the report MUST make that obvious before any
	// headline number is consumed.
	TierCoverage TierCoverage `json:"tier_coverage"`
}

// TierCoverage reports which tiers actually executed during the run.
// "Configured" means the harness was given a client for that tier;
// "Executed" means at least one fixture's evaluation invoked it
// without erroring. Both being true is the only configuration that
// justifies treating the headline metrics as "full-pipeline".
type TierCoverage struct {
	Tier0Configured  bool `json:"tier0_configured"`
	Tier0Executed    bool `json:"tier0_executed"`
	Tier1Configured  bool `json:"tier1_configured"`
	Tier1Executed    bool `json:"tier1_executed"`
	Tier2Configured  bool `json:"tier2_configured"`
	Tier2Executed    bool `json:"tier2_executed"`
	RspamdConfigured bool `json:"rspamd_configured"`
	RspamdExecuted   bool `json:"rspamd_executed"`
}

// FullPipeline reports whether the run exercised the complete
// Tier 0 → Tier 1 → Tier 2 cascade. "Complete" means every tier was
// both configured AND executed at least once during the run. A
// stage that was never configured (e.g. Tier 1 with no encoder URL
// in CI) trips this to false; the harness consumer is then expected
// to surface "headline metrics from Tier 0 only" rather than claim
// full-pipeline accuracy.
//
// Rspamd is treated as optional (it is a co-signal scorer, not a
// gate) so a run without Rspamd configured can still be considered
// full-pipeline as long as Tier 0 / 1 / 2 are all live.
func (c TierCoverage) FullPipeline() bool {
	if !c.Tier0Configured || !c.Tier0Executed {
		return false
	}
	if !c.Tier1Configured || !c.Tier1Executed {
		return false
	}
	if !c.Tier2Configured || !c.Tier2Executed {
		return false
	}
	if c.RspamdConfigured && !c.RspamdExecuted {
		return false
	}
	return true
}
