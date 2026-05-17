// Package corpus generates labelled synthetic email fixtures used by
// the SN360-ES accuracy benchmarks, performance benchmarks, and
// resource-profiling tests. The generator is deterministic for a given
// seed so benchmark runs across CI / local / nightly are reproducible.
//
// The package is intentionally importable from internal/* tests — it
// does NOT import any service code, so cycles with internal/service/*
// are impossible.
//
// See cmd/gen-corpus for the CLI that serialises a generated corpus to
// JSON for external consumption (`make gen-corpus`).
package corpus

import (
	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Difficulty buckets a generated email by how hard the pipeline should
// find the classification. Easy threats stack many signals; hard ones
// hide most of them so only Tier 2 escalation should catch them.
type Difficulty string

const (
	DifficultyEasy   Difficulty = "easy"
	DifficultyMedium Difficulty = "medium"
	DifficultyHard   Difficulty = "hard"
)

// AllDifficulties is the canonical iteration order used by the
// distribution sanity checks.
var AllDifficulties = []Difficulty{
	DifficultyEasy,
	DifficultyMedium,
	DifficultyHard,
}

// LabeledEmail bundles a synthetic EvaluateRequest with the ground
// truth labels that the accuracy harness compares the pipeline output
// against. The struct is the single source of truth shared between the
// generator, accuracy report, and benchmarks.
type LabeledEmail struct {
	// Request is the EvaluateRequest fed into the evaluator. Sender,
	// Recipient, Subject, Body and Signals are always populated.
	Request dto.EvaluateRequest
	// ExpectedTier is the tier the full pipeline is expected to assign.
	ExpectedTier constant.Tier
	// ExpectedPrimary is the primary category the categorizer is
	// expected to choose given the populated signals.
	ExpectedPrimary constant.Category
	// ExpectedScoreRange is an inclusive [lo, hi] band for the final
	// aggregated risk score; benchmarks use it as a soft check.
	ExpectedScoreRange [2]int
	// Difficulty buckets the example for the per-difficulty breakdown
	// in the accuracy report.
	Difficulty Difficulty
	// AttackType is a short human-readable label (e.g.
	// "lookalike-domain-credential-harvest") used in the accuracy
	// report rows and in failure-case logs.
	AttackType string
	// IsThreat reports whether the email is malicious vs benign. The
	// benign/threat split feeds the FP/FN computation in the accuracy
	// harness.
	IsThreat bool
	// Locale is the BCP-47 locale of the body content.
	Locale string
}

// Config drives Generate. All fields are optional; sensible defaults
// are filled in by Generate.
type Config struct {
	// Seed is the PRNG seed. Same seed → byte-identical output.
	Seed int64
	// Size is the total number of emails to generate. The actual
	// returned slice may be slightly larger so each category meets its
	// MinPerCategory floor.
	Size int
	// MinPerCategory is the minimum number of emails generated per
	// category. Defaults to 50.
	MinPerCategory int
	// Locales overrides the default locale weights. Each entry is a
	// (locale, weight) pair; weight 0 disables the locale. Nil means
	// use DefaultLocaleWeights.
	Locales []LocaleWeight
}

// LocaleWeight is one entry in Config.Locales.
type LocaleWeight struct {
	Locale string
	Weight int
}

// DefaultLocaleWeights mirrors the multilingual distribution used by
// the production-ish corpus generator under scripts/corpus_generator.
// English dominates so accuracy regressions on the primary locale are
// caught even on small corpora.
var DefaultLocaleWeights = []LocaleWeight{
	{Locale: "en", Weight: 80},
	{Locale: "vi", Weight: 4},
	{Locale: "th", Weight: 4},
	{Locale: "ja", Weight: 4},
	{Locale: "ko", Weight: 4},
	{Locale: "zh", Weight: 4},
}
