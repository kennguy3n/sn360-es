package main

import (
	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/scripts/corpus_generator/templates"
)

// TestEmail mirrors scripts/corpus_schema.json exactly. The generator
// produces TestEmail values and the validator consumes them; both are
// emitted as JSON to scripts/corpus/evaluation/<category>.json.
//
// Field order in this struct is the order JSON keys appear on disk —
// keep it stable for diff readability.
type TestEmail struct {
	TestID                  string              `json:"test_id"`
	Category                constant.Category   `json:"category"`
	ExpectedTier            constant.Tier       `json:"expected_tier"`
	ExpectedScoreRange      [2]int              `json:"expected_score_range"`
	IsThreat                bool                `json:"is_threat"`
	Difficulty              templates.Level     `json:"difficulty"`
	Locale                  templates.Locale    `json:"locale"`
	AttackType              string              `json:"attack_type"`
	Description             string              `json:"description"`
	ExpectedSignals         []string            `json:"expected_signals"`
	Tier0Bypass             bool                `json:"tier0_bypass"`
	ExpectedTier1Verdict    string              `json:"expected_tier1_verdict"`
	ExpectedTier2Needed     bool                `json:"expected_tier2_needed"`
	ExpectedTier2Categories []constant.Category `json:"expected_tier2_categories"`
	Payload                 templates.Payload   `json:"payload"`
}

// GenerateOptions configures a generator run.
type GenerateOptions struct {
	Categories       []constant.Category
	CountPerCategory int
	DifficultyPct    [3]int // easy / medium / hard
	Locales          []string
	LocaleWeights    []int
	OutputDir        string
	Seed             int64
	Registry         *templates.Registry
}
