package evaluate

import (
	"math"
	"sort"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Weights configures the relative contribution of each scoring component
// to the final aggregated score.
//
// Components are expressed as fractions of 1.0 — the scorer normalises so
// you don't have to remember to make them sum to 1.0. Tenant-specific
// weights live in Redis under `tenant:{name}:score_engine:weights`.
type Weights struct {
	AI          float64 `json:"ai"`
	Rspamd      float64 `json:"rspamd"`
	Attachments float64 `json:"attachments"`
	Links       float64 `json:"links"`
}

// DefaultWeights match the global defaults in PROPOSAL.md Section 3
// (ai = 80%, rspamd = 20%, attachments and links = 0% pending future tiers).
func DefaultWeights() Weights {
	return Weights{
		AI:          0.80,
		Rspamd:      0.20,
		Attachments: 0.0,
		Links:       0.0,
	}
}

// Total returns the sum of weights (for normalisation).
func (w Weights) Total() float64 {
	return w.AI + w.Rspamd + w.Attachments + w.Links
}

// Components holds the inputs to the scorer. Each value is a 0-100 risk
// score from the corresponding component. AI is the max of Tier 1 and
// Tier 2; Rspamd is normalised from its native unbounded score.
type Components struct {
	AI          int
	Rspamd      int
	Attachments int
	Links       int
}

// FromResult derives Components from a partial EvaluateResult so that the
// caller doesn't have to remember the mapping rules.
func FromResult(r *dto.EvaluateResult) Components {
	c := Components{}
	if r == nil {
		return c
	}
	if r.Tier2 != nil {
		if r.Tier2.Score > c.AI {
			c.AI = r.Tier2.Score
		}
	}
	if r.Tier1 != nil {
		if r.Tier1.Score > c.AI {
			c.AI = r.Tier1.Score
		}
	}
	if r.Rspamd != nil {
		c.Rspamd = normaliseRspamd(r.Rspamd.Score, r.Rspamd.Threshold)
	}
	return c
}

// Score aggregates the components using the given weights. The result is
// clamped to [0, 100].
//
// Algorithm: weighted sum of (weight × normalised_component_score),
// normalised by total weight so callers can use unnormalised weights.
func Score(comp Components, w Weights) int {
	total := w.Total()
	if total <= 0 {
		// No active components — return AI score directly so an admin who
		// zeros every weight still sees something rather than silent zero.
		return clampScore(comp.AI)
	}
	weighted :=
		float64(comp.AI)*w.AI +
			float64(comp.Rspamd)*w.Rspamd +
			float64(comp.Attachments)*w.Attachments +
			float64(comp.Links)*w.Links
	return clampScore(int(math.Round(weighted / total)))
}

// normaliseRspamd maps an Rspamd score (unbounded; reject threshold is
// usually configured around 15) onto a 0-100 risk band. The formula
// matches the v1 behaviour: 0 = no risk, threshold = 50, 2×threshold = 100,
// linear in between.
func normaliseRspamd(score, threshold float64) int {
	if threshold <= 0 {
		threshold = 15
	}
	pct := (score / (2 * threshold)) * 100
	return clampScore(int(math.Round(pct)))
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// SortedReasonCodes returns the reason codes in a deterministic order so
// snapshot tests of the banner stay stable across runs.
func SortedReasonCodes(codes []string) []string {
	out := make([]string, len(codes))
	copy(out, codes)
	sort.Strings(out)
	return out
}
