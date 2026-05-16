package education

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// AdaptiveDifficulty selects a simulation difficulty (and a concrete
// template) appropriate for a user's current resilience score. The
// mapping follows PROPOSAL.md §5c–d:
//
//	score ∈ [0,40)   → Easy  (obvious red flags)
//	score ∈ [40,70)  → Medium (subtle indicators)
//	score ∈ [70,100] → Hard   (sophisticated BEC/spear-phishing)
//
// Users who consistently detect simulations bump up one level per call
// (via the Progression input); users who fall for simulations bump
// down. The adjustment is bounded.
type AdaptiveDifficulty struct {
	templates *TemplateLibrary
}

// NewAdaptiveDifficulty constructs the selector. Templates is required.
func NewAdaptiveDifficulty(templates *TemplateLibrary) (*AdaptiveDifficulty, error) {
	if templates == nil {
		return nil, errors.New("education: adaptive requires Templates")
	}
	return &AdaptiveDifficulty{templates: templates}, nil
}

// SelectDifficulty maps a resilience score to its base difficulty.
func (a *AdaptiveDifficulty) SelectDifficulty(score int) dto.DifficultyLevel {
	switch {
	case score < 40:
		return dto.DifficultyEasy
	case score < 70:
		return dto.DifficultyMedium
	default:
		return dto.DifficultyHard
	}
}

// Progression describes the recent history used to bump the
// base difficulty up or down by one step.
type Progression struct {
	// ConsecutiveDetections is the number of simulations in a row that
	// the user successfully reported or ignored.
	ConsecutiveDetections int
	// ConsecutiveFailures is the number of simulations in a row that
	// the user fell for (clicked or submitted credentials).
	ConsecutiveFailures int
}

// AdjustDifficulty bumps the base difficulty up after 3 consecutive
// detections, and down after 2 consecutive failures. Capped at the
// difficulty bounds.
func (a *AdaptiveDifficulty) AdjustDifficulty(base dto.DifficultyLevel, p Progression) dto.DifficultyLevel {
	idx := indexOf(dto.AllDifficulties, base)
	if p.ConsecutiveDetections >= 3 && idx < len(dto.AllDifficulties)-1 {
		return dto.AllDifficulties[idx+1]
	}
	if p.ConsecutiveFailures >= 2 && idx > 0 {
		return dto.AllDifficulties[idx-1]
	}
	return base
}

// SelectTemplate picks one template that matches the user's adjusted
// difficulty. Selection is deterministic per (tenantID, userHash,
// attackType, difficulty) so that re-runs are reproducible.
func (a *AdaptiveDifficulty) SelectTemplate(_ context.Context, tenantID, userHash string, attackType dto.AttackType, difficulty dto.DifficultyLevel) (dto.SimulationTemplate, error) {
	if tenantID == "" {
		return dto.SimulationTemplate{}, errors.New("education: tenant_id is required")
	}
	if userHash == "" {
		return dto.SimulationTemplate{}, errors.New("education: user_hash is required")
	}
	if !attackType.Valid() {
		return dto.SimulationTemplate{}, fmt.Errorf("education: invalid attack_type %q", attackType)
	}
	if !difficulty.Valid() {
		return dto.SimulationTemplate{}, fmt.Errorf("education: invalid difficulty %q", difficulty)
	}
	candidates := a.templates.List(attackType, difficulty)
	if len(candidates) == 0 {
		return dto.SimulationTemplate{}, fmt.Errorf("education: no templates for %s/%s", attackType, difficulty)
	}
	// Stable sort by template_id (already done by List) — pick by hash.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].TemplateID < candidates[j].TemplateID })
	h := fnv.New32a()
	_, _ = h.Write([]byte(tenantID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(userHash))
	idx := int(h.Sum32() % uint32(len(candidates)))
	return candidates[idx], nil
}

// SelectForUser is a convenience that walks the full adaptive flow:
//
//  1. Map score → base difficulty.
//  2. Apply progression.
//  3. Choose a matching template.
func (a *AdaptiveDifficulty) SelectForUser(ctx context.Context, tenantID, userHash string, attackType dto.AttackType, score int, p Progression) (dto.SimulationTemplate, error) {
	base := a.SelectDifficulty(score)
	adjusted := a.AdjustDifficulty(base, p)
	return a.SelectTemplate(ctx, tenantID, userHash, attackType, adjusted)
}

func indexOf(in []dto.DifficultyLevel, want dto.DifficultyLevel) int {
	for i, v := range in {
		if v == want {
			return i
		}
	}
	return -1
}
