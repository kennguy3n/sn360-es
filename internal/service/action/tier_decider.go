// Package action hosts the post-evaluation surface: tier decision,
// banner rendering, native-provider label application, action tokens,
// URL rewriting, and the in-product feedback handler.
package action

import (
	"errors"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// TierThresholds is the per-tenant cut-offs that map a 0-100 risk score
// to one of the six banner tiers. They mirror the defaults documented
// in ARCHITECTURE.md Section 8.2 and can be overridden in Redis.
type TierThresholds struct {
	Blocked       int
	HighRisk      int
	Warning       int
	Caution       int
	Informational int
	// FirstContactFloor is the minimum tier applied when a message
	// looks otherwise benign but comes from a first-time external
	// sender. Default is Informational.
	FirstContactFloor constant.Tier
}

// DefaultTierThresholds returns the SN360-ES defaults.
func DefaultTierThresholds() TierThresholds {
	return TierThresholds{
		Blocked:           85,
		HighRisk:          70,
		Warning:           50,
		Caution:           30,
		Informational:     15,
		FirstContactFloor: constant.TierInformational,
	}
}

// Validate ensures the thresholds are monotone (Blocked > HighRisk >
// Warning > Caution > Informational).
func (t TierThresholds) Validate() error {
	if t.Blocked <= t.HighRisk || t.HighRisk <= t.Warning ||
		t.Warning <= t.Caution || t.Caution <= t.Informational {
		return errors.New("action: tier thresholds must be strictly descending")
	}
	if t.Blocked > 100 || t.Informational < 0 {
		return errors.New("action: tier thresholds out of [0,100]")
	}
	if !t.FirstContactFloor.Valid() {
		return errors.New("action: first-contact floor must be a known tier")
	}
	return nil
}

// TierDecider maps an EvaluateResult to a Tier. It honours category
// overrides (e.g. CategoryInternalTrusted always → Trusted) and the
// per-tenant thresholds.
type TierDecider struct {
	thresholds TierThresholds
}

// NewTierDecider constructs a TierDecider from thresholds. Falls back
// to defaults if thresholds is zero-value.
func NewTierDecider(t TierThresholds) (*TierDecider, error) {
	if t == (TierThresholds{}) {
		t = DefaultTierThresholds()
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &TierDecider{thresholds: t}, nil
}

// Thresholds returns the active thresholds (for inspection / metrics).
func (d *TierDecider) Thresholds() TierThresholds { return d.thresholds }

// Decide returns the tier for r. Order of precedence:
//
//  1. Category overrides (InternalTrusted / VendorTrusted → Trusted;
//     Newsletter → Informational).
//  2. Tier 0 forced bypass → derived from forced category.
//  3. Score → tier mapping using thresholds.
//  4. Floor: a first-contact-external message that would otherwise
//     fall under Informational gets pinned at FirstContactFloor.
//
// Decide never returns an empty tier — every message receives a
// disposition.
func (d *TierDecider) Decide(r dto.EvaluateResult) constant.Tier {
	switch r.Primary {
	case constant.CategoryInternalTrusted, constant.CategoryVendorTrusted:
		return constant.TierTrusted
	case constant.CategoryNewsletter:
		return constant.TierInformational
	}
	if r.Tier0 != nil && r.Tier0.Bypass {
		switch r.Tier0.ForcedCategory {
		case constant.CategoryInternalTrusted, constant.CategoryVendorTrusted:
			return constant.TierTrusted
		case constant.CategoryNewsletter:
			return constant.TierInformational
		}
	}
	t := d.tierFromScore(r.Score)
	if t == constant.TierTrusted && r.Primary == constant.CategoryFirstContactExternal {
		t = d.thresholds.FirstContactFloor
	}
	return t
}

func (d *TierDecider) tierFromScore(score int) constant.Tier {
	switch {
	case score >= d.thresholds.Blocked:
		return constant.TierBlocked
	case score >= d.thresholds.HighRisk:
		return constant.TierHighRisk
	case score >= d.thresholds.Warning:
		return constant.TierWarning
	case score >= d.thresholds.Caution:
		return constant.TierCaution
	case score >= d.thresholds.Informational:
		return constant.TierInformational
	default:
		return constant.TierTrusted
	}
}
