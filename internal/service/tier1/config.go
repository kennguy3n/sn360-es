// Package tier1 contains the SN360-ES Tier 1 ML stage: a thin HTTP
// client for the XLM-RoBERTa risk-scoring inference service, threshold
// logic, and a batch-fetch helper used by the evaluate pipeline.
package tier1

import (
	"errors"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Config configures the Tier 1 client. URL is required; the rest have
// sensible defaults.
type Config struct {
	// URL is the encoder base URL (e.g. http://encoder.svc.cluster.local:8080).
	URL string
	// PredictPath is the per-message inference path (default /predict).
	PredictPath string
	// BatchPath is the batched inference path (default /predict/batch).
	BatchPath string
	// HealthPath is the readiness path (default /health).
	HealthPath string
	// Timeout is the per-request timeout (default 5s).
	Timeout time.Duration
	// BatchTimeout is the per-batch-request timeout (default 15s).
	BatchTimeout time.Duration
	// MaxBatchSize is the largest number of inputs sent in a single
	// batch request (default 64).
	MaxBatchSize int
	// AuthToken is sent as Bearer token if non-empty.
	AuthToken string
}

// Thresholds holds the tenant-tunable decision thresholds. Scores below
// PassBelow are treated as benign; scores above FlagAbove are treated as
// flagged; anything in between escalates to Tier 2.
type Thresholds struct {
	PassBelow int
	FlagAbove int
	// SuppressPartner adjusts thresholds for relationships flagged as
	// Partner or Customer (lowers thresholds so we are more sensitive).
	SuppressPartner int
}

// DefaultThresholds returns the platform-wide defaults documented in
// the proposal: pass<20, flag>60.
func DefaultThresholds() Thresholds {
	return Thresholds{PassBelow: 20, FlagAbove: 60, SuppressPartner: -10}
}

// Validate normalises and sanity-checks the config. Mutates a copy.
func (c Config) Validate() (Config, error) {
	if c.URL == "" {
		return c, errors.New("tier1: URL is required")
	}
	if c.PredictPath == "" {
		c.PredictPath = "/predict"
	}
	if c.BatchPath == "" {
		c.BatchPath = "/predict/batch"
	}
	if c.HealthPath == "" {
		c.HealthPath = "/health"
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.BatchTimeout <= 0 {
		c.BatchTimeout = 15 * time.Second
	}
	if c.MaxBatchSize <= 0 {
		c.MaxBatchSize = 64
	}
	return c, nil
}

// Decision returns the verdict for score given thresholds.
func (t Thresholds) Decision(score int) Verdict {
	switch {
	case score < t.PassBelow:
		return VerdictPass
	case score > t.FlagAbove:
		return VerdictFlag
	default:
		return VerdictEscalate
	}
}

// Verdict is the discrete output of the Tier 1 threshold logic.
type Verdict string

const (
	VerdictPass     Verdict = "pass"
	VerdictEscalate Verdict = "escalate"
	VerdictFlag     Verdict = "flag"
)

// AdjustForRelationship returns a copy of t adjusted for the given
// relationship category. Partner / Customer get tighter thresholds;
// FirstTimeExternal forces escalation by lifting PassBelow.
func (t Thresholds) AdjustForRelationship(cat dto.RelationshipCategory) Thresholds {
	out := t
	switch cat {
	case dto.RelationshipPartner, dto.RelationshipCustomer:
		out.PassBelow += t.SuppressPartner
		out.FlagAbove += t.SuppressPartner
	case dto.RelationshipFirstTimeExternal:
		out.PassBelow = 0
	}
	if out.PassBelow < 0 {
		out.PassBelow = 0
	}
	if out.FlagAbove < out.PassBelow+1 {
		out.FlagAbove = out.PassBelow + 1
	}
	return out
}
