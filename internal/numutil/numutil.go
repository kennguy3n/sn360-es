// Package numutil holds small numeric helpers shared by scorer
// packages (education resilience, relationship vulnerability, ...).
// Keeping them in one place avoids the drift that occurs when each
// package defines its own identical clamp helpers.
package numutil

import "math"

// ClampPct clamps v to the inclusive 0..100 range. NaN is treated as
// 0 so callers don't have to short-circuit upstream divisions by zero.
func ClampPct(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// IntClamp rounds v to the nearest integer and clamps it to 0..100.
// Used by scorers that publish integer breakdown fields on a 0..100
// scale.
func IntClamp(v float64) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return int(math.Round(v))
}
