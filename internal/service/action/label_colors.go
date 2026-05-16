package action

import "github.com/kennguy3n/sn360-es/internal/constant"

// LabelColor is a provider-agnostic colour pair (background + foreground).
// Concrete provider adapters translate this into Gmail label colour
// objects or Outlook MasterCategory presets.
type LabelColor struct {
	// Background is the primary fill colour. For Gmail this is the
	// "backgroundColor" of the userLabel. For Outlook the closest
	// preset is selected from OutlookPreset below.
	Background string
	// Foreground is the text colour. Gmail uses it as
	// labelColor.textColor; Outlook ignores it (presets carry their
	// own text colour).
	Foreground string
	// OutlookPreset is the closest matching MasterCategory preset
	// (`preset0` … `preset24`). Outlook does not allow arbitrary RGB
	// — every category must map to one of the built-in presets.
	OutlookPreset string
}

// LabelStyle is the per-tier visual treatment applied to provider
// labels / categories. Values mirror ARCHITECTURE.md Section 8.4 and
// are deliberately conservative so they survive provider sanitisers.
var LabelStyle = map[constant.Tier]LabelColor{
	constant.TierBlocked: {
		Background:    "#b00020",
		Foreground:    "#ffffff",
		OutlookPreset: "preset10", // Red
	},
	constant.TierHighRisk: {
		Background:    "#cc5500",
		Foreground:    "#ffffff",
		OutlookPreset: "preset3", // Orange
	},
	constant.TierWarning: {
		Background:    "#b58a00",
		Foreground:    "#1f1f1f",
		OutlookPreset: "preset0", // Yellow / amber
	},
	constant.TierCaution: {
		Background:    "#1565c0",
		Foreground:    "#ffffff",
		OutlookPreset: "preset8", // Blue
	},
	constant.TierInformational: {
		Background:    "#5a6b80",
		Foreground:    "#ffffff",
		OutlookPreset: "preset12", // Steel / gray-blue
	},
	constant.TierTrusted: {
		Background:    "#0a7a3d",
		Foreground:    "#ffffff",
		OutlookPreset: "preset5", // Green
	},
}

// ColorFor returns the LabelColor for tier t, or a neutral grey if t
// is unknown. The unknown branch is defensive — callers should pass a
// validated tier.
func ColorFor(t constant.Tier) LabelColor {
	if c, ok := LabelStyle[t]; ok {
		return c
	}
	return LabelColor{Background: "#7a7a7a", Foreground: "#ffffff", OutlookPreset: "preset12"}
}
