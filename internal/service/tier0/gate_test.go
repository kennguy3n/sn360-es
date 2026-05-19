package tier0

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestGateInternalBypass(t *testing.T) {
	g := NewGate(DefaultGateConfig(), nil)
	out := g.Apply(dto.EvaluateRequest{Signals: dto.RiskSignals{IsInternal: true}})
	if !out.Bypass || !out.SkipML {
		t.Errorf("expected internal bypass, got %+v", out)
	}
	if out.ForcedCategory != constant.CategoryInternalTrusted {
		t.Errorf("forced category = %s, want INTERNAL_TRUSTED", out.ForcedCategory)
	}
	if out.Reason != "internal_trusted" {
		t.Errorf("reason = %s, want internal_trusted", out.Reason)
	}
}

func TestGateVendorBypass(t *testing.T) {
	g := NewGate(DefaultGateConfig(), nil)
	out := g.Apply(dto.EvaluateRequest{Signals: dto.RiskSignals{IsFromVendor: true}})
	if !out.Bypass || !out.SkipML {
		t.Errorf("expected vendor bypass, got %+v", out)
	}
	if out.ForcedCategory != constant.CategoryVendorTrusted {
		t.Errorf("forced category = %s, want VENDOR_TRUSTED", out.ForcedCategory)
	}
}

func TestGateVendorCompromiseBlocksBypass(t *testing.T) {
	g := NewGate(DefaultGateConfig(), nil)

	// Vendor with no compromise signal should get bypass.
	clean := g.Apply(dto.EvaluateRequest{Signals: dto.RiskSignals{
		IsFromVendor:              true,
		LooksLikeVendorCompromise: false,
	}})
	if !clean.Bypass || !clean.SkipML {
		t.Errorf("clean vendor should bypass, got %+v", clean)
	}
	if clean.ForcedCategory != constant.CategoryVendorTrusted {
		t.Errorf("clean vendor category = %s, want VENDOR_TRUSTED", clean.ForcedCategory)
	}
	if clean.Reason != "vendor_trusted" {
		t.Errorf("clean vendor reason = %s, want vendor_trusted", clean.Reason)
	}

	// Vendor with compromise signal should NOT bypass.
	compromised := g.Apply(dto.EvaluateRequest{Signals: dto.RiskSignals{
		IsFromVendor:              true,
		LooksLikeVendorCompromise: true,
	}})
	if compromised.Bypass {
		t.Errorf("compromised vendor should NOT bypass, got %+v", compromised)
	}
	if !compromised.ForceEscalate {
		t.Errorf("compromised vendor should force escalation, got %+v", compromised)
	}
	if compromised.Reason != "vendor_compromise_suspected" {
		t.Errorf("compromised vendor reason = %s, want vendor_compromise_suspected", compromised.Reason)
	}
}

func TestGateRecurringDetectionViaSender(t *testing.T) {
	g := NewGate(DefaultGateConfig(), nil)
	cases := []string{
		"noreply@example.com",
		"no-reply@acme.com",
		"Acme Updates <notifications@acme.com>",
		"mailer-daemon@bounces.example.com",
	}
	for _, s := range cases {
		out := g.Apply(dto.EvaluateRequest{Sender: s})
		if !out.Bypass || out.ForcedCategory != constant.CategoryNewsletter {
			t.Errorf("sender %q should be flagged recurring, got %+v", s, out)
		}
	}
}

func TestGateHighVolumeRoutesToRspamdOnly(t *testing.T) {
	g := NewGate(DefaultGateConfig(), nil)
	out := g.Apply(dto.EvaluateRequest{Signals: dto.RiskSignals{IsHighVolumeSender: true}})
	if out.Bypass {
		t.Errorf("high-volume sender must not bypass, got %+v", out)
	}
	if !out.SkipML || !out.RspamdOnly {
		t.Errorf("high-volume sender should skip ML and use Rspamd-only, got %+v", out)
	}
}

func TestGateFirstContactForcesEscalation(t *testing.T) {
	g := NewGate(DefaultGateConfig(), nil)
	out := g.Apply(dto.EvaluateRequest{Signals: dto.RiskSignals{
		IsExternal:           true,
		RelationshipCategory: dto.RelationshipFirstTimeExternal,
	}})
	if !out.ForceEscalate {
		t.Errorf("first-time external should force escalation, got %+v", out)
	}
}

func TestGatePartnerLowersTier1Threshold(t *testing.T) {
	g := NewGate(DefaultGateConfig(), nil)
	out := g.Apply(dto.EvaluateRequest{Signals: dto.RiskSignals{
		IsExternal:           true,
		RelationshipCategory: dto.RelationshipPartner,
	}})
	if out.Tier1ThresholdOverride == 0 {
		t.Errorf("partner relationship should set Tier1 threshold override, got %+v", out)
	}
}

func TestGateDisabledFlags(t *testing.T) {
	cfg := GateConfig{} // every short-circuit disabled
	g := NewGate(cfg, nil)
	out := g.Apply(dto.EvaluateRequest{Signals: dto.RiskSignals{
		IsInternal:         true,
		IsFromVendor:       true,
		IsRecurringService: true,
		IsHighVolumeSender: true,
	}})
	if out.Bypass || out.SkipML || out.RspamdOnly {
		t.Errorf("all gates disabled — outcome should be zero-value, got %+v", out)
	}
}

func TestRecurringDetectorEdgeCases(t *testing.T) {
	d := NewRecurringDetector()
	cases := []struct {
		sender string
		want   bool
	}{
		{"", false},
		{"alice@example.com", false},
		{"noreply@example.com", true},
		{"NoReply@example.com", true},
		{"do-not-reply@example.com", true},
		{"notifications@github.com", true},
		{"bot@example.com", true},
		{"alerts@example.com", true},
		{"team@example.com", false}, // plain "team" without -bot/-notifications
		{"<noreply@example.com>", true},
		{"Acme <noreply@example.com>", true},
		{"garbage with no @ symbol", false},
	}
	for _, tc := range cases {
		got := d.IsRecurring(tc.sender)
		if got != tc.want {
			t.Errorf("IsRecurring(%q) = %v, want %v", tc.sender, got, tc.want)
		}
	}
}
