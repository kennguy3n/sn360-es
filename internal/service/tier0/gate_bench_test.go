package tier0_test

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
)

// BenchmarkGate_InternalBypass exercises the cheapest Tier 0 path:
// IsInternal=true → immediate Bypass.
func BenchmarkGate_InternalBypass(b *testing.B) {
	g := tier0.NewGate(tier0.DefaultGateConfig(), nil)
	req := dto.EvaluateRequest{
		Sender:    "ceo@acme.test",
		Recipient: "ops@acme.test",
		Signals: dto.RiskSignals{
			IsInternal:      true,
			SenderDomain:    "acme.test",
			RecipientDomain: "acme.test",
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Apply(req, req.Signals)
	}
}

// BenchmarkGate_VendorBypass exercises the vendor-allowlist short
// circuit which runs after the internal check.
func BenchmarkGate_VendorBypass(b *testing.B) {
	g := tier0.NewGate(tier0.DefaultGateConfig(), nil)
	req := dto.EvaluateRequest{
		Sender:    "no-reply@docusign.net",
		Recipient: "ops@acme.test",
		Signals: dto.RiskSignals{
			IsExternal:      true,
			IsFromVendor:    true,
			SenderDomain:    "docusign.net",
			RecipientDomain: "acme.test",
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Apply(req, req.Signals)
	}
}

// BenchmarkGate_ExternalFullPath exercises the longest Tier 0 path:
// no early bypass, the recurring detector runs, the relationship
// modifier triggers ForceEscalate.
func BenchmarkGate_ExternalFullPath(b *testing.B) {
	g := tier0.NewGate(tier0.DefaultGateConfig(), nil)
	req := dto.EvaluateRequest{
		Sender:    "new-supplier@paypa1.com",
		Recipient: "finance@acme.test",
		Signals: dto.RiskSignals{
			IsExternal:           true,
			HasLookalikeDomain:   true,
			HasSuspiciousURL:     true,
			RelationshipCategory: dto.RelationshipFirstTimeExternal,
			SenderDomain:         "paypa1.com",
			RecipientDomain:      "acme.test",
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Apply(req, req.Signals)
	}
}

// BenchmarkGate_HighVolumeRspamdOnly exercises the RspamdOnly path
// (high-volume sender, skip-ML).
func BenchmarkGate_HighVolumeRspamdOnly(b *testing.B) {
	g := tier0.NewGate(tier0.DefaultGateConfig(), nil)
	req := dto.EvaluateRequest{
		Sender:    "news@newsletter.example",
		Recipient: "ops@acme.test",
		Signals: dto.RiskSignals{
			IsExternal:         true,
			IsHighVolumeSender: true,
			SenderDomain:       "newsletter.example",
			RecipientDomain:    "acme.test",
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Apply(req, req.Signals)
	}
}
