package education_test

import (
	"context"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/education"
)

// BenchmarkTemplateLibrary_Render measures the cost of rendering one
// simulation template (subject + body + sender + domain) with a typical
// parameter set. This is the inner loop SendSimulation walks for every
// target so it dominates the campaign-dispatch cost.
func BenchmarkTemplateLibrary_Render(b *testing.B) {
	lib, tmpl := mustBenchTemplates(b)
	params := map[string]string{
		"FirstName":  "Alex",
		"CompanyURL": "https://acme.example/login",
		"BrandName":  "Acme",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := lib.Render(tmpl, params); err != nil {
			b.Fatalf("render: %v", err)
		}
	}
}

// BenchmarkTemplateLibrary_Get measures the cost of the read-side path
// (template lookup) which the engine hits on every CreateCampaign /
// SendSimulation call. It should never allocate.
func BenchmarkTemplateLibrary_Get(b *testing.B) {
	lib, tmpl := mustBenchTemplates(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := lib.Get(tmpl); !ok {
			b.Fatalf("template not found")
		}
	}
}

// BenchmarkSimulationEngine_Dispatch measures the cost of dispatching
// a campaign to a small fixed batch of targets. The Sender is a no-op
// so this benchmark isolates the template-rendering and bookkeeping
// cost rather than network IO.
func BenchmarkSimulationEngine_Dispatch(b *testing.B) {
	lib, tmpl := mustBenchTemplates(b)
	eng, err := education.NewSimulationEngine(education.EngineConfig{
		Store:     education.NewMemoryCampaignStore(),
		Templates: lib,
		Sender:    noopSender{},
	})
	if err != nil {
		b.Fatalf("engine: %v", err)
	}
	ctx := context.Background()
	c, err := eng.CreateCampaign(ctx, education.CampaignConfig{
		TenantID:    "tenant-bench",
		Name:        "bench-campaign",
		TemplateID:  tmpl,
		TargetCount: 8,
	})
	if err != nil {
		b.Fatalf("create campaign: %v", err)
	}
	targets := []education.SimulationTarget{
		{UserHash: "u1", MailboxAlias: "a1@acme.test", DisplayName: "User One"},
		{UserHash: "u2", MailboxAlias: "a2@acme.test", DisplayName: "User Two"},
		{UserHash: "u3", MailboxAlias: "a3@acme.test", DisplayName: "User Three"},
		{UserHash: "u4", MailboxAlias: "a4@acme.test", DisplayName: "User Four"},
		{UserHash: "u5", MailboxAlias: "a5@acme.test", DisplayName: "User Five"},
		{UserHash: "u6", MailboxAlias: "a6@acme.test", DisplayName: "User Six"},
		{UserHash: "u7", MailboxAlias: "a7@acme.test", DisplayName: "User Seven"},
		{UserHash: "u8", MailboxAlias: "a8@acme.test", DisplayName: "User Eight"},
	}
	params := map[string]string{"FirstName": "Alex", "CompanyURL": "https://acme.example/login", "BrandName": "Acme"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.SendSimulation(ctx, c.CampaignID, targets, params); err != nil {
			b.Fatalf("send: %v", err)
		}
	}
}

// noopSender implements education.SimulationSender without producing
// any side effects. Used to isolate engine cost from network IO.
type noopSender struct{}

func (noopSender) Send(_ context.Context, _ education.SimulationTarget, _ dto.RenderedSimulation) error {
	return nil
}

// mustBenchTemplates loads the embedded default catalog and returns
// the first template id so every benchmark exercises a real template
// configuration.
func mustBenchTemplates(b *testing.B) (*education.TemplateLibrary, string) {
	b.Helper()
	lib, err := education.LoadDefaultTemplates()
	if err != nil {
		b.Fatalf("load templates: %v", err)
	}
	templates := lib.List("", "")
	if len(templates) == 0 {
		b.Fatalf("no default templates registered")
	}
	return lib, templates[0].TemplateID
}
