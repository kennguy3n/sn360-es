package education

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

type recordingSender struct {
	calls []dto.RenderedSimulation
	err   error
}

func (r *recordingSender) Send(_ context.Context, _ SimulationTarget, rendered dto.RenderedSimulation) error {
	if r.err != nil {
		return r.err
	}
	r.calls = append(r.calls, rendered)
	return nil
}

func newTestLibrary(t *testing.T) *TemplateLibrary {
	t.Helper()
	lib, err := LoadDefaultTemplates()
	if err != nil {
		t.Fatalf("LoadDefaultTemplates: %v", err)
	}
	return lib
}

func TestSimulation_CreateCampaign(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCampaignStore()
	eng, err := NewSimulationEngine(EngineConfig{
		Store:     store,
		Templates: newTestLibrary(t),
		Clock:     func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewSimulationEngine: %v", err)
	}
	c, err := eng.CreateCampaign(ctx, CampaignConfig{
		TenantID:    "acme",
		Name:        "Q1 phishing test",
		TemplateID:  "bec.easy.ceo_gift_card",
		TargetCount: 12,
	})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if c.Status != dto.CampaignDraft {
		t.Fatalf("status: %q", c.Status)
	}
	if c.Difficulty != dto.DifficultyEasy {
		t.Fatalf("difficulty inherited: %q", c.Difficulty)
	}
	if c.CampaignID == "" {
		t.Fatal("campaign_id not assigned")
	}
	saved, ok, _ := store.LoadCampaign(ctx, c.CampaignID)
	if !ok || saved.CampaignID != c.CampaignID {
		t.Fatal("campaign not persisted")
	}
}

func TestSimulation_CreateCampaign_RejectsInvalid(t *testing.T) {
	ctx := context.Background()
	eng, _ := NewSimulationEngine(EngineConfig{
		Store:     NewMemoryCampaignStore(),
		Templates: newTestLibrary(t),
	})
	cases := []CampaignConfig{
		{},
		{TenantID: "acme"},
		{TenantID: "acme", Name: "X"},
		{TenantID: "acme", Name: "X", TemplateID: "does-not-exist"},
	}
	for i, c := range cases {
		if _, err := eng.CreateCampaign(ctx, c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestSimulation_SendSimulation_DispatchesTargets(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCampaignStore()
	sender := &recordingSender{}
	pub := &recordingPublisher{}
	eng, _ := NewSimulationEngine(EngineConfig{
		Store:     store,
		Templates: newTestLibrary(t),
		Sender:    sender,
		Publisher: pub,
	})
	c, _ := eng.CreateCampaign(ctx, CampaignConfig{
		TenantID:   "acme",
		Name:       "T",
		TemplateID: "credential_phishing.easy.office365",
	})
	targets := []SimulationTarget{
		{UserHash: "u1", MailboxAlias: "user1"},
		{UserHash: "u2", MailboxAlias: "user2"},
	}
	params := map[string]string{"landing_url": "https://example/abc", "fake_o365_domain": "office365-help.example"}
	result, err := eng.SendSimulation(ctx, c.CampaignID, targets, params)
	if err != nil {
		t.Fatalf("SendSimulation: %v", err)
	}
	if result.Delivered != 2 {
		t.Fatalf("delivered: %d", result.Delivered)
	}
	if len(sender.calls) != 2 {
		t.Fatalf("send calls: %d", len(sender.calls))
	}
	saved, _, _ := store.LoadCampaign(ctx, c.CampaignID)
	if saved.Status != dto.CampaignActive {
		t.Fatalf("campaign status after send: %q", saved.Status)
	}
	if saved.SentCount != 2 {
		t.Fatalf("sent_count: %d", saved.SentCount)
	}
	// Publisher should have received two interaction events.
	if len(pub.subjects) != 2 {
		t.Fatalf("interaction events: %d", len(pub.subjects))
	}
}

func TestSimulation_SendSimulation_TolerantOfSenderErrors(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCampaignStore()
	sender := &recordingSender{err: errors.New("smtp down")}
	eng, _ := NewSimulationEngine(EngineConfig{
		Store:     store,
		Templates: newTestLibrary(t),
		Sender:    sender,
	})
	c, _ := eng.CreateCampaign(ctx, CampaignConfig{
		TenantID:   "acme",
		Name:       "T",
		TemplateID: "credential_phishing.easy.office365",
	})
	res, err := eng.SendSimulation(ctx, c.CampaignID, []SimulationTarget{{UserHash: "u1"}}, nil)
	if err != nil {
		t.Fatalf("SendSimulation should not fail on per-target errors: %v", err)
	}
	if res.Delivered != 0 {
		t.Fatalf("delivered should be 0 when sender fails, got %d", res.Delivered)
	}
}

func TestTracker_RecordsAndAggregates(t *testing.T) {
	ctx := context.Background()
	tracker, err := NewSimulationTracker(TrackerConfig{
		Store: NewMemoryInteractionStore(),
	})
	if err != nil {
		t.Fatalf("NewSimulationTracker: %v", err)
	}
	cid := "camp-1"
	actions := []dto.UserInteractionType{
		dto.InteractionDelivered,
		dto.InteractionOpened,
		dto.InteractionClickedLink,
		dto.InteractionReportedPhishing,
	}
	for _, a := range actions {
		if _, err := tracker.RecordInteraction(ctx, cid, "user-hash", a); err != nil {
			t.Fatalf("RecordInteraction(%v): %v", a, err)
		}
	}
	agg, err := tracker.Aggregate(ctx, cid)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if agg.Delivered != 1 || agg.Opened != 1 || agg.Clicked != 1 || agg.Reported != 1 {
		t.Fatalf("aggregation: %+v", agg)
	}
}

func TestTracker_RejectsInvalid(t *testing.T) {
	ctx := context.Background()
	tracker, _ := NewSimulationTracker(TrackerConfig{Store: NewMemoryInteractionStore()})
	cases := []struct {
		c, u string
		a    dto.UserInteractionType
	}{
		{"", "u", dto.InteractionDelivered},
		{"c", "", dto.InteractionDelivered},
		{"c", "u", dto.UserInteractionType("nope")},
	}
	for i, c := range cases {
		if _, err := tracker.RecordInteraction(ctx, c.c, c.u, c.a); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestTemplateLibrary_CoversAllAttackTypesAtAllDifficulties(t *testing.T) {
	lib := newTestLibrary(t)
	for _, atk := range dto.AllAttackTypes {
		for _, diff := range dto.AllDifficulties {
			got := lib.List(atk, diff)
			if len(got) == 0 {
				t.Fatalf("no template for attack=%q difficulty=%q", atk, diff)
			}
		}
	}
}

func TestTemplateLibrary_Render(t *testing.T) {
	lib := newTestLibrary(t)
	rendered, err := lib.Render("bec.easy.ceo_gift_card", map[string]string{
		"target_name":      "Alice",
		"ceo_name":         "Bob",
		"lookalike_domain": "exampie.com",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if rendered.Subject == "" || rendered.Body == "" {
		t.Fatalf("empty rendered output: %+v", rendered)
	}
	if !rendered.ContainsHazard {
		t.Fatal("ContainsHazard should be true")
	}
	if rendered.SenderDomain != "exampie.com" {
		t.Fatalf("sender_domain: %q", rendered.SenderDomain)
	}
}

func TestTemplateLibrary_Register_DuplicateReplaces(t *testing.T) {
	lib := NewTemplateLibrary()
	t1 := dto.SimulationTemplate{
		TemplateID: "t.x", AttackType: dto.AttackTypeBEC, Difficulty: dto.DifficultyEasy,
		SubjectTemplate: "S", BodyTemplate: "B", SenderDisplayTemplate: "D",
		SenderDomainTemplate: "X", LandingPageType: "none",
	}
	if err := lib.Register(t1); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Same ID, different subject — should replace, not append.
	t2 := t1
	t2.SubjectTemplate = "S2"
	if err := lib.Register(t2); err != nil {
		t.Fatalf("Register replace: %v", err)
	}
	list := lib.List(dto.AttackTypeBEC, dto.DifficultyEasy)
	if len(list) != 1 {
		t.Fatalf("expected 1 template after replace, got %d", len(list))
	}
	if list[0].SubjectTemplate != "S2" {
		t.Fatalf("subject not replaced: %q", list[0].SubjectTemplate)
	}
}
