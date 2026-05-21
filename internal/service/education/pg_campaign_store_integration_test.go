//go:build integration
// +build integration

package education_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/education"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// startPGForEducation stands up a clean Postgres container for the
// education store integration tests. Mirrors pkg/storage/postgres'
// helper rather than importing it so this package doesn't take a
// test-time dependency on another _test package.
func startPGForEducation(t *testing.T) postgres.Config {
	t.Helper()
	ctx := context.Background()
	c, err := tcpg.Run(ctx, "postgres:16-alpine",
		tcpg.WithDatabase("sn360es"),
		tcpg.WithUsername("sn360es"),
		tcpg.WithPassword("sn360es"),
		tcpg.BasicWaitStrategies(),
	)
	if err != nil {
		if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "docker") {
			t.Skipf("docker not available, skipping: %v", err)
		}
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "5432/tcp")
	portNum, err := strconv.Atoi(port.Port())
	if err != nil {
		t.Fatalf("parse port %q: %v", port.Port(), err)
	}
	return postgres.Config{
		Host:     host,
		Port:     portNum,
		User:     "sn360es",
		Password: "sn360es",
		Database: "sn360es",
		SSLMode:  "disable",
	}
}

// openEducationDB opens the pgx pool against the fresh container,
// then exercises EnsureSchema so each test starts on a known table
// shape. Returns the closer the caller must defer.
func openEducationDB(t *testing.T) (*postgres.DB, *education.PostgresCampaignStore, *education.PostgresInteractionStore) {
	t.Helper()
	cfg := startPGForEducation(t)
	db, err := postgres.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	campaigns := education.NewPostgresCampaignStore(db)
	if err := campaigns.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure campaign schema: %v", err)
	}
	interactions := education.NewPostgresInteractionStore(db)
	if err := interactions.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure interaction schema: %v", err)
	}
	return db, campaigns, interactions
}

func TestPostgresCampaignStore_SaveLoadRoundTrip(t *testing.T) {
	_, campaigns, _ := openEducationDB(t)
	ctx := context.Background()

	started := time.Date(2025, 5, 1, 12, 0, 0, 0, time.UTC)
	c := dto.Campaign{
		CampaignID:  "camp-1",
		TenantID:    "acme",
		Name:        "Q2 phishing",
		TemplateID:  "tmpl-1",
		Difficulty:  dto.DifficultyMedium,
		Status:      dto.CampaignActive,
		CreatedAt:   started,
		ScheduledAt: started,
		StartedAt:   &started,
		TargetCount: 200,
		SentCount:   50,
	}
	if err := campaigns.SaveCampaign(ctx, c); err != nil {
		t.Fatalf("SaveCampaign: %v", err)
	}
	got, ok, err := campaigns.LoadCampaign(ctx, c.CampaignID)
	if err != nil {
		t.Fatalf("LoadCampaign: %v", err)
	}
	if !ok {
		t.Fatal("expected campaign found")
	}
	if got.CampaignID != c.CampaignID ||
		got.TenantID != c.TenantID ||
		got.Name != c.Name ||
		got.TemplateID != c.TemplateID ||
		got.Difficulty != c.Difficulty ||
		got.Status != c.Status ||
		got.TargetCount != c.TargetCount ||
		got.SentCount != c.SentCount {
		t.Fatalf("round-trip mismatch:\n want %+v\n got  %+v", c, got)
	}
	if got.StartedAt == nil || !got.StartedAt.Equal(started) {
		t.Fatalf("started_at mismatch: want %v got %v", started, got.StartedAt)
	}
}

func TestPostgresCampaignStore_SaveIsUpsert(t *testing.T) {
	_, campaigns, _ := openEducationDB(t)
	ctx := context.Background()
	base := dto.Campaign{
		CampaignID: "camp-upsert",
		TenantID:   "acme",
		Name:       "v1",
		Difficulty: dto.DifficultyEasy,
		Status:     dto.CampaignDraft,
		CreatedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := campaigns.SaveCampaign(ctx, base); err != nil {
		t.Fatalf("SaveCampaign v1: %v", err)
	}
	base.Name = "v2"
	base.Status = dto.CampaignActive
	base.TargetCount = 99
	if err := campaigns.SaveCampaign(ctx, base); err != nil {
		t.Fatalf("SaveCampaign v2: %v", err)
	}
	got, ok, err := campaigns.LoadCampaign(ctx, base.CampaignID)
	if err != nil || !ok {
		t.Fatalf("LoadCampaign: ok=%v err=%v", ok, err)
	}
	if got.Name != "v2" || got.Status != dto.CampaignActive || got.TargetCount != 99 {
		t.Fatalf("upsert did not overwrite previous row: %+v", got)
	}
}

func TestPostgresCampaignStore_ListFiltersByTenant(t *testing.T) {
	_, campaigns, _ := openEducationDB(t)
	ctx := context.Background()
	seed := []dto.Campaign{
		{CampaignID: "a-1", TenantID: "acme", Name: "a1", Difficulty: dto.DifficultyEasy, Status: dto.CampaignDraft, CreatedAt: time.Now().UTC()},
		{CampaignID: "a-2", TenantID: "acme", Name: "a2", Difficulty: dto.DifficultyEasy, Status: dto.CampaignDraft, CreatedAt: time.Now().UTC()},
		{CampaignID: "b-1", TenantID: "beta", Name: "b1", Difficulty: dto.DifficultyEasy, Status: dto.CampaignDraft, CreatedAt: time.Now().UTC()},
	}
	for _, c := range seed {
		if err := campaigns.SaveCampaign(ctx, c); err != nil {
			t.Fatalf("seed %s: %v", c.CampaignID, err)
		}
	}
	got, err := campaigns.ListCampaigns(ctx, "acme")
	if err != nil {
		t.Fatalf("ListCampaigns acme: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 acme campaigns, got %d (%+v)", len(got), ids(got))
	}
	for _, c := range got {
		if c.TenantID != "acme" {
			t.Fatalf("ListCampaigns returned %q for tenant filter \"acme\"", c.TenantID)
		}
	}
	gotBeta, err := campaigns.ListCampaigns(ctx, "beta")
	if err != nil {
		t.Fatalf("ListCampaigns beta: %v", err)
	}
	if len(gotBeta) != 1 || gotBeta[0].CampaignID != "b-1" {
		t.Fatalf("expected only b-1 for beta, got %+v", ids(gotBeta))
	}
}

func ids(cs []dto.Campaign) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.CampaignID
	}
	return out
}
