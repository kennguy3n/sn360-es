package education

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// CampaignStore is the persistence surface for simulation campaigns.
// Implementations can be in-memory (tests), Redis, or Postgres.
type CampaignStore interface {
	SaveCampaign(ctx context.Context, c dto.Campaign) error
	LoadCampaign(ctx context.Context, id string) (dto.Campaign, bool, error)
	ListCampaigns(ctx context.Context, tenantID string) ([]dto.Campaign, error)
}

// SimulationSender is the side-effect interface that actually mails the
// rendered simulation to a target. In production this is wired to a
// throttled SMTP or Graph API client.
type SimulationSender interface {
	Send(ctx context.Context, target SimulationTarget, rendered dto.RenderedSimulation) error
}

// SimulationTarget is the pseudonymised recipient envelope passed to a
// SimulationSender. We carry the user_hash + mailbox alias rather than
// PII so the engine never needs raw recipient PII in transit.
type SimulationTarget struct {
	UserHash     string
	MailboxAlias string
	DisplayName  string
}

// EngineConfig wires the SimulationEngine.
type EngineConfig struct {
	Store     CampaignStore
	Templates *TemplateLibrary
	Sender    SimulationSender
	Publisher events.EventService
	Logger    *slog.Logger
	// Clock is overridable for deterministic tests.
	Clock func() time.Time
}

// SimulationEngine creates and executes phishing-simulation campaigns.
type SimulationEngine struct {
	store     CampaignStore
	templates *TemplateLibrary
	sender    SimulationSender
	pub       events.EventService
	log       *slog.Logger
	now       func() time.Time
}

// NewSimulationEngine constructs the engine. Store + Templates are
// required; Sender + Publisher are optional (the engine will skip the
// corresponding side-effects when nil).
func NewSimulationEngine(cfg EngineConfig) (*SimulationEngine, error) {
	if cfg.Store == nil {
		return nil, errors.New("education: simulation engine requires Store")
	}
	if cfg.Templates == nil {
		return nil, errors.New("education: simulation engine requires Templates")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &SimulationEngine{
		store:     cfg.Store,
		templates: cfg.Templates,
		sender:    cfg.Sender,
		pub:       cfg.Publisher,
		log:       cfg.Logger,
		now:       cfg.Clock,
	}, nil
}

// CampaignConfig is the inbound spec for CreateCampaign.
type CampaignConfig struct {
	TenantID    string
	Name        string
	TemplateID  string
	Difficulty  dto.DifficultyLevel
	ScheduledAt time.Time
	TargetCount int
}

// CreateCampaign reserves a campaign ID, validates the template, and
// persists the campaign in CampaignDraft state.
func (e *SimulationEngine) CreateCampaign(ctx context.Context, cfg CampaignConfig) (dto.Campaign, error) {
	if cfg.TenantID == "" {
		return dto.Campaign{}, errors.New("education: tenant_id is required")
	}
	if cfg.Name == "" {
		return dto.Campaign{}, errors.New("education: campaign name is required")
	}
	tmpl, ok := e.templates.Get(cfg.TemplateID)
	if !ok {
		return dto.Campaign{}, fmt.Errorf("education: unknown template %q", cfg.TemplateID)
	}
	if cfg.Difficulty == "" {
		cfg.Difficulty = tmpl.Difficulty
	}
	if !cfg.Difficulty.Valid() {
		return dto.Campaign{}, fmt.Errorf("education: invalid difficulty %q", cfg.Difficulty)
	}
	if cfg.TargetCount < 0 {
		return dto.Campaign{}, errors.New("education: target_count must be >= 0")
	}
	now := e.now()
	if cfg.ScheduledAt.IsZero() {
		cfg.ScheduledAt = now
	}
	campaign := dto.Campaign{
		CampaignID:  newCampaignID(),
		TenantID:    cfg.TenantID,
		Name:        cfg.Name,
		TemplateID:  cfg.TemplateID,
		Difficulty:  cfg.Difficulty,
		Status:      dto.CampaignDraft,
		CreatedAt:   now,
		ScheduledAt: cfg.ScheduledAt,
		TargetCount: cfg.TargetCount,
	}
	if err := e.store.SaveCampaign(ctx, campaign); err != nil {
		return dto.Campaign{}, fmt.Errorf("education: persist campaign: %w", err)
	}
	return campaign, nil
}

// SendSimulation renders the template for each target and dispatches via
// the configured Sender. The campaign moves through Scheduled → Sending
// → Active. Per-target errors are recorded but do not abort the batch.
func (e *SimulationEngine) SendSimulation(ctx context.Context, campaignID string, targets []SimulationTarget, params map[string]string) (dto.SimulationResult, error) {
	if campaignID == "" {
		return dto.SimulationResult{}, errors.New("education: campaign_id is required")
	}
	c, ok, err := e.store.LoadCampaign(ctx, campaignID)
	if err != nil {
		return dto.SimulationResult{}, fmt.Errorf("education: load campaign: %w", err)
	}
	if !ok {
		return dto.SimulationResult{}, fmt.Errorf("education: campaign %q not found", campaignID)
	}
	c.Status = dto.CampaignSending
	c.SentCount = 0
	startedAt := e.now()
	c.StartedAt = &startedAt
	if c.TargetCount == 0 {
		c.TargetCount = len(targets)
	}
	if err := e.store.SaveCampaign(ctx, c); err != nil {
		return dto.SimulationResult{}, fmt.Errorf("education: persist sending state: %w", err)
	}
	result := dto.SimulationResult{CampaignID: campaignID}
	for _, target := range targets {
		rendered, err := e.templates.Render(c.TemplateID, params)
		if err != nil {
			e.log.WarnContext(ctx, "education: render failed",
				slog.String("campaign_id", campaignID),
				slog.String("template_id", c.TemplateID),
				slog.Any("error", err),
			)
			continue
		}
		if e.sender != nil {
			if err := e.sender.Send(ctx, target, rendered); err != nil {
				e.log.WarnContext(ctx, "education: send failed",
					slog.String("campaign_id", campaignID),
					slog.String("user_hash", target.UserHash),
					slog.Any("error", err),
				)
				continue
			}
		}
		c.SentCount++
		result.Delivered++
		e.publishInteraction(ctx, dto.UserInteraction{
			CampaignID: campaignID,
			UserHash:   target.UserHash,
			Action:     dto.InteractionDelivered,
			OccurredAt: e.now(),
		})
	}
	c.Status = dto.CampaignActive
	if err := e.store.SaveCampaign(ctx, c); err != nil {
		return result, fmt.Errorf("education: persist active state: %w", err)
	}
	return result, nil
}

func (e *SimulationEngine) publishInteraction(ctx context.Context, i dto.UserInteraction) {
	if e.pub == nil {
		return
	}
	payload, err := json.Marshal(i)
	if err != nil {
		e.log.WarnContext(ctx, "education: marshal interaction", slog.Any("error", err))
		return
	}
	if err := e.pub.Publish(ctx, "es.education.simulation.result", payload,
		events.WithEventType("education.simulation.result"),
	); err != nil {
		e.log.WarnContext(ctx, "education: publish interaction", slog.Any("error", err))
	}
}

// CompleteCampaign closes the campaign and records its completion time.
func (e *SimulationEngine) CompleteCampaign(ctx context.Context, campaignID string) error {
	c, ok, err := e.store.LoadCampaign(ctx, campaignID)
	if err != nil {
		return fmt.Errorf("education: load campaign: %w", err)
	}
	if !ok {
		return fmt.Errorf("education: campaign %q not found", campaignID)
	}
	if c.Status == dto.CampaignCompleted || c.Status == dto.CampaignCancelled {
		return nil
	}
	completed := e.now()
	c.Status = dto.CampaignCompleted
	c.CompletedAt = &completed
	return e.store.SaveCampaign(ctx, c)
}

func newCampaignID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failures are catastrophic; fall back to a
		// timestamp-derived value so callers don't observe an empty ID.
		return fmt.Sprintf("camp-%d", time.Now().UnixNano())
	}
	return "camp-" + hex.EncodeToString(b[:])
}

// --- In-memory store --------------------------------------------------------

// MemoryCampaignStore is a goroutine-safe in-memory CampaignStore
// suitable for tests and small single-process deployments.
type MemoryCampaignStore struct {
	mu        sync.RWMutex
	campaigns map[string]dto.Campaign
}

// NewMemoryCampaignStore returns an empty MemoryCampaignStore.
func NewMemoryCampaignStore() *MemoryCampaignStore {
	return &MemoryCampaignStore{campaigns: map[string]dto.Campaign{}}
}

// SaveCampaign implements CampaignStore.
func (s *MemoryCampaignStore) SaveCampaign(_ context.Context, c dto.Campaign) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.campaigns[c.CampaignID] = c
	return nil
}

// LoadCampaign implements CampaignStore.
func (s *MemoryCampaignStore) LoadCampaign(_ context.Context, id string) (dto.Campaign, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.campaigns[id]
	return c, ok, nil
}

// ListCampaigns implements CampaignStore.
func (s *MemoryCampaignStore) ListCampaigns(_ context.Context, tenantID string) ([]dto.Campaign, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]dto.Campaign, 0, len(s.campaigns))
	for _, c := range s.campaigns {
		if tenantID != "" && c.TenantID != tenantID {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}
