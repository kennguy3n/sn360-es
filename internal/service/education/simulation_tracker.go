package education

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// InteractionStore is the persistence surface for per-campaign user
// interactions. Implementations only need to be append-friendly and
// support range queries by campaign.
type InteractionStore interface {
	Append(ctx context.Context, i dto.UserInteraction) error
	ListByCampaign(ctx context.Context, campaignID string) ([]dto.UserInteraction, error)
}

// TrackerConfig wires the SimulationTracker.
type TrackerConfig struct {
	Store     InteractionStore
	Publisher events.EventService
	Logger    *slog.Logger
	Clock     func() time.Time
}

// SimulationTracker records user interactions with simulation messages
// and publishes them on the event bus. It is intentionally distinct
// from the SimulationEngine so a downstream consumer (e.g. a webhook
// listener) can record interactions without depending on the engine.
type SimulationTracker struct {
	store InteractionStore
	pub   events.EventService
	log   *slog.Logger
	now   func() time.Time
}

// NewSimulationTracker constructs the tracker. Store is required.
func NewSimulationTracker(cfg TrackerConfig) (*SimulationTracker, error) {
	if cfg.Store == nil {
		return nil, errors.New("education: tracker requires Store")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &SimulationTracker{
		store: cfg.Store,
		pub:   cfg.Publisher,
		log:   cfg.Logger,
		now:   cfg.Clock,
	}, nil
}

// RecordInteraction validates and persists a single interaction, then
// publishes it on es.education.simulation.result.
func (t *SimulationTracker) RecordInteraction(ctx context.Context, campaignID, userHash string, action dto.UserInteractionType) (dto.UserInteraction, error) {
	if campaignID == "" {
		return dto.UserInteraction{}, errors.New("education: campaign_id is required")
	}
	if userHash == "" {
		return dto.UserInteraction{}, errors.New("education: user_hash is required")
	}
	if !action.Valid() {
		return dto.UserInteraction{}, fmt.Errorf("education: invalid interaction %q", action)
	}
	i := dto.UserInteraction{
		CampaignID: campaignID,
		UserHash:   userHash,
		Action:     action,
		OccurredAt: t.now(),
	}
	if err := t.store.Append(ctx, i); err != nil {
		return dto.UserInteraction{}, fmt.Errorf("education: append interaction: %w", err)
	}
	if t.pub != nil {
		payload, err := json.Marshal(i)
		if err == nil {
			if perr := t.pub.Publish(ctx, "es.education.simulation.result", payload,
				events.WithEventType("education.simulation.result"),
			); perr != nil {
				t.log.WarnContext(ctx, "education: publish interaction",
					slog.String("campaign_id", campaignID),
					slog.Any("error", perr),
				)
			}
		}
	}
	return i, nil
}

// Aggregate computes per-action counts for a campaign.
func (t *SimulationTracker) Aggregate(ctx context.Context, campaignID string) (dto.SimulationResult, error) {
	if campaignID == "" {
		return dto.SimulationResult{}, errors.New("education: campaign_id is required")
	}
	items, err := t.store.ListByCampaign(ctx, campaignID)
	if err != nil {
		return dto.SimulationResult{}, fmt.Errorf("education: list interactions: %w", err)
	}
	out := dto.SimulationResult{CampaignID: campaignID}
	for _, i := range items {
		switch i.Action {
		case dto.InteractionDelivered:
			out.Delivered++
		case dto.InteractionOpened:
			out.Opened++
		case dto.InteractionClickedLink:
			out.Clicked++
		case dto.InteractionSubmittedCredentials:
			out.SubmittedCredentials++
		case dto.InteractionReportedPhishing:
			out.Reported++
		case dto.InteractionIgnored:
			out.Ignored++
		}
	}
	return out, nil
}

// --- In-memory store --------------------------------------------------------

// MemoryInteractionStore is a goroutine-safe in-memory InteractionStore.
type MemoryInteractionStore struct {
	mu    sync.RWMutex
	items map[string][]dto.UserInteraction
}

// NewMemoryInteractionStore returns an empty store.
func NewMemoryInteractionStore() *MemoryInteractionStore {
	return &MemoryInteractionStore{items: map[string][]dto.UserInteraction{}}
}

// Append implements InteractionStore.
func (s *MemoryInteractionStore) Append(_ context.Context, i dto.UserInteraction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[i.CampaignID] = append(s.items[i.CampaignID], i)
	return nil
}

// ListByCampaign implements InteractionStore.
func (s *MemoryInteractionStore) ListByCampaign(_ context.Context, campaignID string) ([]dto.UserInteraction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	in := s.items[campaignID]
	out := make([]dto.UserInteraction, len(in))
	copy(out, in)
	return out, nil
}
