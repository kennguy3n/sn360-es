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
// interactions.
//
// Semantic contract — all implementations MUST satisfy this so that
// Aggregate's per-action counters are stable across backends and
// under at-least-once event delivery:
//
//   - Append is idempotent per (CampaignID, UserHash, Action). Recording
//     the same action twice for the same target is a no-op on the
//     second call (the first OccurredAt is retained, subsequent
//     observations are dropped). This matches the natural semantic
//     of a phishing-simulation outcome: "did this target open?" is a
//     boolean, not a count — replay of the same NATS message must
//     not inflate the campaign's open rate.
//   - ListByCampaign returns at most one UserInteraction per
//     (UserHash, Action) tuple, in deterministic order. The
//     OccurredAt on each returned entry is the moment the action was
//     FIRST observed for that target.
//
// PostgresInteractionStore satisfies this via its (campaign_id,
// user_hash) primary key + COALESCE-on-upsert; MemoryInteractionStore
// and any in-test stubs must explicitly enforce the same dedup.
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

// memoryKey indexes the (user_hash, action) tuple used for in-memory
// dedup. The campaign id is the outer map key on MemoryInteractionStore.
type memoryKey struct {
	UserHash string
	Action   dto.UserInteractionType
}

// MemoryInteractionStore is a goroutine-safe in-memory InteractionStore.
//
// The store enforces the InteractionStore semantic contract: Append is
// idempotent per (CampaignID, UserHash, Action), and ListByCampaign
// returns at most one entry per (UserHash, Action) tuple. This keeps
// Aggregate's per-action counters stable under at-least-once NATS
// delivery and aligns the in-memory backend with PostgresInteractionStore.
//
// The slice-of-keys preserves first-observed insertion order so callers
// that compare against a deterministic ListByCampaign output (tests,
// snapshot assertions) get stable iteration regardless of Go's
// randomised map traversal.
type MemoryInteractionStore struct {
	mu    sync.RWMutex
	items map[string]map[memoryKey]dto.UserInteraction
	order map[string][]memoryKey
}

// NewMemoryInteractionStore returns an empty store.
func NewMemoryInteractionStore() *MemoryInteractionStore {
	return &MemoryInteractionStore{
		items: map[string]map[memoryKey]dto.UserInteraction{},
		order: map[string][]memoryKey{},
	}
}

// Append implements InteractionStore. Subsequent Append calls with the
// same (CampaignID, UserHash, Action) are dropped — only the first
// observation's OccurredAt is retained, matching the COALESCE-on-upsert
// behaviour of PostgresInteractionStore.
func (s *MemoryInteractionStore) Append(_ context.Context, i dto.UserInteraction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket, ok := s.items[i.CampaignID]
	if !ok {
		bucket = map[memoryKey]dto.UserInteraction{}
		s.items[i.CampaignID] = bucket
	}
	k := memoryKey{UserHash: i.UserHash, Action: i.Action}
	if _, exists := bucket[k]; exists {
		// First-observation wins — drop the replay so Aggregate
		// doesn't double-count under at-least-once delivery.
		return nil
	}
	bucket[k] = i
	s.order[i.CampaignID] = append(s.order[i.CampaignID], k)
	return nil
}

// ListByCampaign implements InteractionStore. Returns deduped entries
// in first-observed insertion order.
func (s *MemoryInteractionStore) ListByCampaign(_ context.Context, campaignID string) ([]dto.UserInteraction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bucket := s.items[campaignID]
	order := s.order[campaignID]
	out := make([]dto.UserInteraction, 0, len(order))
	for _, k := range order {
		if v, ok := bucket[k]; ok {
			out = append(out, v)
		}
	}
	return out, nil
}
