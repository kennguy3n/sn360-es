package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// TuningApprovalStatus is the state of a proposed tuning change.
type TuningApprovalStatus string

const (
	TuningProposed TuningApprovalStatus = "proposed"
	TuningApproved TuningApprovalStatus = "approved"
	TuningRejected TuningApprovalStatus = "rejected"
)

// TuningProposal holds a proposed weight/threshold change that
// requires admin approval before being applied.
type TuningProposal struct {
	ID            string               `json:"id"`
	TenantID      string               `json:"tenant_id"`
	Status        TuningApprovalStatus `json:"status"`
	Decision      TuningDecision       `json:"decision"`
	ProposedAt    time.Time            `json:"proposed_at"`
	ReviewedAt    *time.Time           `json:"reviewed_at,omitempty"`
	ReviewedBy    string               `json:"reviewed_by,omitempty"`
}

// TuningProposalStore persists tuning proposals.
type TuningProposalStore interface {
	Save(ctx context.Context, proposal TuningProposal) error
	Get(ctx context.Context, id string) (TuningProposal, error)
	ListPending(ctx context.Context, tenantID string) ([]TuningProposal, error)
	Update(ctx context.Context, id string, status TuningApprovalStatus, reviewedBy string) error
}

// MemoryTuningProposalStore is an in-memory implementation for dev/test.
type MemoryTuningProposalStore struct {
	mu        sync.RWMutex
	proposals map[string]TuningProposal
}

// NewMemoryTuningProposalStore creates a new in-memory store.
func NewMemoryTuningProposalStore() *MemoryTuningProposalStore {
	return &MemoryTuningProposalStore{
		proposals: make(map[string]TuningProposal),
	}
}

func (s *MemoryTuningProposalStore) Save(_ context.Context, p TuningProposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proposals[p.ID] = p
	return nil
}

func (s *MemoryTuningProposalStore) Get(_ context.Context, id string) (TuningProposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.proposals[id]
	if !ok {
		return TuningProposal{}, fmt.Errorf("tuning_approval: proposal not found: %s", id)
	}
	return p, nil
}

func (s *MemoryTuningProposalStore) ListPending(_ context.Context, tenantID string) ([]TuningProposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []TuningProposal
	for _, p := range s.proposals {
		if p.TenantID == tenantID && p.Status == TuningProposed {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *MemoryTuningProposalStore) Update(_ context.Context, id string, status TuningApprovalStatus, reviewedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.proposals[id]
	if !ok {
		return fmt.Errorf("tuning_approval: proposal not found: %s", id)
	}
	now := time.Now().UTC()
	p.Status = status
	p.ReviewedBy = reviewedBy
	p.ReviewedAt = &now
	s.proposals[id] = p
	return nil
}

// ApprovalGatedTuningConfig extends TuningConfig with approval mode.
type ApprovalGatedTuningConfig struct {
	TuningConfig
	// RequireApproval controls whether changes are auto-applied or held
	// for admin confirmation. When true, proposed changes emit
	// es.agent.tuning.proposed instead of being applied immediately.
	RequireApproval bool
	// ForceApprovalDelta is the maximum delta (for any single weight or
	// threshold) above which approval is always required regardless of
	// RequireApproval. Defaults to 0.03 for weights and 3 for thresholds.
	ForceApprovalWeightDelta    float64
	ForceApprovalThresholdDelta int
	// Proposals is the store for pending proposals.
	Proposals TuningProposalStore
	// Publisher emits events for proposed changes.
	Publisher events.EventService
}

// ApprovalGatedTuningAgent wraps TuningAgent with an approval gate.
type ApprovalGatedTuningAgent struct {
	inner    *TuningAgent
	cfg      ApprovalGatedTuningConfig
	store    TuningProposalStore
	pub      events.EventService
	log      *slog.Logger
	counter  uint64
	mu       sync.Mutex
}

// NewApprovalGatedTuningAgent constructs the gated agent.
func NewApprovalGatedTuningAgent(cfg ApprovalGatedTuningConfig) (*ApprovalGatedTuningAgent, error) {
	inner, err := NewTuningAgent(cfg.TuningConfig)
	if err != nil {
		return nil, err
	}
	if cfg.Proposals == nil {
		cfg.Proposals = NewMemoryTuningProposalStore()
	}
	if cfg.ForceApprovalWeightDelta <= 0 {
		cfg.ForceApprovalWeightDelta = 0.03
	}
	if cfg.ForceApprovalThresholdDelta <= 0 {
		cfg.ForceApprovalThresholdDelta = 3
	}
	log := cfg.TuningConfig.Logger
	if log == nil {
		log = slog.Default()
	}
	return &ApprovalGatedTuningAgent{
		inner: inner,
		cfg:   cfg,
		store: cfg.Proposals,
		pub:   cfg.Publisher,
		log:   log,
	}, nil
}

// Tune runs the decision logic and either applies immediately or holds
// for approval based on configuration and delta magnitude.
func (a *ApprovalGatedTuningAgent) Tune(ctx context.Context, tenantID string) (TuningDecision, error) {
	// Get the snapshot to compute the decision WITHOUT applying.
	snap, err := a.inner.BuildSnapshot(ctx, tenantID)
	if err != nil {
		return TuningDecision{}, err
	}
	decision := a.inner.Decide(snap)
	decision.TenantID = tenantID
	decision.DecidedAt = time.Now().UTC()

	if decision.NewWeights == nil && decision.NewThresholds == nil {
		return decision, nil
	}

	needsApproval := a.cfg.RequireApproval || a.exceedsForceDelta(snap, decision)

	if needsApproval {
		return a.holdForApproval(ctx, tenantID, decision)
	}

	// Auto-apply using the snapshot we already have, avoiding a second
	// store round-trip and the TOCTOU window that re-fetching would create.
	if err := a.inner.ApplyDecision(ctx, snap, decision); err != nil {
		return decision, err
	}
	return decision, nil
}

func (a *ApprovalGatedTuningAgent) exceedsForceDelta(snap TuningSnapshot, decision TuningDecision) bool {
	if decision.NewWeights != nil {
		w := snap.CurrentWeights
		nw := *decision.NewWeights
		maxDelta := maxAbs(w.AI-nw.AI, w.Rspamd-nw.Rspamd, w.Attachments-nw.Attachments, w.Links-nw.Links)
		if maxDelta > a.cfg.ForceApprovalWeightDelta {
			return true
		}
	}
	if decision.NewThresholds != nil {
		t := snap.CurrentThresholds
		nt := *decision.NewThresholds
		maxDelta := maxAbsInt(
			t.BannerWarning-nt.BannerWarning,
			t.BannerCaution-nt.BannerCaution,
			t.BannerHighRisk-nt.BannerHighRisk,
			t.BannerBlocked-nt.BannerBlocked,
			t.BannerInfo-nt.BannerInfo,
		)
		if maxDelta > a.cfg.ForceApprovalThresholdDelta {
			return true
		}
	}
	return false
}

func (a *ApprovalGatedTuningAgent) holdForApproval(ctx context.Context, tenantID string, decision TuningDecision) (TuningDecision, error) {
	a.mu.Lock()
	a.counter++
	id := fmt.Sprintf("tp-%s-%d", tenantID, a.counter)
	a.mu.Unlock()

	proposal := TuningProposal{
		ID:         id,
		TenantID:   tenantID,
		Status:     TuningProposed,
		Decision:   decision,
		ProposedAt: time.Now().UTC(),
	}
	if err := a.store.Save(ctx, proposal); err != nil {
		return decision, fmt.Errorf("tuning_approval: save: %w", err)
	}

	if a.pub != nil {
		blob, _ := json.Marshal(proposal)
		_ = a.pub.Publish(ctx, "es.agent.tuning.proposed", blob,
			events.WithTenantID(tenantID),
			events.WithEventType("agent.tuning.proposed"),
		)
	}

	decision.Notes = append(decision.Notes, fmt.Sprintf("held for approval (proposal_id=%s)", id))
	a.log.InfoContext(ctx, "tuning_approval: proposal held",
		slog.String("tenant", tenantID),
		slog.String("proposal_id", id))

	return decision, nil
}

// ApproveProposal approves a pending proposal and applies the changes.
func (a *ApprovalGatedTuningAgent) ApproveProposal(ctx context.Context, proposalID, approvedBy string) error {
	proposal, err := a.store.Get(ctx, proposalID)
	if err != nil {
		return err
	}
	if proposal.Status != TuningProposed {
		return fmt.Errorf("tuning_approval: proposal %s is not pending (status=%s)", proposalID, proposal.Status)
	}

	if err := a.store.Update(ctx, proposalID, TuningApproved, approvedBy); err != nil {
		return fmt.Errorf("tuning_approval: update: %w", err)
	}

	dec := proposal.Decision
	if dec.NewWeights != nil {
		if err := a.cfg.TuningConfig.Config.UpdateWeights(ctx, proposal.TenantID, *dec.NewWeights); err != nil {
			return fmt.Errorf("tuning_approval: apply weights: %w", err)
		}
	}
	if dec.NewThresholds != nil {
		if err := a.cfg.TuningConfig.Config.UpdateThresholds(ctx, proposal.TenantID, *dec.NewThresholds); err != nil {
			return fmt.Errorf("tuning_approval: apply thresholds: %w", err)
		}
	}

	a.log.InfoContext(ctx, "tuning_approval: proposal approved and applied",
		slog.String("proposal_id", proposalID),
		slog.String("approved_by", approvedBy))
	return nil
}

// RejectProposal rejects a pending proposal.
func (a *ApprovalGatedTuningAgent) RejectProposal(ctx context.Context, proposalID, rejectedBy string) error {
	return a.store.Update(ctx, proposalID, TuningRejected, rejectedBy)
}

// ListPendingProposals returns all pending proposals for a tenant.
func (a *ApprovalGatedTuningAgent) ListPendingProposals(ctx context.Context, tenantID string) ([]TuningProposal, error) {
	return a.store.ListPending(ctx, tenantID)
}

func maxAbs(vals ...float64) float64 {
	max := 0.0
	for _, v := range vals {
		if v < 0 {
			v = -v
		}
		if v > max {
			max = v
		}
	}
	return max
}

func maxAbsInt(vals ...int) int {
	max := 0
	for _, v := range vals {
		if v < 0 {
			v = -v
		}
		if v > max {
			max = v
		}
	}
	return max
}
