package relationship

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// VendorApprovalStatus represents the approval state of a vendor proposal.
type VendorApprovalStatus string

const (
	VendorStatusPending  VendorApprovalStatus = "pending_approval"
	VendorStatusApproved VendorApprovalStatus = "approved"
	VendorStatusRejected VendorApprovalStatus = "rejected"
)

// VendorApprovalRecord tracks a vendor proposal through the approval process.
type VendorApprovalRecord struct {
	TenantID   string               `json:"tenant_id"`
	Domain     string               `json:"domain"`
	Confidence float64              `json:"confidence"`
	Status     VendorApprovalStatus `json:"status"`
	Proposal   VendorProposal       `json:"proposal"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
	ApprovedBy string               `json:"approved_by,omitempty"`
}

// VendorApprovalStore persists vendor approval records.
type VendorApprovalStore interface {
	Save(ctx context.Context, record VendorApprovalRecord) error
	Get(ctx context.Context, tenantID, domain string) (VendorApprovalRecord, error)
	List(ctx context.Context, tenantID string, status VendorApprovalStatus) ([]VendorApprovalRecord, error)
	Update(ctx context.Context, tenantID, domain string, status VendorApprovalStatus, approvedBy string) error
}

// MemoryVendorApprovalStore is an in-memory implementation for dev/test.
type MemoryVendorApprovalStore struct {
	mu      sync.RWMutex
	records map[string]VendorApprovalRecord // keyed by tenant:domain
}

// NewMemoryVendorApprovalStore creates a new in-memory store.
func NewMemoryVendorApprovalStore() *MemoryVendorApprovalStore {
	return &MemoryVendorApprovalStore{
		records: make(map[string]VendorApprovalRecord),
	}
}

func approvalKey(tenantID, domain string) string { return tenantID + ":" + domain }

func (s *MemoryVendorApprovalStore) Save(_ context.Context, r VendorApprovalRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[approvalKey(r.TenantID, r.Domain)] = r
	return nil
}

func (s *MemoryVendorApprovalStore) Get(_ context.Context, tenantID, domain string) (VendorApprovalRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[approvalKey(tenantID, domain)]
	if !ok {
		return VendorApprovalRecord{}, fmt.Errorf("vendor approval not found: %s/%s", tenantID, domain)
	}
	return r, nil
}

func (s *MemoryVendorApprovalStore) List(_ context.Context, tenantID string, status VendorApprovalStatus) ([]VendorApprovalRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []VendorApprovalRecord
	for _, r := range s.records {
		if r.TenantID == tenantID && (status == "" || r.Status == status) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *MemoryVendorApprovalStore) Update(_ context.Context, tenantID, domain string, status VendorApprovalStatus, approvedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := approvalKey(tenantID, domain)
	r, ok := s.records[key]
	if !ok {
		return fmt.Errorf("vendor approval not found: %s/%s", tenantID, domain)
	}
	r.Status = status
	r.ApprovedBy = approvedBy
	r.UpdatedAt = time.Now().UTC()
	s.records[key] = r
	return nil
}

// VendorApprovalGate intercepts VendorProposals and routes them
// through a human approval workflow when confidence is above the
// auto-approve threshold but the gate is enabled.
type VendorApprovalGate struct {
	Discovery   *VendorDiscovery
	Store       VendorApprovalStore
	Publisher   events.EventService
	Logger      *slog.Logger
	RequireGate bool // when true, proposals emit pending_approval instead of auto-approving
}

// ProposeWithGate runs vendor discovery and applies the approval gate.
// High-confidence proposals are held for human approval instead of
// being auto-approved when RequireGate is true.
func (g *VendorApprovalGate) ProposeWithGate(ctx context.Context, tenantID string, observations []SenderObservation) ([]VendorProposal, error) {
	proposals, err := g.Discovery.Propose(ctx, tenantID, observations)
	if err != nil {
		return nil, err
	}

	if !g.RequireGate {
		return proposals, nil
	}

	now := time.Now().UTC()
	for i, p := range proposals {
		if p.AutoApprove {
			// Hold for human approval instead of auto-approving.
			proposals[i].AutoApprove = false

			record := VendorApprovalRecord{
				TenantID:   tenantID,
				Domain:     p.Domain,
				Confidence: p.Confidence,
				Status:     VendorStatusPending,
				Proposal:   p,
				CreatedAt:  now,
				UpdatedAt:  now,
			}
			if serr := g.Store.Save(ctx, record); serr != nil {
				g.Logger.Warn("vendor_approval: save failed",
					slog.String("tenant", tenantID),
					slog.String("domain", p.Domain),
					slog.Any("error", serr))
				continue
			}

			// Emit pending approval event.
			g.emitPendingApproval(ctx, tenantID, p)
		}
	}
	return proposals, nil
}

// ApproveVendor approves a pending vendor and emits the approval event.
func (g *VendorApprovalGate) ApproveVendor(ctx context.Context, tenantID, domain, approvedBy string) error {
	if tenantID == "" || domain == "" {
		return errors.New("vendor_approval: tenant_id and domain are required")
	}

	record, err := g.Store.Get(ctx, tenantID, domain)
	if err != nil {
		return fmt.Errorf("vendor_approval: %w", err)
	}
	if record.Status != VendorStatusPending {
		return fmt.Errorf("vendor_approval: vendor %s is not pending (current: %s)", domain, record.Status)
	}

	if err := g.Store.Update(ctx, tenantID, domain, VendorStatusApproved, approvedBy); err != nil {
		return fmt.Errorf("vendor_approval: update failed: %w", err)
	}

	g.emitApproval(ctx, tenantID, domain, approvedBy)
	return nil
}

// RejectVendor rejects a pending vendor.
func (g *VendorApprovalGate) RejectVendor(ctx context.Context, tenantID, domain, rejectedBy string) error {
	if tenantID == "" || domain == "" {
		return errors.New("vendor_approval: tenant_id and domain are required")
	}

	record, err := g.Store.Get(ctx, tenantID, domain)
	if err != nil {
		return fmt.Errorf("vendor_approval: %w", err)
	}
	if record.Status != VendorStatusPending {
		return fmt.Errorf("vendor_approval: vendor %s is not pending (current: %s)", domain, record.Status)
	}

	if err := g.Store.Update(ctx, tenantID, domain, VendorStatusRejected, rejectedBy); err != nil {
		return fmt.Errorf("vendor_approval: update failed: %w", err)
	}

	return nil
}

// ListPendingApprovals returns all pending vendor approvals for a tenant.
func (g *VendorApprovalGate) ListPendingApprovals(ctx context.Context, tenantID string) ([]VendorApprovalRecord, error) {
	return g.Store.List(ctx, tenantID, VendorStatusPending)
}

func (g *VendorApprovalGate) emitPendingApproval(ctx context.Context, tenantID string, p VendorProposal) {
	if g.Publisher == nil {
		return
	}
	blob, err := json.Marshal(struct {
		TenantID string         `json:"tenant_id"`
		Proposal VendorProposal `json:"proposal"`
	}{
		TenantID: tenantID,
		Proposal: p,
	})
	if err != nil {
		return
	}
	if perr := g.Publisher.Publish(ctx, "es.relationship.vendor.pending_approval", blob,
		events.WithTenantID(tenantID),
		events.WithEventType("vendor.pending_approval"),
	); perr != nil {
		g.Logger.Warn("vendor_approval: publish pending failed", slog.Any("error", perr))
	}
}

func (g *VendorApprovalGate) emitApproval(ctx context.Context, tenantID, domain, approvedBy string) {
	if g.Publisher == nil {
		return
	}
	blob, err := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		Domain     string `json:"domain"`
		ApprovedBy string `json:"approved_by"`
	}{
		TenantID:   tenantID,
		Domain:     domain,
		ApprovedBy: approvedBy,
	})
	if err != nil {
		return
	}
	if perr := g.Publisher.Publish(ctx, "es.relationship.vendor.approved", blob,
		events.WithTenantID(tenantID),
		events.WithEventType("vendor.approved"),
	); perr != nil {
		g.Logger.Warn("vendor_approval: publish approval failed", slog.Any("error", perr))
	}
}
