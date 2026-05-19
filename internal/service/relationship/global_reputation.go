package relationship

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// GlobalReputationConfig wires the cross-tenant sender reputation service.
type GlobalReputationConfig struct {
	Logger *slog.Logger
	Clock  func() time.Time
	// WindowDays is the trailing window for reputation aggregation.
	// Defaults to 30.
	WindowDays int
	// FlagThreshold is the fraction of tenants flagging a domain
	// above which it is considered suspicious. Defaults to 0.10 (10%).
	FlagThreshold float64
}

// DomainReputation is the anonymized cross-tenant reputation for a
// sender domain.
type DomainReputation struct {
	Domain          string    `json:"domain"`
	Score           float64   `json:"score"` // 0.0 (clean) to 1.0 (malicious)
	TenantsFlagged  int       `json:"tenants_flagged"`
	TenantsTotal    int       `json:"tenants_total"`
	FlaggedFraction float64   `json:"flagged_fraction"`
	LastUpdated     time.Time `json:"last_updated"`
}

// ReputationStore persists cross-tenant reputation data. All methods
// are tenant-agnostic — they aggregate across the entire platform.
type ReputationStore interface {
	// RecordFlag records that a tenant flagged a domain. The
	// implementation must de-duplicate per (tenant, domain, window).
	RecordFlag(ctx context.Context, domain, tenantID string, at time.Time) error
	// GetReputation returns the aggregated reputation for a domain.
	GetReputation(ctx context.Context, domain string) (DomainReputation, error)
	// TopSuspicious returns the N most flagged domains in the current window.
	TopSuspicious(ctx context.Context, limit int) ([]DomainReputation, error)
	// TotalTenants returns the total number of active tenants.
	TotalTenants(ctx context.Context) (int, error)
}

// MemoryReputationStore is an in-memory implementation for dev/test.
type MemoryReputationStore struct {
	mu      sync.RWMutex
	flags   map[string]map[string]time.Time // domain -> tenant -> first_flag_at
	tenants map[string]struct{}
}

// NewMemoryReputationStore creates a new in-memory store.
func NewMemoryReputationStore() *MemoryReputationStore {
	return &MemoryReputationStore{
		flags:   make(map[string]map[string]time.Time),
		tenants: make(map[string]struct{}),
	}
}

func (s *MemoryReputationStore) RecordFlag(_ context.Context, domain, tenantID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[tenantID] = struct{}{}
	if _, ok := s.flags[domain]; !ok {
		s.flags[domain] = make(map[string]time.Time)
	}
	if _, exists := s.flags[domain][tenantID]; !exists {
		s.flags[domain][tenantID] = at
	}
	return nil
}

func (s *MemoryReputationStore) GetReputation(_ context.Context, domain string) (DomainReputation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	flagged := len(s.flags[domain])
	total := len(s.tenants)
	if total == 0 {
		total = 1
	}
	frac := float64(flagged) / float64(total)
	return DomainReputation{
		Domain:          domain,
		Score:           frac,
		TenantsFlagged:  flagged,
		TenantsTotal:    total,
		FlaggedFraction: frac,
		LastUpdated:     time.Now().UTC(),
	}, nil
}

func (s *MemoryReputationStore) TopSuspicious(_ context.Context, limit int) ([]DomainReputation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := len(s.tenants)
	if total == 0 {
		total = 1
	}
	type domCount struct {
		domain string
		count  int
	}
	var all []domCount
	for d, tenants := range s.flags {
		all = append(all, domCount{d, len(tenants)})
	}
	// Sort descending by count.
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].count > all[i].count {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	if limit > 0 && limit < len(all) {
		all = all[:limit]
	}
	out := make([]DomainReputation, len(all))
	for i, dc := range all {
		frac := float64(dc.count) / float64(total)
		out[i] = DomainReputation{
			Domain:          dc.domain,
			Score:           frac,
			TenantsFlagged:  dc.count,
			TenantsTotal:    total,
			FlaggedFraction: frac,
			LastUpdated:     time.Now().UTC(),
		}
	}
	return out, nil
}

func (s *MemoryReputationStore) TotalTenants(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tenants), nil
}

// GlobalReputationService manages cross-tenant sender-domain reputation.
// It aggregates threat flags from all tenants and computes an anonymized
// reputation score for each sender domain.
type GlobalReputationService struct {
	store     ReputationStore
	log       *slog.Logger
	now       func() time.Time
	threshold float64
}

// NewGlobalReputationService constructs the service.
func NewGlobalReputationService(cfg GlobalReputationConfig, store ReputationStore) (*GlobalReputationService, error) {
	if store == nil {
		return nil, fmt.Errorf("global_reputation: store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.FlagThreshold <= 0 {
		cfg.FlagThreshold = 0.10
	}
	return &GlobalReputationService{
		store:     store,
		log:       cfg.Logger,
		now:       cfg.Clock,
		threshold: cfg.FlagThreshold,
	}, nil
}

// RecordThreatFlag records that a tenant flagged an email from a domain.
func (s *GlobalReputationService) RecordThreatFlag(ctx context.Context, domain, tenantID string) error {
	return s.store.RecordFlag(ctx, domain, tenantID, s.now())
}

// GetDomainReputation returns the cross-tenant reputation for a domain.
func (s *GlobalReputationService) GetDomainReputation(ctx context.Context, domain string) (DomainReputation, error) {
	return s.store.GetReputation(ctx, domain)
}

// IsSuspicious returns true if the domain has been flagged by more than
// FlagThreshold of all tenants.
func (s *GlobalReputationService) IsSuspicious(ctx context.Context, domain string) (bool, float64, error) {
	rep, err := s.store.GetReputation(ctx, domain)
	if err != nil {
		return false, 0, err
	}
	return rep.FlaggedFraction >= s.threshold, rep.Score, nil
}

// TopSuspiciousDomains returns the N most flagged domains.
func (s *GlobalReputationService) TopSuspiciousDomains(ctx context.Context, limit int) ([]DomainReputation, error) {
	return s.store.TopSuspicious(ctx, limit)
}

// compile-time assertions
var _ ReputationStore = (*MemoryReputationStore)(nil)
