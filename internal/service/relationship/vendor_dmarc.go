package relationship

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// AuthStatus summarises the DMARC/SPF/DKIM health of a vendor domain.
type AuthStatus string

const (
	AuthHealthy  AuthStatus = "healthy"
	AuthDegraded AuthStatus = "degraded"
	AuthFailing  AuthStatus = "failing"
)

// VendorAuthRecord is the per-domain authentication health record.
type VendorAuthRecord struct {
	Domain        string     `json:"domain"`
	TenantID      string     `json:"tenant_id"`
	DMARC         AuthStatus `json:"dmarc"`
	SPF           AuthStatus `json:"spf"`
	DKIM          AuthStatus `json:"dkim"`
	OverallStatus AuthStatus `json:"overall_status"`
	PassCount     int        `json:"pass_count"`
	FailCount     int        `json:"fail_count"`
	TotalCount    int        `json:"total_count"`
	LastChecked   time.Time  `json:"last_checked"`
	LastPassed    time.Time  `json:"last_passed,omitempty"`
	LastFailed    time.Time  `json:"last_failed,omitempty"`
}

// VendorAuthStore persists per-domain auth health records.
type VendorAuthStore interface {
	Save(ctx context.Context, record VendorAuthRecord) error
	Get(ctx context.Context, tenantID, domain string) (VendorAuthRecord, error)
	ListDegraded(ctx context.Context, tenantID string) ([]VendorAuthRecord, error)
}

// MemoryVendorAuthStore is an in-memory implementation for dev/test.
type MemoryVendorAuthStore struct {
	mu      sync.RWMutex
	records map[string]VendorAuthRecord // key: tenantID+":"+domain
}

// NewMemoryVendorAuthStore creates a new in-memory store.
func NewMemoryVendorAuthStore() *MemoryVendorAuthStore {
	return &MemoryVendorAuthStore{
		records: make(map[string]VendorAuthRecord),
	}
}

func (s *MemoryVendorAuthStore) Save(_ context.Context, r VendorAuthRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[r.TenantID+":"+r.Domain] = r
	return nil
}

func (s *MemoryVendorAuthStore) Get(_ context.Context, tenantID, domain string) (VendorAuthRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[tenantID+":"+domain]
	if !ok {
		return VendorAuthRecord{}, fmt.Errorf("vendor_dmarc: record not found: %s/%s", tenantID, domain)
	}
	return r, nil
}

func (s *MemoryVendorAuthStore) ListDegraded(_ context.Context, tenantID string) ([]VendorAuthRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []VendorAuthRecord
	for _, r := range s.records {
		if r.TenantID == tenantID && (r.OverallStatus == AuthDegraded || r.OverallStatus == AuthFailing) {
			out = append(out, r)
		}
	}
	return out, nil
}

// VendorAuthMonitorConfig wires the DMARC/SPF monitoring service.
type VendorAuthMonitorConfig struct {
	Store     VendorAuthStore
	Publisher events.EventService
	Logger    *slog.Logger
	Clock     func() time.Time
	// FailThreshold is the fraction of failing auth checks above which
	// the vendor domain is considered degraded. Defaults to 0.20 (20%).
	FailThreshold float64
	// RevokeThreshold is the fraction of failing auth checks above
	// which trusted status is immediately revoked. Defaults to 0.50 (50%).
	RevokeThreshold float64
}

// VendorAuthMonitor tracks DMARC/SPF/DKIM health for trusted vendor
// domains. When authentication degrades beyond the threshold, it
// immediately revokes trusted status and emits an event.
type VendorAuthMonitor struct {
	store    VendorAuthStore
	pub      events.EventService
	log      *slog.Logger
	now      func() time.Time
	failTh   float64
	revokeTh float64
}

// NewVendorAuthMonitor constructs the monitor.
func NewVendorAuthMonitor(cfg VendorAuthMonitorConfig) (*VendorAuthMonitor, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("vendor_dmarc: store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.FailThreshold <= 0 {
		cfg.FailThreshold = 0.20
	}
	if cfg.RevokeThreshold <= 0 {
		cfg.RevokeThreshold = 0.50
	}
	return &VendorAuthMonitor{
		store:    cfg.Store,
		pub:      cfg.Publisher,
		log:      cfg.Logger,
		now:      cfg.Clock,
		failTh:   cfg.FailThreshold,
		revokeTh: cfg.RevokeThreshold,
	}, nil
}

// AuthCheckInput is the result of an individual email's authentication
// check (DMARC/SPF/DKIM) for a vendor domain.
type AuthCheckInput struct {
	TenantID string
	Domain   string
	DMARC    bool // pass or fail
	SPF      bool
	DKIM     bool
}

// RecordAuthCheck records a single email's authentication result and
// evaluates the vendor domain's health.
func (m *VendorAuthMonitor) RecordAuthCheck(ctx context.Context, input AuthCheckInput) error {
	now := m.now()

	record, err := m.store.Get(ctx, input.TenantID, input.Domain)
	if err != nil {
		// New domain — initialize.
		record = VendorAuthRecord{
			Domain:   input.Domain,
			TenantID: input.TenantID,
		}
	}

	record.TotalCount++
	record.LastChecked = now

	allPassed := input.DMARC && input.SPF && input.DKIM
	if allPassed {
		record.PassCount++
		record.LastPassed = now
	} else {
		record.FailCount++
		record.LastFailed = now
	}

	record.DMARC = boolToAuthStatus(input.DMARC)
	record.SPF = boolToAuthStatus(input.SPF)
	record.DKIM = boolToAuthStatus(input.DKIM)

	failRate := 0.0
	if record.TotalCount > 0 {
		failRate = float64(record.FailCount) / float64(record.TotalCount)
	}

	oldStatus := record.OverallStatus
	switch {
	case failRate >= m.revokeTh:
		record.OverallStatus = AuthFailing
	case failRate >= m.failTh:
		record.OverallStatus = AuthDegraded
	default:
		record.OverallStatus = AuthHealthy
	}

	if err := m.store.Save(ctx, record); err != nil {
		return fmt.Errorf("vendor_dmarc: save: %w", err)
	}

	// Emit event when status degrades.
	if oldStatus != record.OverallStatus && record.OverallStatus != AuthHealthy {
		m.emitDegradedEvent(ctx, record)
	}

	return nil
}

func (m *VendorAuthMonitor) emitDegradedEvent(ctx context.Context, record VendorAuthRecord) {
	if m.pub == nil {
		return
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	subject := "es.relationship.vendor.auth_degraded"
	if err := m.pub.Publish(ctx, subject, payload,
		events.WithTenantID(record.TenantID),
		events.WithEventType("vendor.auth_degraded"),
	); err != nil {
		m.log.WarnContext(ctx, "vendor_dmarc: publish failed", slog.Any("error", err))
	}

	m.log.WarnContext(ctx, "vendor_dmarc: auth degraded",
		slog.String("domain", record.Domain),
		slog.String("tenant", record.TenantID),
		slog.String("status", string(record.OverallStatus)),
		slog.Int("fail_count", record.FailCount),
		slog.Int("total", record.TotalCount))
}

// GetDomainHealth returns the current auth health of a vendor domain.
func (m *VendorAuthMonitor) GetDomainHealth(ctx context.Context, tenantID, domain string) (VendorAuthRecord, error) {
	return m.store.Get(ctx, tenantID, domain)
}

// ListDegradedDomains returns all vendor domains with degraded auth.
func (m *VendorAuthMonitor) ListDegradedDomains(ctx context.Context, tenantID string) ([]VendorAuthRecord, error) {
	return m.store.ListDegraded(ctx, tenantID)
}

func boolToAuthStatus(passed bool) AuthStatus {
	if passed {
		return AuthHealthy
	}
	return AuthFailing
}

// compile-time assertion
var _ VendorAuthStore = (*MemoryVendorAuthStore)(nil)
