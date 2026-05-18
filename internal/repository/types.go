// Package repository defines persistence interfaces and the Postgres
// implementation backing them.
//
// The domain entities listed in ARCHITECTURE.md §5.3 (tenants, users,
// groups, labels, score_engine, email_classifications, vendors,
// evaluation_results, communication_histories) are each exposed via a
// purpose-built interface in this package. Services depend only on the
// interfaces; the Postgres implementation lives under sibling files in
// `*_pg.go` and can be swapped for an in-memory fixture in unit tests
// (see `memory.go`).
//
// The schema this package writes against is created by the SQL files
// under `migrations/` and applied via `make migrate-up`.
package repository

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Get/UpdateByID when no row matches.
var ErrNotFound = errors.New("repository: not found")

// ErrConflict is returned when a unique-constraint check rejects a write.
var ErrConflict = errors.New("repository: unique conflict")

// ----------------------------------------------------------------------
// Domain types
// ----------------------------------------------------------------------

// Tenant is a customer organisation.
type Tenant struct {
	ID            string
	Name          string
	DisplayName   string
	Provider      string
	PrimaryDomain string
	Region        string
	KMSKeyARN     string
	ScoreBase     int
	RetentionDays int
	Locale        string
	Status        string
	Metadata      map[string]string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// User is a pseudonymised mailbox owner.
type User struct {
	ID              string
	TenantID        string
	EmailHash       []byte
	Role            string
	Department      string
	SensitivityTier string
	ResilienceScore int
	Vulnerability   int
	Locale          string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Group represents an organisational unit.
type Group struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	RiskClass   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Label represents a provider-specific tier/category label.
type Label struct {
	ID        string
	TenantID  string
	Provider  string
	Tier      string
	Category  string
	Name      string
	ColorBG   string
	ColorFG   string
	Preset    int
	Visible   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ScoreEngine holds per-tenant scoring weights and thresholds.
type ScoreEngine struct {
	TenantID          string
	ScoreBase         int
	WeightAI          int
	WeightRspamd      int
	WeightAttachments int
	WeightLinks       int
	ThresholdBlocked  int
	ThresholdHigh     int
	ThresholdWarning  int
	ThresholdCaution  int
	ThresholdInfo     int
	SubjectTagEnabled bool
	SubjectTagPrefix  string
	UpdatedAt         time.Time
}

// EmailClassification represents a domain-level classification list entry.
type EmailClassification struct {
	ID             string
	Domain         string
	Classification string
	Source         string
	UpdatedAt      time.Time
}

// Vendor represents an approved external sender for a tenant.
type Vendor struct {
	ID             string
	TenantID       string
	Domain         string
	DisplayName    string
	Approved       bool
	AutoDiscovered bool
	Confidence     float64
	LastSeenAt     time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EvaluationResult is the persisted output of a Tier 0/1/2 evaluation.
type EvaluationResult struct {
	ID                string
	TenantID          string
	MessageIDHash     []byte
	CorrelationID     string
	Score             int
	Tier              string
	Primary           string
	Secondary         []string
	ReasonCodes       []string
	Degraded          bool
	DegradedServices  []string
	Tier0OutcomeJSON  []byte
	Tier1OutcomeJSON  []byte
	Tier2OutcomeJSON  []byte
	RspamdOutcomeJSON []byte
	EvaluatedAt       time.Time
	CreatedAt         time.Time
}

// FeedbackEvent is a single verified banner-action click. Rows live
// in `feedback_events` (migration 0002) and back dto.FeedbackStats on
// the dashboard.
type FeedbackEvent struct {
	ID              string
	TenantID        string
	PseudoMessageID string
	Action          string
	Tier            string
	CorrelationID   string
	OccurredAt      time.Time
	CreatedAt       time.Time
}

// FeedbackCounts is the per-action aggregate the dashboard reads.
type FeedbackCounts struct {
	ReportedPhishing int
	MarkedSafe       int
	TrustedSender    int
}

// CommunicationHistory is a relationship aggregate keyed by sender +
// recipient hash.
//
// SenderDomain holds the plaintext sender domain so downstream
// services (vendor discovery, dashboard aggregations) can match on
// the actual domain string. SenderDomainHash is kept for the legacy
// hash-only index but should not be used as a domain identifier —
// converting the raw bytes to a string produces binary gibberish.
type CommunicationHistory struct {
	ID               string
	TenantID         string
	SenderHash       []byte
	RecipientHash    []byte
	SenderDomainHash []byte
	SenderDomain     string
	Count7d          int
	Count30d         int
	FirstSeenAt      time.Time
	LastSeenAt       time.Time
	Relationship     string
	UpdatedAt        time.Time
}

// ----------------------------------------------------------------------
// Repository interfaces
// ----------------------------------------------------------------------

// TenantRepository persists Tenant rows.
type TenantRepository interface {
	Create(ctx context.Context, t *Tenant) error
	GetByID(ctx context.Context, id string) (*Tenant, error)
	GetByName(ctx context.Context, name string) (*Tenant, error)
	UpdateStatus(ctx context.Context, id, status string) error
	List(ctx context.Context, limit int) ([]Tenant, error)
}

// UserRepository persists User rows.
type UserRepository interface {
	Upsert(ctx context.Context, u *User) error
	GetByHash(ctx context.Context, tenantID string, emailHash []byte) (*User, error)
	List(ctx context.Context, tenantID string, limit int) ([]User, error)
}

// GroupRepository persists Group rows.
type GroupRepository interface {
	Create(ctx context.Context, g *Group) error
	GetByName(ctx context.Context, tenantID, name string) (*Group, error)
	List(ctx context.Context, tenantID string) ([]Group, error)
}

// LabelRepository persists Label rows.
type LabelRepository interface {
	Upsert(ctx context.Context, l *Label) error
	ListByTenant(ctx context.Context, tenantID, provider string) ([]Label, error)
}

// ScoreEngineRepository persists ScoreEngine rows.
type ScoreEngineRepository interface {
	Get(ctx context.Context, tenantID string) (*ScoreEngine, error)
	Upsert(ctx context.Context, s *ScoreEngine) error
}

// EmailClassificationRepository persists EmailClassification rows.
type EmailClassificationRepository interface {
	Upsert(ctx context.Context, e *EmailClassification) error
	GetByDomain(ctx context.Context, domain string) ([]EmailClassification, error)
}

// VendorRepository persists Vendor rows.
type VendorRepository interface {
	Upsert(ctx context.Context, v *Vendor) error
	GetByDomain(ctx context.Context, tenantID, domain string) (*Vendor, error)
	ListApproved(ctx context.Context, tenantID string) ([]Vendor, error)
}

// EvaluationResultRepository persists EvaluationResult rows.
type EvaluationResultRepository interface {
	Create(ctx context.Context, r *EvaluationResult) error
	GetByMessageHash(ctx context.Context, tenantID string, messageIDHash []byte) (*EvaluationResult, error)
	ListRecent(ctx context.Context, tenantID string, limit int) ([]EvaluationResult, error)
}

// CommunicationHistoryRepository persists CommunicationHistory rows.
//
// ListByTenant returns rows whose LastSeenAt is at or after `since`,
// capped at `limit` entries. Both bounds carry zero-value semantics
// every implementation MUST honour identically — otherwise the
// relationship-aggregation and vendor-discovery periodic workers
// degrade silently when wired in `cmd/sn360-es/main.go`:
//
//   - `since == time.Time{}` (Go zero) ⇒ no time filter; the call
//     returns every row for the tenant. The in-memory backend
//     short-circuits the filter via `since.IsZero()`; the Postgres
//     backend relies on `last_seen_at >= 0001-01-01T00:00:00Z`
//     matching every persisted row (the column is NOT NULL).
//   - `limit <= 0` ⇒ no row cap. The in-memory backend skips the
//     truncation step; the Postgres backend uses `LIMIT NULLIF($N,0)`
//     so the planner sees `LIMIT NULL` (= unbounded).
//
// Callers that want the documented worker behaviour pass a non-zero
// `since` (the rolling-window cutoff) and a positive `limit` (the
// per-tenant scan cap). The zero-value semantics exist so ad-hoc
// callers (tests, admin tools) can request an unfiltered tenant
// scan without a sentinel API.
type CommunicationHistoryRepository interface {
	Upsert(ctx context.Context, h *CommunicationHistory) error
	Get(ctx context.Context, tenantID string, senderHash, recipientHash []byte) (*CommunicationHistory, error)
	ListByTenant(ctx context.Context, tenantID string, since time.Time, limit int) ([]CommunicationHistory, error)
}

// FeedbackEventRepository persists FeedbackEvent rows and exposes the
// per-action aggregate the dashboard relies on.
type FeedbackEventRepository interface {
	Create(ctx context.Context, e *FeedbackEvent) error
	Counts(ctx context.Context, tenantID string, start, end time.Time) (FeedbackCounts, error)
}

// Registry bundles all repositories for convenient wiring.
type Registry struct {
	Tenants                TenantRepository
	Users                  UserRepository
	Groups                 GroupRepository
	Labels                 LabelRepository
	ScoreEngines           ScoreEngineRepository
	EmailClassifications   EmailClassificationRepository
	Vendors                VendorRepository
	EvaluationResults      EvaluationResultRepository
	CommunicationHistories CommunicationHistoryRepository
	FeedbackEvents         FeedbackEventRepository
}
