// Package agent hosts SN360-ES's three "zero-admin" AI agents:
//
//   - Onboarding agent — bootstraps a new tenant by discovering users,
//     groups, communication patterns, then creating per-mailbox labels
//     and seeding the vendor list.
//   - Tuning agent — runs on a schedule, looks at FP/FN feedback, and
//     adjusts per-tenant Tier 0 / Tier 1 thresholds and score weights.
//   - Support agent — handles in-product user queries about flagged
//     emails (explanations, quarantine release, escalation to SecOps).
//
// All three share a small set of contracts defined here so they can
// be wired interchangeably from the service entrypoint.
package agent

import (
	"context"
	"errors"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Provider identifies the email provider a tenant is on.
type Provider string

const (
	ProviderGoogle    Provider = "google_workspace"
	ProviderMicrosoft Provider = "microsoft_365"
	ProviderUnknown   Provider = "unknown"
)

// Valid reports whether p is a known provider.
func (p Provider) Valid() bool {
	switch p {
	case ProviderGoogle, ProviderMicrosoft, ProviderUnknown:
		return true
	}
	return false
}

// TenantContext is the small bundle of inputs every agent needs to run
// against a single tenant.
type TenantContext struct {
	TenantID  string
	Provider  Provider
	Locale    string
	StartedAt time.Time
}

// Validate returns an error if the context is unusable.
func (c TenantContext) Validate() error {
	if c.TenantID == "" {
		return errors.New("agent: tenant ID is required")
	}
	if !c.Provider.Valid() {
		return errors.New("agent: provider is required")
	}
	return nil
}

// DiscoveredUser is the canonical representation of a mailbox owner.
// Both GWS and MS Graph clients map their per-API user shapes onto this
// struct so downstream consumers (label applier, role classifier) need
// only handle one type.
type DiscoveredUser struct {
	ID            string
	Email         string
	DisplayName   string
	Department    string
	JobTitle      string
	IsAdmin       bool
	IsSuspended   bool
	GroupIDs      []string
	ManagerID     string
	// SensitivityHint is the per-role sensitivity boost applied during
	// onboarding (e.g. C-suite / Finance / HR get higher sensitivity).
	SensitivityHint Sensitivity
}

// DiscoveredGroup is the canonical group/distribution-list shape.
type DiscoveredGroup struct {
	ID          string
	Name        string
	Description string
	Email       string
	MemberCount int
}

// Sensitivity is the per-user/per-group threshold modifier applied by
// the tuning agent. Higher is stricter (catch more, accept more FPs).
type Sensitivity int

const (
	SensitivityDefault  Sensitivity = 0
	SensitivityElevated Sensitivity = 1
	SensitivityHigh     Sensitivity = 2
	SensitivityMax      Sensitivity = 3
)

// String returns a stable label used in audit logs and Redis keys.
func (s Sensitivity) String() string {
	switch s {
	case SensitivityElevated:
		return "elevated"
	case SensitivityHigh:
		return "high"
	case SensitivityMax:
		return "max"
	default:
		return "default"
	}
}

// FeedbackKind captures the user action that produced a feedback signal.
type FeedbackKind string

const (
	FeedbackReportPhishing FeedbackKind = "report_phishing"
	FeedbackMarkSafe       FeedbackKind = "mark_safe"
	FeedbackTrustSender    FeedbackKind = "trust_sender"
)

// Feedback is a single user-action event consumed by the tuning agent.
type Feedback struct {
	TenantID     string
	MessageID    string
	Action       FeedbackKind
	PriorTier    constant.Tier
	PriorScore   int
	PriorPrimary constant.Category
	OccurredAt   time.Time
}

// TuningSnapshot captures the inputs to a tuning decision: aggregate
// FP/FN counts plus the prior weights so the decision is deterministic.
type TuningSnapshot struct {
	TenantID         string
	WindowStart      time.Time
	WindowEnd        time.Time
	TotalEvaluations int
	FalsePositives   int
	FalseNegatives   int
	CurrentWeights   ScoreWeights
	CurrentThresholds Thresholds
}

// ScoreWeights mirrors the score-engine weights stored in Redis.
type ScoreWeights struct {
	AI          float64 `json:"ai"`
	Rspamd      float64 `json:"rspamd"`
	Attachments float64 `json:"attachments"`
	Links       float64 `json:"links"`
}

// Thresholds is the per-tenant decision threshold bundle.
type Thresholds struct {
	Tier1PassBelow int
	Tier1FlagAbove int
	BannerBlocked  int
	BannerHighRisk int
	BannerWarning  int
	BannerCaution  int
	BannerInfo     int
}

// TuningDecision captures the (optional) update the tuning agent emits.
type TuningDecision struct {
	TenantID      string
	NewWeights    *ScoreWeights
	NewThresholds *Thresholds
	Notes         []string
	DecidedAt     time.Time
}

// SupportQuery is the inbound shape a user sends to the support agent.
type SupportQuery struct {
	TenantID    string
	UserEmail   string
	MessageID   string
	Question    string
	Action      string // "explain", "release", "escalate"
	Locale      string
}

// SupportReply is the structured answer the support agent emits.
type SupportReply struct {
	Explanation string
	Confidence  float64
	Suggestion  string
	Escalated   bool
	ReleasedAt  *time.Time
	ReleasedAs  constant.Category
}

// Agent is the canonical "do one thing per tenant" interface implemented
// by each concrete agent type. The methods are intentionally
// coarse-grained because each agent's work units differ.
type Agent interface {
	Name() string
}

// DirectoryClient is implemented by per-provider clients (GWS, MS
// Graph) that the onboarding/tuning agents call.
type DirectoryClient interface {
	ListUsers(ctx context.Context, tenantID string) ([]DiscoveredUser, error)
	ListGroups(ctx context.Context, tenantID string) ([]DiscoveredGroup, error)
}

// VendorScanner discovers vendor candidates from the tenant's recent
// inbound mail history.
type VendorScanner interface {
	ScanRecentSenders(ctx context.Context, tenantID string, since time.Time) ([]VendorCandidate, error)
}

// VendorCandidate is a sender promoted to the vendor allowlist on first
// onboarding. Real CRM-driven workflows can override this later.
type VendorCandidate struct {
	Domain   string
	Confidence float64
	SeenCount int
}

// LabelApplier creates / applies tier labels per mailbox. The signature
// matches the provider-agnostic implementation in
// internal/service/action.
type LabelApplier interface {
	EnsureTierLabels(ctx context.Context, tenantID, mailbox string) error
}

// EventPublisher is the minimal NATS publisher surface agents need.
type EventPublisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// AuditLog records every agent decision so the tuning + support agents
// can be audited.
type AuditLog interface {
	Record(ctx context.Context, entry AuditEntry) error
}

// AuditEntry is one row in the agent audit log.
type AuditEntry struct {
	Agent      string
	TenantID   string
	Action     string
	Reason     string
	Detail     map[string]any
	OccurredAt time.Time
}

// ResultRepository is the read-side surface for the tuning agent (to
// pull recent feedback and aggregate statistics).
type ResultRepository interface {
	RecentFeedback(ctx context.Context, tenantID string, since time.Time) ([]Feedback, error)
	CurrentWeights(ctx context.Context, tenantID string) (ScoreWeights, error)
	CurrentThresholds(ctx context.Context, tenantID string) (Thresholds, error)
}

// ConfigStore is the write-side surface for the tuning agent.
type ConfigStore interface {
	UpdateWeights(ctx context.Context, tenantID string, w ScoreWeights) error
	UpdateThresholds(ctx context.Context, tenantID string, t Thresholds) error
}

// EvaluationLookup is the surface the support agent uses to fetch the
// stored verdict for a message (so it can explain it back to the user).
type EvaluationLookup interface {
	FindResult(ctx context.Context, tenantID, messageID string) (dto.EvaluateResult, error)
}
