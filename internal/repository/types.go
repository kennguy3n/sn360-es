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
	// ThresholdTier1PassBelow / ThresholdTier1FlagAbove are the
	// Tier 1 (encoder-stage) gating thresholds: a Tier 1 score below
	// PassBelow short-circuits to a clear verdict; above FlagAbove
	// promotes to Tier 2 for the SLM. Persisted by the tuning agent
	// so its updates survive a restart. See migration 0013.
	ThresholdTier1PassBelow int
	ThresholdTier1FlagAbove int
	SubjectTagEnabled       bool
	SubjectTagPrefix        string
	UpdatedAt               time.Time
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
//
// SenderHash and RecipientHash carry the pseudonymised participant
// identities the signal enricher derived during evaluation. They
// are persisted onto the row so the WS-3b investigation API can
// reverse-lookup per-sender history without joining back to
// communication_histories on a non-hash equality. Both fields are
// nullable in the database (migration 0020) because rows written
// before the WS-4a / WS-3b producer paths landed have no usable
// participant identity to backfill — the raw addresses were never
// persisted by design.
type EvaluationResult struct {
	ID                string
	TenantID          string
	MessageIDHash     []byte
	SenderHash        []byte
	RecipientHash     []byte
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
	// TypicalHour is the modal (most-frequent) send hour for this
	// (sender, recipient) pair, derived from the accumulated
	// per-(user, sender-domain) timing distribution held in
	// user_behavioral_baselines.typical_send_hours by the
	// relationship aggregation worker. Persisted in the
	// communication_histories.typical_hour column (migration 0007)
	// so the Tier 0 ATO heuristic's checkTimingAnomaly() can read
	// a representative baseline hour without having to JOIN against
	// user_behavioral_baselines on the hot path.
	//
	// Write contract (shared by every CommunicationHistoryRepository
	// implementation — memory.go, postgres.go):
	//
	//   - Upsert (ingestion-time write path): the field is IGNORED.
	//     Upsert never touches the typical_hour column — new rows
	//     fall back to the migration 0007 column default
	//     (TypicalHourUnset, -1) and existing rows keep whatever
	//     the worker last wrote. This guarantees ingestion cannot
	//     accidentally overwrite the worker-computed modal hour,
	//     including via the Go zero-value trap (0 == midnight UTC).
	//
	//   - UpdateCountsIfFresh (relationship-worker CAS path): the
	//     repository applies a CASE guard:
	//       * 0..23                → written to typical_hour as-is.
	//       * TypicalHourUnset(-1) → sentinel meaning "no fresh
	//                                modal hour this cycle"; the
	//                                column is preserved.
	//       * any other out-of-range value → also preserved.
	//
	// Because Go's int zero value (0) is a *valid* hour, callers of
	// UpdateCountsIfFresh MUST set this field explicitly. Use
	// TypicalHourUnset for "no change this cycle".
	TypicalHour int
	UpdatedAt   time.Time
}

// TypicalHourUnset is the sentinel value for
// CommunicationHistory.TypicalHour meaning "no baseline yet" / "do
// not overwrite". It matches the migration 0007 column default
// and is what every CommunicationHistoryRepository implementation
// looks for when deciding whether to preserve the existing
// typical_hour column on an Upsert / UpdateCountsIfFresh.
//
// See the CommunicationHistory.TypicalHour comment above for the
// full contract.
const TypicalHourUnset = -1

// ----------------------------------------------------------------------
// Repository interfaces
// ----------------------------------------------------------------------

// TenantRepository persists Tenant rows.
//
// Background workers that need to process every tenant should use
// IterateActive — it streams results in keyset-paginated batches so
// memory stays O(batchSize) regardless of tenant count. Reserve List
// for admin/operator queries on small bounded sets (the operator CLI,
// onboarding dashboards, etc.). At 10k+ tenants, List(ctx, 0) is a
// silent OOM waiting to happen.
type TenantRepository interface {
	Create(ctx context.Context, t *Tenant) error
	GetByID(ctx context.Context, id string) (*Tenant, error)
	GetByName(ctx context.Context, name string) (*Tenant, error)
	UpdateStatus(ctx context.Context, id, status string) error
	List(ctx context.Context, limit int) ([]Tenant, error)
	// IterateActive yields non-deleted tenants in keyset-paginated
	// batches. batchSize <= 0 selects a 100-tenant default. yield is
	// called once per batch (potentially with a short final batch).
	// Returning a non-nil error from yield stops iteration and the
	// error is returned from IterateActive. Implementations MUST
	// NOT assume the caller retains the slice across batches —
	// callers may modify it in-place.
	//
	// Memory footprint is O(batchSize), not O(tenant_count). Use
	// this from background workers that need to fan out per-tenant
	// work; use List for finite small admin queries.
	IterateActive(ctx context.Context, batchSize int, yield func([]Tenant) error) error
}

// UserRepository persists User rows.
type UserRepository interface {
	Upsert(ctx context.Context, u *User) error
	GetByHash(ctx context.Context, tenantID string, emailHash []byte) (*User, error)
	List(ctx context.Context, tenantID string, limit int) ([]User, error)
	Count(ctx context.Context, tenantID string) (int, error)
}

// GroupRepository persists Group rows.
type GroupRepository interface {
	Create(ctx context.Context, g *Group) error
	Upsert(ctx context.Context, g *Group) error
	GetByName(ctx context.Context, tenantID, name string) (*Group, error)
	List(ctx context.Context, tenantID string) ([]Group, error)
	Count(ctx context.Context, tenantID string) (int, error)
}

// LabelRepository persists Label rows.
type LabelRepository interface {
	Upsert(ctx context.Context, l *Label) error
	ListByTenant(ctx context.Context, tenantID, provider string) ([]Label, error)
}

// ScoreWeightUpdate is the column subset written by the tuning /
// onboarding agents' UpdateWeights path. Each field is the integer
// percentage already clamped to [0, 100] by the caller; the
// repository writes exactly these four columns in a single SQL
// UPDATE so a concurrent ThresholdUpdate against the same row cannot
// clobber them.
type ScoreWeightUpdate struct {
	WeightAI          int
	WeightRspamd      int
	WeightAttachments int
	WeightLinks       int
}

// ScoreThresholdUpdate is the column subset written by the tuning
// agent's UpdateThresholds path. Banner + Tier 1 columns only — the
// row's weights and subject-tag fields stay untouched.
type ScoreThresholdUpdate struct {
	Blocked        int
	High           int
	Warning        int
	Caution        int
	Info           int
	Tier1PassBelow int
	Tier1FlagAbove int
}

// ScoreEngineRepository persists ScoreEngine rows.
//
// UpdateWeights / UpdateThresholds are column-scoped UPDATEs that
// touch only the columns named in their respective update structs.
// They are the production write path used by the agent ConfigStore
// (cmd/sn360-es/adapters.go: postgresConfigStore) so concurrent
// weight + threshold writers against the same tenant cannot
// overwrite each other through a full-row Upsert. Both return
// ErrNotFound when no row exists for tenantID; the caller is
// responsible for first-time seeding via Upsert.
type ScoreEngineRepository interface {
	Get(ctx context.Context, tenantID string) (*ScoreEngine, error)
	Upsert(ctx context.Context, s *ScoreEngine) error
	UpdateWeights(ctx context.Context, tenantID string, w ScoreWeightUpdate) error
	UpdateThresholds(ctx context.Context, tenantID string, t ScoreThresholdUpdate) error
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
	List(ctx context.Context, tenantID string, limit int) ([]Vendor, error)
	Delete(ctx context.Context, tenantID, domain string) error
}

// EvalListBySenderMaxLimit is the hard cap on the number of rows
// EvaluationResultRepository.ListBySender returns in a single call.
// Sized to comfortably page through the operator-facing
// investigation view without letting a malformed caller stream the
// entire per-sender history through the bus on one HTTP request.
// Callers that need a longer trail must paginate by evaluated_at.
const EvalListBySenderMaxLimit = 500

// clampEvalListBySenderLimit normalises a caller-supplied `limit`
// for ListBySender to a strictly positive, bounded value. Both
// backends (memory.go, postgres.go) MUST clamp identically so
// callers get the same effective slice regardless of the backend
// under the seam.
//
//   - limit <= 0 ⇒ EvalListBySenderMaxLimit (no longer "unbounded")
//   - limit > EvalListBySenderMaxLimit ⇒ EvalListBySenderMaxLimit
//   - otherwise ⇒ the caller's value.
func clampEvalListBySenderLimit(limit int) int {
	if limit <= 0 || limit > EvalListBySenderMaxLimit {
		return EvalListBySenderMaxLimit
	}
	return limit
}

// EvaluationResultRepository persists EvaluationResult rows.
//
// ListBySender returns rows for `tenantID` whose sender_hash matches
// `senderHash`, ordered by evaluated_at descending (newest first) so
// the investigation UI sees the most recent verdicts at the top.
// Implementations MUST filter out rows whose persisted sender_hash
// is NULL or empty — a legacy row written before the WS-3b producer
// path stamped a hash carries no usable participant identity and
// matching it against an empty `senderHash` argument would leak the
// row to the wrong query.
type EvaluationResultRepository interface {
	Create(ctx context.Context, r *EvaluationResult) error
	GetByMessageHash(ctx context.Context, tenantID string, messageIDHash []byte) (*EvaluationResult, error)
	ListRecent(ctx context.Context, tenantID string, limit int) ([]EvaluationResult, error)
	// ListBySender returns evaluation results for the (tenant, sender)
	// pair, newest first, capped at min(limit, EvalListBySenderMaxLimit).
	// An empty senderHash returns an empty slice and no error — the
	// equality predicate against a zero-length pseudonym is
	// structurally pointless and would otherwise scan the table on
	// the Postgres backend where the partial index excludes the
	// NULL-sender rows.
	ListBySender(ctx context.Context, tenantID string, senderHash []byte, limit int) ([]EvaluationResult, error)
}

// CommHistoryListByTenantMaxLimit is the hard cap on the number of
// rows ListByTenant will return in a single call, regardless of
// what the caller passes for `limit`. Sizing chosen to keep the
// worst-case Postgres rowset comfortably under a few MB of network
// + memory and well under the relationship worker's 10-minute
// budget per tenant.
const CommHistoryListByTenantMaxLimit = 10000

// clampCommHistoryLimit normalises a caller-supplied `limit` to a
// strictly positive, bounded value. Both the Postgres and in-memory
// implementations MUST clamp identically so callers get the same
// effective slice regardless of backend.
//
//   - limit <= 0 ⇒ CommHistoryListByTenantMaxLimit (no longer
//     "unbounded" — `limit=0` used to silently mean "return every
//     row in the tenant", which is now disallowed).
//   - limit > CommHistoryListByTenantMaxLimit ⇒
//     CommHistoryListByTenantMaxLimit.
//   - otherwise ⇒ the caller's value.
func clampCommHistoryLimit(limit int) int {
	if limit <= 0 || limit > CommHistoryListByTenantMaxLimit {
		return CommHistoryListByTenantMaxLimit
	}
	return limit
}

// CommunicationHistoryRepository persists CommunicationHistory rows.
//
// ListByTenant returns rows whose LastSeenAt is at or after `since`,
// capped at min(limit, CommHistoryListByTenantMaxLimit) entries. The
// `since` zero-value semantics still apply (the in-memory backend
// short-circuits the filter via `since.IsZero()`; the Postgres
// backend relies on `last_seen_at >= 0001-01-01T00:00:00Z` matching
// every persisted row because the column is NOT NULL).
//
// `limit <= 0` is treated as "use the max cap", NOT as "no cap";
// every implementation clamps via clampCommHistoryLimit so that an
// inadvertent caller cannot stream a multi-million-row scan.
// CommHistoryListByTenantMaxLimit is a hard ceiling: callers that
// pass a larger value (e.g. the relationship worker's
// MaxPerTenant knob configured above the cap) are silently
// truncated to the cap. Callers that legitimately need to iterate
// the entire tenant must page across multiple ListByTenant calls
// using the LastSeenAt of the final returned row as the next
// `since` argument.
type CommunicationHistoryRepository interface {
	// Upsert writes the ingestion-time view of a (sender,
	// recipient) pair. Implementations MUST NOT propagate
	// h.TypicalHour onto the persisted row — that column is owned
	// by UpdateCountsIfFresh. See CommunicationHistory.TypicalHour
	// for the full rationale (TL;DR: Go's int zero value 0 is a
	// valid hour, so any path that lets ingestion write
	// typical_hour creates a silent-overwrite trap for callers
	// that omit the field).
	Upsert(ctx context.Context, h *CommunicationHistory) error
	Get(ctx context.Context, tenantID string, senderHash, recipientHash []byte) (*CommunicationHistory, error)
	ListByTenant(ctx context.Context, tenantID string, since time.Time, limit int) ([]CommunicationHistory, error)

	// UpdateCountsIfFresh applies the relationship-worker's
	// recomputed Count7d + Relationship to the (tenant, sender,
	// recipient) row IFF the row's UpdatedAt still matches `readAt`
	// — i.e. ingestion has not written to it since the worker
	// loaded the snapshot via ListByTenant. This is an optimistic-
	// concurrency guard, NOT a long-running lock; the row remains
	// available for ingestion-time Upsert at all times.
	//
	// Returns (true, nil) when the row was updated and (false, nil)
	// when the guard rejected the write because ingestion already
	// produced a fresher snapshot. The worker treats the second
	// case as success because the ingestion-time write is canonical
	// — re-running the decay/reclassify against ingestion's fresher
	// counts would just resurrect the same race on the next cycle.
	//
	// The full-replacement Upsert remains the ingestion-time path
	// because ingestion always writes a freshly-computed row;
	// switching ingestion to CAS would defeat its monotonic
	// increment-and-stamp model. The worker is the only caller
	// that needs the CAS semantics because it carries a stale
	// snapshot across a list/decide/write boundary.
	//
	// Reflection contract: implementations MUST NOT be relied upon
	// to reflect the post-CAS row state back onto *h. The Postgres
	// implementation uses ExecContext (no RETURNING clause), so
	// `h.UpdatedAt` and `h.TypicalHour` retain whatever values the
	// caller passed in even after a successful return — the
	// canonical post-write state lives in the repository and must
	// be re-read via Get / ListByTenant if needed. The in-memory
	// implementation matches this contract deliberately so tests
	// cannot accidentally depend on a reflection that production
	// does not provide.
	UpdateCountsIfFresh(ctx context.Context, h *CommunicationHistory, readAt time.Time) (bool, error)

	// RecordSighting is the WS-4a "incremental baseline" write
	// path. It atomically inserts the (tenant, sender, recipient)
	// row when it does not already exist OR increments the rolling
	// counters when it does — in a single SQL statement on the
	// Postgres backend, eliminating the read-modify-write race
	// window that Upsert leaves open.
	//
	// Semantics on conflict:
	//
	//   - count_30d: incremented by 1 unconditionally. The decay
	//                     side is owned by the relationship worker
	//                     which periodically re-bases the counters
	//                     via UpdateCountsIfFresh, so an aged
	//                     sighting that should not have contributed
	//                     to the 30-day window is corrected on the
	//                     next worker cycle.
	//
	//   - count_7d:  incremented by 1 unconditionally for the same
	//                     reason. The worker recomputes
	//                     post-decay.
	//
	//   - last_seen_at: GREATEST(persisted, s.SentAt). Monotonic;
	//                     a redelivered (or out-of-order) sighting
	//                     never regresses the timestamp.
	//
	//   - first_seen_at: NEVER overwritten on conflict. The Tier 0
	//                     FirstTimeExternal heuristic depends on
	//                     the timestamp of the original sighting
	//                     being row-stable.
	//
	//   - sender_domain / sender_domain_hash: filled in IFF the
	//                     persisted row's domain is empty AND the
	//                     sighting carries a non-empty domain.
	//                     This handles the case where the first
	//                     few sightings of a sender arrived before
	//                     the bridge could extract a parseable
	//                     domain and a later sighting fills it in;
	//                     it does NOT overwrite a persisted domain
	//                     just because a later sighting carries a
	//                     different one (e.g. a forwarded message
	//                     with a different envelope sender).
	//
	//   - relationship: never touched. Owned by the worker via
	//                     UpdateCountsIfFresh.
	//
	//   - typical_hour: never touched. Owned by the worker.
	//
	//   - updated_at: stamped to NOW() so subsequent worker CAS
	//                     reads via UpdateCountsIfFresh see a
	//                     fresher row and step aside on the next
	//                     cycle. This is the same CAS-coherence
	//                     property Upsert maintains, so the
	//                     existing worker contract is preserved
	//                     transparently.
	//
	// Idempotency: callers are responsible for upstream dedup (the
	// JetStream consumer relies on a per-(tenant, sender, recipient,
	// message_id) dedup key). A duplicate call that DOES reach
	// this method will increment the counters a second time; the
	// worker's 4-hour recomputation cycle corrects any drift the
	// next cycle. The contract here is "best-effort monotonic
	// increment", not "exactly-once increment".
	RecordSighting(ctx context.Context, s Sighting) error

	// ListBySender returns CommunicationHistory rows for `tenantID`
	// whose sender_hash matches `senderHash`, ordered by
	// last_seen_at descending (most recently active recipients
	// first). Capped at min(limit, CommHistoryListByTenantMaxLimit).
	// An empty senderHash returns an empty slice and no error.
	//
	// Used by the WS-3b investigation API to render the
	// per-sender recipient fan-out for an operator drill-down
	// without forcing the read path through ListByTenant (which is
	// the relationship worker's full-tenant scan path with a
	// different `since` semantic).
	ListBySender(ctx context.Context, tenantID string, senderHash []byte, limit int) ([]CommunicationHistory, error)
}

// Sighting is the input to CommunicationHistoryRepository.RecordSighting.
// See the docstring on RecordSighting for the semantics of each field.
type Sighting struct {
	TenantID         string
	SenderHash       []byte
	RecipientHash    []byte
	SenderDomainHash []byte
	SenderDomain     string
	SentAt           time.Time
}

// FeedbackEventRepository persists FeedbackEvent rows and exposes the
// per-action aggregate the dashboard relies on.
type FeedbackEventRepository interface {
	Create(ctx context.Context, e *FeedbackEvent) error
	Counts(ctx context.Context, tenantID string, start, end time.Time) (FeedbackCounts, error)
	ListSince(ctx context.Context, tenantID string, since time.Time) ([]FeedbackEvent, error)
}

// GroupMembership is a join-table row linking a user to a group.
type GroupMembership struct {
	GroupID   string
	UserID    string
	CreatedAt time.Time
}

// GroupMembershipRepository persists group membership rows.
type GroupMembershipRepository interface {
	Upsert(ctx context.Context, gm *GroupMembership) error
	ListByGroup(ctx context.Context, groupID string) ([]GroupMembership, error)
	ListByUser(ctx context.Context, userID string) ([]GroupMembership, error)
	DeleteByGroup(ctx context.Context, groupID string) error
	ReplaceForGroup(ctx context.Context, groupID string, userIDs []string) error
}

// SyncCheckpoint stores delta-sync tokens for incremental directory
// synchronization (MS Graph delta queries, GWS updatedMin timestamps).
type SyncCheckpoint struct {
	TenantID   string
	Provider   string // "outlook" or "gmail"
	DeltaToken string
	UpdatedAt  time.Time
}

// SyncCheckpointRepository persists delta-sync checkpoints.
type SyncCheckpointRepository interface {
	Get(ctx context.Context, tenantID, provider string) (*SyncCheckpoint, error)
	Upsert(ctx context.Context, cp *SyncCheckpoint) error
}

// UserBehavioralBaseline tracks per-user-sender-domain communication
// patterns for anomaly detection.
type UserBehavioralBaseline struct {
	ID                 string
	TenantID           string
	UserEmailHash      []byte
	SenderDomainHash   []byte
	TypicalSendHours   []int
	TypicalDeviceTypes []string
	AvgMessagesPerWeek float64
	LastSeenAt         time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// UserBehavioralBaselineRepository persists per-user behavioral baselines.
type UserBehavioralBaselineRepository interface {
	Upsert(ctx context.Context, b *UserBehavioralBaseline) error
	Get(ctx context.Context, tenantID string, userHash, senderDomainHash []byte) (*UserBehavioralBaseline, error)
}

// OrgGraphSnapshot is the persisted output of onboarding.Project().
type OrgGraphSnapshot struct {
	ID              string
	TenantID        string
	BuiltAt         time.Time
	GraphJSON       []byte
	HighRiskIDs     []string
	DepartmentCount int
	EmployeeCount   int
	GroupCount      int
	CreatedAt       time.Time
}

// OrgGraphRepository persists org graph snapshots.
type OrgGraphRepository interface {
	Upsert(ctx context.Context, s *OrgGraphSnapshot) error
	GetByTenant(ctx context.Context, tenantID string) (*OrgGraphSnapshot, error)
}

// Registry bundles all repositories for convenient wiring.
type Registry struct {
	Tenants                TenantRepository
	Users                  UserRepository
	Groups                 GroupRepository
	GroupMemberships       GroupMembershipRepository
	Labels                 LabelRepository
	ScoreEngines           ScoreEngineRepository
	EmailClassifications   EmailClassificationRepository
	Vendors                VendorRepository
	EvaluationResults      EvaluationResultRepository
	CommunicationHistories CommunicationHistoryRepository
	FeedbackEvents         FeedbackEventRepository
	AuditLogs              AuditLogRepository
	SyncCheckpoints        SyncCheckpointRepository
	BehavioralBaselines    UserBehavioralBaselineRepository
	OrgGraphs              OrgGraphRepository
}
