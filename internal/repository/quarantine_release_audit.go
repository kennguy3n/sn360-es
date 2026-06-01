package repository

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// QuarantineReleaseOutcome is the closed enum the WS-3a self-service
// release flow writes to `quarantine_release_audit.outcome`. The Go
// constants mirror the CHECK constraint installed by migration 0021
// — adding a new state requires both an enum constant here and a
// CHECK literal in the up migration. Tests assert the two stay in
// sync.
type QuarantineReleaseOutcome string

const (
	// QuarantineReleaseOutcomeReleased records a successful release:
	// rate-limit passed, no tier-2 block, record restored on the
	// provider side.
	QuarantineReleaseOutcomeReleased QuarantineReleaseOutcome = "released"
	// QuarantineReleaseOutcomeRateLimited records an attempt
	// rejected by the per-recipient hourly cap (default 5 / hour,
	// per tenant policy).
	QuarantineReleaseOutcomeRateLimited QuarantineReleaseOutcome = "rate_limited"
	// QuarantineReleaseOutcomeTier2Blocked records an attempt
	// against a message that the persisted tier-2 SLM verdict
	// (`QuarantineRecord.Tier2Malicious=true`) classified as
	// malicious at quarantine time. Unconditional — no tenant
	// policy overrides this gate. Reserved exclusively for the
	// persisted-bit gate caught at lookup time; for any
	// safety-stack refusal that surfaces from the runner's
	// re-evaluation (tier-1 still over threshold, fresh tier-2
	// verdict, policy gate, …) use
	// QuarantineReleaseOutcomeReleaseRefused instead so SOC
	// queries `WHERE outcome = 'tier2_blocked'` get only true
	// tier-2 verdicts.
	QuarantineReleaseOutcomeTier2Blocked QuarantineReleaseOutcome = "tier2_blocked"
	// QuarantineReleaseOutcomeReleaseRefused records an attempt
	// the shared release runner refused at re-evaluation time
	// for a reason OTHER than the persisted Tier2Malicious bit
	// (e.g. tier-1 score still above threshold, fresh tier-2
	// verdict differing from the persisted bit, policy gate).
	// Distinct from Tier2Blocked so the audit column accurately
	// reflects which classifier said no; the wire response is
	// the same 403 in both cases (cross-tenant
	// indistinguishability is preserved by the handler's
	// outcome→status mapping).
	QuarantineReleaseOutcomeReleaseRefused QuarantineReleaseOutcome = "release_refused"
	// QuarantineReleaseOutcomeTokenExpired records a 401 caused by
	// an `exp`-claim violation. The client-visible response body is
	// the same as for InvalidToken — only the audit row
	// distinguishes them so SOC can tell stale-link from
	// tampering.
	QuarantineReleaseOutcomeTokenExpired QuarantineReleaseOutcome = "token_expired"
	// QuarantineReleaseOutcomeInvalidToken records any other JWT
	// validation failure (signature, malformed payload, missing
	// claim). Same 401 wire body as TokenExpired.
	QuarantineReleaseOutcomeInvalidToken QuarantineReleaseOutcome = "invalid_token"
	// QuarantineReleaseOutcomeAlreadyReleased records a duplicate
	// click on the same release URL after a prior success. The
	// release operation itself is idempotent — re-release of an
	// already-released message is a no-op audited under this
	// outcome.
	QuarantineReleaseOutcomeAlreadyReleased QuarantineReleaseOutcome = "already_released"
	// QuarantineReleaseOutcomeNotFound covers three indistinguishable
	// cases at the wire (cross-tenant indistinguishability): the
	// record doesn't exist in any tenant, the record exists in a
	// different tenant, or the record was hard-deleted by retention.
	// The wire response is the same 404 in all three cases; the
	// audit row preserves the distinction for in-tenant SOC review.
	QuarantineReleaseOutcomeNotFound QuarantineReleaseOutcome = "not_found"
)

// AllQuarantineReleaseOutcomes lists every outcome value in a fixed
// order. Tests iterate this list to ensure the Go enum and the SQL
// CHECK constraint stay in sync.
var AllQuarantineReleaseOutcomes = []QuarantineReleaseOutcome{
	QuarantineReleaseOutcomeReleased,
	QuarantineReleaseOutcomeRateLimited,
	QuarantineReleaseOutcomeTier2Blocked,
	QuarantineReleaseOutcomeReleaseRefused,
	QuarantineReleaseOutcomeTokenExpired,
	QuarantineReleaseOutcomeInvalidToken,
	QuarantineReleaseOutcomeAlreadyReleased,
	QuarantineReleaseOutcomeNotFound,
}

// Valid reports whether o is one of the known outcome values.
func (o QuarantineReleaseOutcome) Valid() bool {
	for _, known := range AllQuarantineReleaseOutcomes {
		if o == known {
			return true
		}
	}
	return false
}

// QuarantineReleaseAuditEntry represents one row in
// `quarantine_release_audit`. Persisted by the self-release handler
// for every release attempt — success or failure — keyed by
// (tenant_id, recipient_user_hash) and (pseudo_message_id).
type QuarantineReleaseAuditEntry struct {
	// ID is the audit row's UUID. Auto-generated when zero.
	ID string
	// TenantID scopes the row. RLS enforces visibility by this
	// column; cross-tenant reads are filtered out by the
	// `tenant_isolation` policy from migration 0018.
	TenantID string
	// PseudoMessageID is the privacy-safe handle for the message
	// being released — same shape as everywhere else in the
	// codebase (pseudonymisation happens at ingest).
	PseudoMessageID string
	// RecipientUserHash is the BLAKE2b-256 pseudonym of the
	// recipient mailbox. Matches `users.email_hash` /
	// `communication_histories.recipient_hash` shape (BYTEA).
	RecipientUserHash []byte
	// Outcome is the result of the release attempt; one of
	// AllQuarantineReleaseOutcomes.
	Outcome QuarantineReleaseOutcome
	// Reason is a short, free-form human-readable note (e.g.
	// "verdict still Blocked after re-evaluation") for SOC
	// debugging. May be empty.
	Reason string
	// CorrelationID propagates from the request for cross-service
	// tracing (matches feedback_events / audit_logs convention).
	// May be empty.
	CorrelationID string
	// RequestedAt is the timestamp the release attempt was
	// initiated (wall-clock at handler entry). Drives the
	// rate-limit window — the per-recipient counter is
	// `count(*) WHERE requested_at >= now() - '1 hour'`.
	RequestedAt time.Time
	// CreatedAt is when the row was inserted. Equals RequestedAt
	// for synchronous writes; diverges only for retried writes.
	CreatedAt time.Time
}

// QuarantineReleaseAuditRepository persists self-release attempts and
// drives the per-recipient rate-limit lookup.
type QuarantineReleaseAuditRepository interface {
	// Record appends one audit row. ID and CreatedAt are populated
	// when zero. Returns the row that was actually written
	// (echoes back any defaulted columns) so the caller can log
	// the canonical ID.
	Record(ctx context.Context, entry QuarantineReleaseAuditEntry) (QuarantineReleaseAuditEntry, error)
	// CountRecentByRecipient returns the number of audit rows for
	// (tenantID, recipientUserHash) with `requested_at >= since`
	// that come from a recipient whose JWT signature the handler
	// successfully verified. Auth-failure outcomes
	// (`token_expired`, `invalid_token`) are EXCLUDED from the
	// count because they are written from the
	// unverified-and-attacker-controllable claims of a rejected
	// JWT; counting them would let an attacker who learned a
	// target's `recipient_user_hash` (a BLAKE2b-256 digest, hard
	// but not impossible to obtain — e.g. via observation of a
	// legitimate self-release URL) deny self-release to that
	// recipient by spraying forged JWTs.
	//
	// Used by the rate-limit check: the handler queries with
	// `since = now() - 1 hour` and rejects when the count meets
	// or exceeds the tenant's configured cap.
	//
	// All other outcomes — `released`, `rate_limited`,
	// `tier2_blocked`, `release_refused`, `already_released`,
	// `not_found` — DO count, because they are written only after
	// the JWT verified. An auth'd recipient hitting the endpoint
	// with mismatched inputs still legitimately consumes their
	// hourly budget.
	//
	// Defense against forged-token audit-table growth (the
	// concern that previously motivated counting auth-failure
	// rows) is the responsibility of upstream per-source-IP
	// rate-limiting middleware, NOT the per-recipient counter:
	// those two limits guard different threat models and should
	// not be conflated.
	CountRecentByRecipient(ctx context.Context, tenantID string, recipientUserHash []byte, since time.Time) (int, error)
	// ListByMessage returns audit rows for a single
	// (tenantID, pseudoMessageID) ordered newest first, capped at
	// limit (limit<=0 returns up to 100). Used by the WS-3b
	// investigation API's message trail to surface release
	// history alongside the verdict timeline.
	ListByMessage(ctx context.Context, tenantID, pseudoMessageID string, limit int) ([]QuarantineReleaseAuditEntry, error)
}

// pgQuarantineReleaseAudit implements QuarantineReleaseAuditRepository
// against Postgres.
type pgQuarantineReleaseAudit struct {
	db *postgres.DB
}

// NewPgQuarantineReleaseAudit constructs a Postgres-backed audit
// repository. Reads / writes route through whatever connection scope
// the caller has bound (WithTenant / WithCrossTenant), so RLS
// enforces tenant isolation at the row level.
func NewPgQuarantineReleaseAudit(db *postgres.DB) QuarantineReleaseAuditRepository {
	return &pgQuarantineReleaseAudit{db: db}
}

// Record inserts one row. The CHECK constraint in migration 0021
// validates the outcome enum at the DB layer — an invalid outcome
// surfaces as a 23514 (check_violation), which we wrap so callers
// can distinguish "bad input" from "bad infra".
//
// tenant-lint:cross-tenant — the INSERT statement contains the
// tenant_id column in the column list, which the tenant-lint
// analyser already counts as a sufficient tenant predicate for
// INSERT statements. The annotation is here only for grep-ability
// when an operator audits the cross-tenant surface.
func (p *pgQuarantineReleaseAudit) Record(ctx context.Context, entry QuarantineReleaseAuditEntry) (QuarantineReleaseAuditEntry, error) {
	if entry.TenantID == "" {
		return entry, fmt.Errorf("quarantine_release_audit: tenant_id is required")
	}
	if entry.PseudoMessageID == "" {
		return entry, fmt.Errorf("quarantine_release_audit: pseudo_message_id is required")
	}
	if len(entry.RecipientUserHash) == 0 {
		return entry, fmt.Errorf("quarantine_release_audit: recipient_user_hash is required")
	}
	if !entry.Outcome.Valid() {
		return entry, fmt.Errorf("quarantine_release_audit: outcome %q is not a known value", entry.Outcome)
	}
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if entry.RequestedAt.IsZero() {
		entry.RequestedAt = now
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO quarantine_release_audit
    (id, tenant_id, pseudo_message_id, recipient_user_hash, outcome, reason, correlation_id, requested_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.ID, entry.TenantID, entry.PseudoMessageID, entry.RecipientUserHash,
		string(entry.Outcome), entry.Reason, entry.CorrelationID,
		entry.RequestedAt, entry.CreatedAt)
	if err != nil {
		return entry, fmt.Errorf("quarantine_release_audit: record: %w", err)
	}
	return entry, nil
}

// CountRecentByRecipient runs the rate-limit count query. The index
// `idx_qra_tenant_recipient_requested` from migration 0021 makes
// this an index-only scan on the hot partition. The
// `outcome NOT IN (...)` predicate filters out the auth-failure
// outcomes whose rows were written from unverified JWT claims; see
// the QuarantineReleaseAuditRepository interface doc for the threat
// model.
func (p *pgQuarantineReleaseAudit) CountRecentByRecipient(ctx context.Context, tenantID string, recipientUserHash []byte, since time.Time) (int, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("quarantine_release_audit: tenant_id is required")
	}
	if len(recipientUserHash) == 0 {
		return 0, fmt.Errorf("quarantine_release_audit: recipient_user_hash is required")
	}
	var count int
	err := p.db.QueryRowContext(ctx, `
SELECT count(*)
FROM quarantine_release_audit
WHERE tenant_id = $1
  AND recipient_user_hash = $2
  AND requested_at >= $3
  AND outcome NOT IN ('token_expired', 'invalid_token')`,
		tenantID, recipientUserHash, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("quarantine_release_audit: count: %w", err)
	}
	return count, nil
}

// ListByMessage returns audit rows newest first. The index
// `idx_qra_tenant_message_requested` from migration 0021 makes the
// ORDER BY + LIMIT N a pure index scan with no separate sort node.
func (p *pgQuarantineReleaseAudit) ListByMessage(ctx context.Context, tenantID, pseudoMessageID string, limit int) ([]QuarantineReleaseAuditEntry, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("quarantine_release_audit: tenant_id is required")
	}
	if pseudoMessageID == "" {
		return nil, fmt.Errorf("quarantine_release_audit: pseudo_message_id is required")
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.db.QueryContext(ctx, `
SELECT id, tenant_id, pseudo_message_id, recipient_user_hash, outcome, reason, correlation_id, requested_at, created_at
FROM quarantine_release_audit
WHERE tenant_id = $1
  AND pseudo_message_id = $2
ORDER BY requested_at DESC
LIMIT $3`,
		tenantID, pseudoMessageID, limit)
	if err != nil {
		return nil, fmt.Errorf("quarantine_release_audit: list: %w", err)
	}
	defer rows.Close()
	var out []QuarantineReleaseAuditEntry
	for rows.Next() {
		var e QuarantineReleaseAuditEntry
		var outcome string
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.PseudoMessageID, &e.RecipientUserHash,
			&outcome, &e.Reason, &e.CorrelationID, &e.RequestedAt, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("quarantine_release_audit: scan: %w", err)
		}
		e.Outcome = QuarantineReleaseOutcome(outcome)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("quarantine_release_audit: rows: %w", err)
	}
	return out, nil
}

// memoryQuarantineReleaseAudit implements the repository in-memory
// for unit tests. Concurrent access is guarded by an RWMutex so the
// fixture is safe for table-driven tests that share one instance
// across parallel sub-tests.
type memoryQuarantineReleaseAudit struct {
	mu      sync.RWMutex
	entries []QuarantineReleaseAuditEntry
}

// NewMemoryQuarantineReleaseAudit constructs an in-memory audit
// repository for tests.
func NewMemoryQuarantineReleaseAudit() QuarantineReleaseAuditRepository {
	return &memoryQuarantineReleaseAudit{}
}

func (m *memoryQuarantineReleaseAudit) Record(_ context.Context, entry QuarantineReleaseAuditEntry) (QuarantineReleaseAuditEntry, error) {
	if entry.TenantID == "" {
		return entry, fmt.Errorf("quarantine_release_audit: tenant_id is required")
	}
	if entry.PseudoMessageID == "" {
		return entry, fmt.Errorf("quarantine_release_audit: pseudo_message_id is required")
	}
	if len(entry.RecipientUserHash) == 0 {
		return entry, fmt.Errorf("quarantine_release_audit: recipient_user_hash is required")
	}
	if !entry.Outcome.Valid() {
		return entry, fmt.Errorf("quarantine_release_audit: outcome %q is not a known value", entry.Outcome)
	}
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if entry.RequestedAt.IsZero() {
		entry.RequestedAt = now
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	// Copy the hash slice so later mutations by the caller don't
	// leak into the stored row (memory backing must not alias).
	copied := make([]byte, len(entry.RecipientUserHash))
	copy(copied, entry.RecipientUserHash)
	entry.RecipientUserHash = copied
	m.mu.Lock()
	m.entries = append(m.entries, entry)
	m.mu.Unlock()
	return entry, nil
}

func (m *memoryQuarantineReleaseAudit) CountRecentByRecipient(_ context.Context, tenantID string, recipientUserHash []byte, since time.Time) (int, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("quarantine_release_audit: tenant_id is required")
	}
	if len(recipientUserHash) == 0 {
		return 0, fmt.Errorf("quarantine_release_audit: recipient_user_hash is required")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, e := range m.entries {
		if e.TenantID != tenantID {
			continue
		}
		if !bytes.Equal(e.RecipientUserHash, recipientUserHash) {
			continue
		}
		if e.RequestedAt.Before(since) {
			continue
		}
		// Exclude auth-failure outcomes — see the
		// QuarantineReleaseAuditRepository interface doc for
		// the threat model. Mirror the Postgres
		// `outcome NOT IN ('token_expired','invalid_token')`
		// predicate exactly so both implementations agree.
		if e.Outcome == QuarantineReleaseOutcomeTokenExpired ||
			e.Outcome == QuarantineReleaseOutcomeInvalidToken {
			continue
		}
		count++
	}
	return count, nil
}

func (m *memoryQuarantineReleaseAudit) ListByMessage(_ context.Context, tenantID, pseudoMessageID string, limit int) ([]QuarantineReleaseAuditEntry, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("quarantine_release_audit: tenant_id is required")
	}
	if pseudoMessageID == "" {
		return nil, fmt.Errorf("quarantine_release_audit: pseudo_message_id is required")
	}
	if limit <= 0 {
		limit = 100
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]QuarantineReleaseAuditEntry, 0, limit)
	for _, e := range m.entries {
		if e.TenantID != tenantID {
			continue
		}
		if e.PseudoMessageID != pseudoMessageID {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].RequestedAt.After(out[j].RequestedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
