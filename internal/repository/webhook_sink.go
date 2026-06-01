package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// WebhookSinkFormat is the closed set of formats a sink can publish.
// Values mirror the SQL CHECK constraint on tenant_webhook_sinks.format
// (migration 0025). Adding a value here requires a matching migration.
type WebhookSinkFormat string

const (
	// WebhookSinkFormatECS emits Elastic Common Schema JSON. Compatible
	// with Splunk HEC's "raw" endpoint, Elastic webhook input,
	// Sentinel Logic Apps custom-log connector.
	WebhookSinkFormatECS WebhookSinkFormat = "ecs"
	// WebhookSinkFormatCEF emits ArcSight CEF (pipe-delimited). The
	// canonical wire format for ArcSight, RSA NetWitness, McAfee
	// ESM, and most legacy SIEMs.
	WebhookSinkFormatCEF WebhookSinkFormat = "cef"
)

// AllWebhookSinkFormats lists every format value in a fixed order.
// Tests iterate this list to ensure the Go enum and the SQL CHECK
// constraint stay in sync.
var AllWebhookSinkFormats = []WebhookSinkFormat{
	WebhookSinkFormatECS,
	WebhookSinkFormatCEF,
}

// Valid reports whether f is one of the known formats.
func (f WebhookSinkFormat) Valid() bool {
	for _, known := range AllWebhookSinkFormats {
		if f == known {
			return true
		}
	}
	return false
}

// WebhookSinkAuditAction is the closed set of audit actions written
// to tenant_webhook_sink_audit.action. Mirrors the SQL CHECK
// constraint in migration 0025.
type WebhookSinkAuditAction string

const (
	// WebhookSinkAuditActionCreated records a successful POST.
	WebhookSinkAuditActionCreated WebhookSinkAuditAction = "created"
	// WebhookSinkAuditActionUpdated records a PATCH that modified
	// enabled/format/url/filters. Secret rotation has its own
	// dedicated action.
	WebhookSinkAuditActionUpdated WebhookSinkAuditAction = "updated"
	// WebhookSinkAuditActionDeleted records a soft-delete (DELETE
	// flips deleted_at and disables the sink).
	WebhookSinkAuditActionDeleted WebhookSinkAuditAction = "deleted"
	// WebhookSinkAuditActionSecretRotated records a fresh HMAC
	// secret being issued. The new plaintext secret is returned to
	// the caller exactly once and is NOT persisted to the audit
	// row.
	WebhookSinkAuditActionSecretRotated WebhookSinkAuditAction = "secret_rotated"
	// WebhookSinkAuditActionDispatchFailed records a DLQ
	// final-fail (max attempts exhausted). Reason carries the
	// last HTTP status + short cause string (no secrets, no
	// payload).
	WebhookSinkAuditActionDispatchFailed WebhookSinkAuditAction = "dispatch_failed"
)

// AllWebhookSinkAuditActions lists every action value in a fixed
// order. Tests iterate this list to keep the Go enum and the SQL
// CHECK in sync.
var AllWebhookSinkAuditActions = []WebhookSinkAuditAction{
	WebhookSinkAuditActionCreated,
	WebhookSinkAuditActionUpdated,
	WebhookSinkAuditActionDeleted,
	WebhookSinkAuditActionSecretRotated,
	WebhookSinkAuditActionDispatchFailed,
}

// Valid reports whether a is one of the known audit actions.
func (a WebhookSinkAuditAction) Valid() bool {
	for _, known := range AllWebhookSinkAuditActions {
		if a == known {
			return true
		}
	}
	return false
}

// WebhookSink is one row of `tenant_webhook_sinks` (migration 0025).
//
// HMACSecretCiphertext is the AES-GCM envelope blob produced by
// privacy.Encryptor under the tenant's KMS key. The plaintext
// 32-byte HMAC secret is shown to the operator ONCE in the create
// response and is never recoverable from this struct. Callers that
// need the plaintext to sign outbound publishes ask the encryptor to
// decrypt this field at use time.
type WebhookSink struct {
	ID                   string
	TenantID             string
	Name                 string
	URL                  string
	HMACSecretCiphertext []byte
	Format               WebhookSinkFormat
	EventFilters         WebhookSinkFilters
	Enabled              bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
	DeletedAt            *time.Time
}

// WebhookSinkFilters is the JSONB blob carried in
// tenant_webhook_sinks.event_filters. Unknown JSON keys are
// preserved in the underlying map so a forward-rolling deployment
// can store filter knobs a newer dispatcher understands.
//
// The strongly-typed fields are the canonical knobs the dispatcher
// reads today; arbitrary additional keys land in Extra. JSON
// round-trips merge the typed fields back into Extra on Marshal so
// the persisted shape is a flat object.
type WebhookSinkFilters struct {
	// MinTier is the lowest tier name (constant.Tier) the sink
	// should receive. Empty means "no minimum"; the dispatcher
	// then publishes every terminal verdict.
	MinTier string `json:"min_tier,omitempty"`
	// Categories restricts the sink to verdicts whose Primary
	// category is in this list. Empty means "no restriction".
	Categories []string `json:"categories,omitempty"`
	// RateLimitPerMinute overrides the per-sink rate limit
	// (default 100). Zero means "use default".
	RateLimitPerMinute int `json:"rate_limit_per_minute,omitempty"`
	// Extra carries unknown JSON fields verbatim so forward-rolling
	// stores written by newer code don't get clobbered on a
	// round-trip through an older dispatcher.
	Extra map[string]json.RawMessage `json:"-"`
}

// MarshalJSON merges the typed fields back into the Extra map so the
// persisted blob is a single flat object.
func (f WebhookSinkFilters) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(f.Extra)+3)
	for k, v := range f.Extra {
		out[k] = v
	}
	if f.MinTier != "" {
		b, err := json.Marshal(f.MinTier)
		if err != nil {
			return nil, err
		}
		out["min_tier"] = b
	}
	if len(f.Categories) > 0 {
		b, err := json.Marshal(f.Categories)
		if err != nil {
			return nil, err
		}
		out["categories"] = b
	}
	if f.RateLimitPerMinute > 0 {
		b, err := json.Marshal(f.RateLimitPerMinute)
		if err != nil {
			return nil, err
		}
		out["rate_limit_per_minute"] = b
	}
	return json.Marshal(out)
}

// UnmarshalJSON parses the typed fields and preserves unknown keys
// in Extra.
func (f *WebhookSinkFilters) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v, ok := raw["min_tier"]; ok {
		if err := json.Unmarshal(v, &f.MinTier); err != nil {
			return fmt.Errorf("webhook_sink_filters: min_tier: %w", err)
		}
		delete(raw, "min_tier")
	}
	if v, ok := raw["categories"]; ok {
		if err := json.Unmarshal(v, &f.Categories); err != nil {
			return fmt.Errorf("webhook_sink_filters: categories: %w", err)
		}
		delete(raw, "categories")
	}
	if v, ok := raw["rate_limit_per_minute"]; ok {
		if err := json.Unmarshal(v, &f.RateLimitPerMinute); err != nil {
			return fmt.Errorf("webhook_sink_filters: rate_limit_per_minute: %w", err)
		}
		delete(raw, "rate_limit_per_minute")
	}
	if len(raw) > 0 {
		f.Extra = raw
	}
	return nil
}

// WebhookSinkAuditEntry is one row of `tenant_webhook_sink_audit`.
type WebhookSinkAuditEntry struct {
	ID        string
	TenantID  string
	SinkID    string
	SinkName  string
	Action    WebhookSinkAuditAction
	Reason    string
	DedupID   string
	CreatedAt time.Time
}

// WebhookSinkRepository persists per-tenant webhook sink
// configuration and the matching audit trail.
//
// All Get/List operations filter out soft-deleted rows (deleted_at
// IS NOT NULL). Delete is a soft-delete: it stamps deleted_at and
// flips enabled=false so the dispatcher's hot-path partial index
// stops returning the row, but preserves the configuration for
// audit-trail forensics.
type WebhookSinkRepository interface {
	// Create inserts s. The caller is responsible for stamping
	// HMACSecretCiphertext (AES-encrypted) before calling.
	Create(ctx context.Context, s *WebhookSink) error
	// GetByID returns the sink for (tenant, id) or ErrNotFound.
	// Soft-deleted rows are not returned.
	GetByID(ctx context.Context, tenantID, id string) (*WebhookSink, error)
	// List returns every non-deleted sink for the tenant ordered
	// by name. Returns an empty slice (not nil) when the tenant
	// has no sinks.
	List(ctx context.Context, tenantID string) ([]WebhookSink, error)
	// ListEnabled returns every enabled, non-deleted sink for the
	// tenant. Used by the dispatcher hot path so the partial
	// index can serve an index-only scan.
	ListEnabled(ctx context.Context, tenantID string) ([]WebhookSink, error)
	// Update applies the supplied changes to (tenant, id). Only
	// non-nil fields in upd are written. Returns ErrNotFound when
	// no live row matches.
	Update(ctx context.Context, tenantID, id string, upd WebhookSinkUpdate) (*WebhookSink, error)
	// SoftDelete flips deleted_at = NOW() and enabled = FALSE on
	// (tenant, id) and returns a snapshot of the row as it stood
	// just before the soft-delete (name, URL, format, filters,
	// timestamps) so callers can write an audit row without a
	// separate GetByID lookup — that lookup would otherwise race
	// against the soft-delete itself, opening a TOCTOU window
	// where a concurrent Update would change the values the
	// audit row records. Returns ErrNotFound when no live row
	// matches; the returned sink is non-nil only on success.
	SoftDelete(ctx context.Context, tenantID, id string) (*WebhookSink, error)

	// AppendAudit inserts an audit row. INSERT-ON-CONFLICT on
	// (tenant_id, dedup_id) makes the call idempotent under
	// JetStream re-delivery — callers that want a guaranteed-
	// fresh row stamp a random dedup_id; callers that want
	// idempotent dispatch-failed rows stamp a deterministic
	// dedup_id derived from (sink_id, event_message_id, attempt).
	AppendAudit(ctx context.Context, e WebhookSinkAuditEntry) error
	// ListAudit returns audit rows for the tenant, newest-first,
	// capped at limit. limit <= 0 falls back to a sensible
	// default.
	ListAudit(ctx context.Context, tenantID string, limit int) ([]WebhookSinkAuditEntry, error)
}

// WebhookSinkUpdate is the patch shape for WebhookSinkRepository.Update.
// Nil pointer means "leave unchanged"; non-nil means "set to this".
// Name updates are not supported because (tenant_id, name) is the
// configuration UNIQUE — renames would force a chain of audit rows
// the WS-5B.2 surface doesn't support yet.
type WebhookSinkUpdate struct {
	URL                  *string
	HMACSecretCiphertext []byte
	Format               *WebhookSinkFormat
	EventFilters         *WebhookSinkFilters
	Enabled              *bool
}

// ----- Postgres implementation -------------------------------------------

type pgWebhookSinks struct{ db *postgres.DB }

// NewPgWebhookSinks constructs the Postgres-backed
// WebhookSinkRepository.
func NewPgWebhookSinks(db *postgres.DB) WebhookSinkRepository {
	if db == nil {
		panic("repository: db is required")
	}
	return &pgWebhookSinks{db: db}
}

func (p *pgWebhookSinks) Create(ctx context.Context, s *WebhookSink) error {
	if s == nil {
		return errors.New("repository: webhook sink is required")
	}
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	if s.Format == "" {
		s.Format = WebhookSinkFormatECS
	}
	filters, err := json.Marshal(s.EventFilters)
	if err != nil {
		return fmt.Errorf("marshal event_filters: %w", err)
	}
	now := time.Now().UTC()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now
	_, err = p.db.ExecContext(ctx, `
INSERT INTO tenant_webhook_sinks
  (id, tenant_id, name, url, hmac_secret, format, event_filters, enabled, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
`,
		s.ID, s.TenantID, s.Name, s.URL, s.HMACSecretCiphertext, string(s.Format), filters,
		s.Enabled, s.CreatedAt, s.UpdatedAt,
	)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (p *pgWebhookSinks) GetByID(ctx context.Context, tenantID, id string) (*WebhookSink, error) {
	const q = `
SELECT id, tenant_id, name, url, hmac_secret, format, event_filters, enabled,
       created_at, updated_at, deleted_at
  FROM tenant_webhook_sinks
 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`
	rows, err := p.queryAndScan(ctx, q, tenantID, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	cp := rows[0]
	return &cp, nil
}

func (p *pgWebhookSinks) List(ctx context.Context, tenantID string) ([]WebhookSink, error) {
	const q = `
SELECT id, tenant_id, name, url, hmac_secret, format, event_filters, enabled,
       created_at, updated_at, deleted_at
  FROM tenant_webhook_sinks
 WHERE tenant_id = $1 AND deleted_at IS NULL
 ORDER BY name`
	return p.queryAndScan(ctx, q, tenantID)
}

func (p *pgWebhookSinks) ListEnabled(ctx context.Context, tenantID string) ([]WebhookSink, error) {
	const q = `
SELECT id, tenant_id, name, url, hmac_secret, format, event_filters, enabled,
       created_at, updated_at, deleted_at
  FROM tenant_webhook_sinks
 WHERE tenant_id = $1 AND deleted_at IS NULL AND enabled = TRUE
 ORDER BY name`
	return p.queryAndScan(ctx, q, tenantID)
}

func (p *pgWebhookSinks) Update(ctx context.Context, tenantID, id string, upd WebhookSinkUpdate) (*WebhookSink, error) {
	// Build a dynamic UPDATE so unset fields stay untouched. We
	// always bump updated_at when SOMETHING changes — if every
	// patch field is nil-equivalent we still touch updated_at so
	// the audit row carries a meaningful timestamp.
	setClauses := []string{"updated_at = NOW()"}
	args := []any{tenantID, id}
	next := 3
	if upd.URL != nil {
		setClauses = append(setClauses, fmt.Sprintf("url = $%d", next))
		args = append(args, *upd.URL)
		next++
	}
	if upd.HMACSecretCiphertext != nil {
		setClauses = append(setClauses, fmt.Sprintf("hmac_secret = $%d", next))
		args = append(args, upd.HMACSecretCiphertext)
		next++
	}
	if upd.Format != nil {
		setClauses = append(setClauses, fmt.Sprintf("format = $%d", next))
		args = append(args, string(*upd.Format))
		next++
	}
	if upd.EventFilters != nil {
		b, err := json.Marshal(*upd.EventFilters)
		if err != nil {
			return nil, fmt.Errorf("marshal event_filters: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("event_filters = $%d", next))
		args = append(args, b)
		next++
	}
	if upd.Enabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("enabled = $%d", next))
		args = append(args, *upd.Enabled)
		// `next` is not referenced after the final clause — the
		// query is built below from setClauses + args.
	}
	// The full SQL is built with fmt.Sprintf so the WHERE
	// predicate (which carries `tenant_id = $1`) lives in the
	// same string literal as the table name. The tenant-lint
	// analyser inspects each literal independently — splitting
	// the SET clause across a `+` concatenation would lose the
	// predicate in the first literal and fail the gate.
	query := fmt.Sprintf(
		`UPDATE tenant_webhook_sinks SET %s WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
		joinSet(setClauses),
	)
	res, err := p.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrNotFound
	}
	return p.GetByID(ctx, tenantID, id)
}

func (p *pgWebhookSinks) SoftDelete(ctx context.Context, tenantID, id string) (*WebhookSink, error) {
	// RETURNING the full row in the same statement that performs
	// the soft-delete: the audit caller gets a consistent
	// snapshot atomically with the delete, eliminating any
	// TOCTOU window between a pre-delete GetByID and the
	// UPDATE. We expose the POST-update timestamps (updated_at /
	// deleted_at reflect this transaction) but every other
	// column is by definition the pre-delete value because the
	// UPDATE only touches the three fields below.
	rows, err := p.queryAndScan(ctx, `
UPDATE tenant_webhook_sinks
   SET deleted_at = NOW(), enabled = FALSE, updated_at = NOW()
 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
RETURNING id, tenant_id, name, url, hmac_secret, format, event_filters, enabled,
          created_at, updated_at, deleted_at
`, tenantID, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	cp := rows[0]
	return &cp, nil
}

func (p *pgWebhookSinks) AppendAudit(ctx context.Context, e WebhookSinkAuditEntry) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.DedupID == "" {
		return errors.New("repository: webhook sink audit dedup_id is required")
	}
	if !e.Action.Valid() {
		return fmt.Errorf("repository: invalid webhook sink audit action %q", e.Action)
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	// INSERT-ON-CONFLICT (tenant_id, dedup_id) for idempotent
	// final-fail recording under JetStream re-delivery. The
	// audit row is purely a record; on conflict the existing
	// row stays as the canonical record and we return nil.
	_, err := p.db.ExecContext(ctx, `
INSERT INTO tenant_webhook_sink_audit
  (id, tenant_id, sink_id, sink_name, action, reason, dedup_id, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (tenant_id, dedup_id) DO NOTHING
`, e.ID, e.TenantID, e.SinkID, e.SinkName, string(e.Action), nullableString(e.Reason), e.DedupID, e.CreatedAt)
	return err
}

func (p *pgWebhookSinks) ListAudit(ctx context.Context, tenantID string, limit int) ([]WebhookSinkAuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := p.db.QueryContext(ctx, `
SELECT id, tenant_id, sink_id, sink_name, action, COALESCE(reason,''), dedup_id, created_at
  FROM tenant_webhook_sink_audit
 WHERE tenant_id = $1
 ORDER BY created_at DESC
 LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]WebhookSinkAuditEntry, 0, limit)
	for rows.Next() {
		var e WebhookSinkAuditEntry
		var action string
		if err := rows.Scan(&e.ID, &e.TenantID, &e.SinkID, &e.SinkName, &action, &e.Reason, &e.DedupID, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Action = WebhookSinkAuditAction(action)
		out = append(out, e)
	}
	return out, rows.Err()
}

// queryAndScan executes the full SELECT query (which the caller is
// responsible for including the tenant_id predicate in — every
// caller does, and the tenant-lint analyser verifies it at build
// time) and decodes the resulting rows into WebhookSink values.
func (p *pgWebhookSinks) queryAndScan(ctx context.Context, query string, args ...any) ([]WebhookSink, error) {
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebhookSink{}
	for rows.Next() {
		var s WebhookSink
		var format string
		var filters []byte
		var deletedAt *time.Time
		if err := rows.Scan(&s.ID, &s.TenantID, &s.Name, &s.URL, &s.HMACSecretCiphertext, &format,
			&filters, &s.Enabled, &s.CreatedAt, &s.UpdatedAt, &deletedAt); err != nil {
			return nil, err
		}
		s.Format = WebhookSinkFormat(format)
		if len(filters) > 0 {
			if err := json.Unmarshal(filters, &s.EventFilters); err != nil {
				return nil, fmt.Errorf("decode event_filters: %w", err)
			}
		}
		s.DeletedAt = deletedAt
		out = append(out, s)
	}
	return out, rows.Err()
}

// joinSet renders a SET clause's column list as a comma-separated
// string. Kept local so we don't depend on strings.Join in a hot
// path that the database driver immediately re-parses.
func joinSet(clauses []string) string {
	var b bytes.Buffer
	for i, c := range clauses {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(c)
	}
	return b.String()
}

// nullableString returns a sql-friendly value for an audit reason
// column: empty Go string is persisted as SQL NULL so the `reason`
// nullable column can distinguish "not set" from "set to empty".
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ----- In-memory implementation (test fixture) ---------------------------

type memoryWebhookSinks struct {
	mu     sync.RWMutex
	sinks  map[string]WebhookSink           // id → sink
	audit  map[string]WebhookSinkAuditEntry // dedup_id → entry
	auditO []string                         // dedup_id order, newest last
}

func newMemoryWebhookSinks() *memoryWebhookSinks {
	return &memoryWebhookSinks{
		sinks: map[string]WebhookSink{},
		audit: map[string]WebhookSinkAuditEntry{},
	}
}

func (m *memoryWebhookSinks) Create(_ context.Context, s *WebhookSink) error {
	if s == nil {
		return errors.New("repository: webhook sink is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.sinks {
		if existing.TenantID == s.TenantID && existing.Name == s.Name && existing.DeletedAt == nil {
			return ErrConflict
		}
	}
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	if s.Format == "" {
		s.Format = WebhookSinkFormatECS
	}
	now := time.Now().UTC()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now
	m.sinks[s.ID] = *s
	return nil
}

func (m *memoryWebhookSinks) GetByID(_ context.Context, tenantID, id string) (*WebhookSink, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sinks[id]
	if !ok || s.TenantID != tenantID || s.DeletedAt != nil {
		return nil, ErrNotFound
	}
	cp := s
	return &cp, nil
}

func (m *memoryWebhookSinks) List(_ context.Context, tenantID string) ([]WebhookSink, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []WebhookSink{}
	for _, s := range m.sinks {
		if s.TenantID == tenantID && s.DeletedAt == nil {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memoryWebhookSinks) ListEnabled(_ context.Context, tenantID string) ([]WebhookSink, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []WebhookSink{}
	for _, s := range m.sinks {
		if s.TenantID == tenantID && s.DeletedAt == nil && s.Enabled {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memoryWebhookSinks) Update(_ context.Context, tenantID, id string, upd WebhookSinkUpdate) (*WebhookSink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sinks[id]
	if !ok || s.TenantID != tenantID || s.DeletedAt != nil {
		return nil, ErrNotFound
	}
	if upd.URL != nil {
		s.URL = *upd.URL
	}
	if upd.HMACSecretCiphertext != nil {
		s.HMACSecretCiphertext = upd.HMACSecretCiphertext
	}
	if upd.Format != nil {
		s.Format = *upd.Format
	}
	if upd.EventFilters != nil {
		s.EventFilters = *upd.EventFilters
	}
	if upd.Enabled != nil {
		s.Enabled = *upd.Enabled
	}
	s.UpdatedAt = time.Now().UTC()
	m.sinks[id] = s
	cp := s
	return &cp, nil
}

func (m *memoryWebhookSinks) SoftDelete(_ context.Context, tenantID, id string) (*WebhookSink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sinks[id]
	if !ok || s.TenantID != tenantID || s.DeletedAt != nil {
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	s.DeletedAt = &now
	s.Enabled = false
	s.UpdatedAt = now
	m.sinks[id] = s
	cp := s
	return &cp, nil
}

func (m *memoryWebhookSinks) AppendAudit(_ context.Context, e WebhookSinkAuditEntry) error {
	if e.DedupID == "" {
		return errors.New("repository: webhook sink audit dedup_id is required")
	}
	if e.TenantID == "" {
		return errors.New("repository: webhook sink audit tenant_id is required")
	}
	if !e.Action.Valid() {
		return fmt.Errorf("repository: invalid webhook sink audit action %q", e.Action)
	}
	// Dedup is scoped to (tenant_id, dedup_id) to match the Postgres
	// UNIQUE constraint in migration 0025. A global-on-dedup_id key
	// would silently swallow a second tenant emitting the same
	// dedup string and produce diverging behavior under cross-tenant
	// tests.
	key := e.TenantID + "\x00" + e.DedupID
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.audit[key]; exists {
		// Idempotent — silently drop duplicate.
		return nil
	}
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	m.audit[key] = e
	m.auditO = append(m.auditO, key)
	return nil
}

func (m *memoryWebhookSinks) ListAudit(_ context.Context, tenantID string, limit int) ([]WebhookSinkAuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]WebhookSinkAuditEntry, 0, limit)
	for i := len(m.auditO) - 1; i >= 0 && len(out) < limit; i-- {
		e := m.audit[m.auditO[i]]
		if e.TenantID != tenantID {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
