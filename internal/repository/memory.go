package repository

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// NewInMemoryRegistry returns a Registry backed by goroutine-safe
// in-memory maps. It is intended for unit tests; the same interface is
// implemented by *_pg.go against Postgres.
func NewInMemoryRegistry() *Registry {
	return &Registry{
		Tenants:                newMemoryTenants(),
		Users:                  newMemoryUsers(),
		Groups:                 newMemoryGroups(),
		GroupMemberships:       newMemoryGroupMemberships(),
		Labels:                 newMemoryLabels(),
		ScoreEngines:           newMemoryScoreEngines(),
		EmailClassifications:   newMemoryClassifications(),
		Vendors:                newMemoryVendors(),
		EvaluationResults:      newMemoryEvalResults(),
		CommunicationHistories: newMemoryCommHistory(),
		FeedbackEvents:         newMemoryFeedbackEvents(),
		AuditLogs:              NewMemoryAuditLogs(),
		SyncCheckpoints:        newMemorySyncCheckpoints(),
		BehavioralBaselines:    newMemoryBehavioralBaselines(),
		OrgGraphs:              newMemoryOrgGraphs(),
		QuarantineReleaseAudit: NewMemoryQuarantineReleaseAudit(),
		TenantReleasePolicies:  NewMemoryTenantReleasePolicy(),
		EmailVerdictAudits:     newMemoryEmailVerdictAudits(),
		BannerStates:           newMemoryBannerStates(),
		WebhookSinks:           newMemoryWebhookSinks(),
	}
}

// --- tenants ------------------------------------------------------------

type memoryTenants struct {
	mu     sync.RWMutex
	byID   map[string]Tenant
	byName map[string]string
}

func newMemoryTenants() *memoryTenants {
	return &memoryTenants{byID: map[string]Tenant{}, byName: map[string]string{}}
}

func (m *memoryTenants) Create(_ context.Context, t *Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byName[t.Name]; exists {
		return ErrConflict
	}
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	m.byID[t.ID] = *t
	m.byName[t.Name] = t.ID
	return nil
}

func (m *memoryTenants) GetByID(_ context.Context, id string) (*Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := t
	return &cp, nil
}

func (m *memoryTenants) GetByName(_ context.Context, name string) (*Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byName[name]
	if !ok {
		return nil, ErrNotFound
	}
	t := m.byID[id]
	return &t, nil
}

func (m *memoryTenants) UpdateStatus(_ context.Context, id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	t.Status = status
	t.UpdatedAt = time.Now().UTC()
	m.byID[id] = t
	return nil
}

func (m *memoryTenants) List(_ context.Context, limit int) ([]Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Tenant, 0, len(m.byID))
	for _, t := range m.byID {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// IterateActive yields non-deleted tenants in (name, id) order in
// batches of batchSize. The in-memory implementation snapshots the
// store under the read-lock and then yields outside the lock so
// long-running per-tenant work in yield cannot block writes. The
// snapshot is bounded by the in-memory tenant count (test/dev
// fixtures), so this is acceptable; the Postgres implementation
// uses keyset pagination instead.
func (m *memoryTenants) IterateActive(ctx context.Context, batchSize int, yield func([]Tenant) error) error {
	if batchSize <= 0 {
		batchSize = 100
	}
	m.mu.RLock()
	snapshot := make([]Tenant, 0, len(m.byID))
	for _, t := range m.byID {
		// Note: memory store does not model deleted_at; status
		// "deleted" maps to the same exclusion behaviour as the
		// Postgres `deleted_at IS NULL` clause so the two
		// implementations stay drop-in compatible.
		if t.Status == "deleted" {
			continue
		}
		snapshot = append(snapshot, t)
	}
	m.mu.RUnlock()
	sort.Slice(snapshot, func(i, j int) bool {
		if snapshot[i].Name == snapshot[j].Name {
			return snapshot[i].ID < snapshot[j].ID
		}
		return snapshot[i].Name < snapshot[j].Name
	})
	for start := 0; start < len(snapshot); start += batchSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := start + batchSize
		if end > len(snapshot) {
			end = len(snapshot)
		}
		if err := yield(snapshot[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// --- users --------------------------------------------------------------

type memoryUsers struct {
	mu sync.RWMutex
	// keyed by tenant+hex(emailHash)
	rows map[string]User
}

func newMemoryUsers() *memoryUsers { return &memoryUsers{rows: map[string]User{}} }

func (m *memoryUsers) Upsert(_ context.Context, u *User) error {
	if u.TenantID == "" || len(u.EmailHash) == 0 {
		return ErrConflict
	}
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[u.TenantID+":"+hex.EncodeToString(u.EmailHash)] = *u
	return nil
}

func (m *memoryUsers) GetByHash(_ context.Context, tenantID string, emailHash []byte) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.rows[tenantID+":"+hex.EncodeToString(emailHash)]
	if !ok {
		return nil, ErrNotFound
	}
	return &u, nil
}

func (m *memoryUsers) List(_ context.Context, tenantID string, limit int) ([]User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.rows))
	for _, u := range m.rows {
		if u.TenantID == tenantID {
			out = append(out, u)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memoryUsers) Count(_ context.Context, tenantID string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, u := range m.rows {
		if u.TenantID == tenantID {
			n++
		}
	}
	return n, nil
}

// --- groups -------------------------------------------------------------

type memoryGroups struct {
	mu     sync.RWMutex
	rows   map[string]Group
	byName map[string]string
}

func newMemoryGroups() *memoryGroups {
	return &memoryGroups{rows: map[string]Group{}, byName: map[string]string{}}
}

func (m *memoryGroups) Create(_ context.Context, g *Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := g.TenantID + ":" + g.Name
	if _, exists := m.byName[key]; exists {
		return ErrConflict
	}
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if g.CreatedAt.IsZero() {
		g.CreatedAt = now
	}
	g.UpdatedAt = now
	m.rows[g.ID] = *g
	m.byName[key] = g.ID
	return nil
}

func (m *memoryGroups) Upsert(_ context.Context, g *Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := g.TenantID + ":" + g.Name
	if g.ID == "" {
		if existingID, exists := m.byName[key]; exists {
			g.ID = existingID
		} else {
			g.ID = uuid.NewString()
		}
	}
	now := time.Now().UTC()
	if g.CreatedAt.IsZero() {
		if existing, ok := m.rows[g.ID]; ok {
			g.CreatedAt = existing.CreatedAt
		} else {
			g.CreatedAt = now
		}
	}
	g.UpdatedAt = now
	m.rows[g.ID] = *g
	m.byName[key] = g.ID
	return nil
}

func (m *memoryGroups) GetByName(_ context.Context, tenantID, name string) (*Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byName[tenantID+":"+name]
	if !ok {
		return nil, ErrNotFound
	}
	g := m.rows[id]
	return &g, nil
}

func (m *memoryGroups) List(_ context.Context, tenantID string) ([]Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Group, 0)
	for _, g := range m.rows {
		if g.TenantID == tenantID {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memoryGroups) Count(_ context.Context, tenantID string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, g := range m.rows {
		if g.TenantID == tenantID {
			n++
		}
	}
	return n, nil
}

// --- labels -------------------------------------------------------------

type memoryLabels struct {
	mu   sync.RWMutex
	rows map[string]Label
}

func newMemoryLabels() *memoryLabels { return &memoryLabels{rows: map[string]Label{}} }

func labelKey(l *Label) string {
	return l.TenantID + ":" + l.Provider + ":" + l.Tier + ":" + l.Category
}

func (m *memoryLabels) Upsert(_ context.Context, l *Label) error {
	if l.ID == "" {
		l.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if l.CreatedAt.IsZero() {
		l.CreatedAt = now
	}
	l.UpdatedAt = now
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[labelKey(l)] = *l
	return nil
}

func (m *memoryLabels) ListByTenant(_ context.Context, tenantID, provider string) ([]Label, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Label, 0)
	for _, l := range m.rows {
		if l.TenantID == tenantID && l.Provider == provider {
			out = append(out, l)
		}
	}
	return out, nil
}

// --- score engines ------------------------------------------------------

type memoryScoreEngines struct {
	mu   sync.RWMutex
	rows map[string]ScoreEngine
}

func newMemoryScoreEngines() *memoryScoreEngines {
	return &memoryScoreEngines{rows: map[string]ScoreEngine{}}
}

func (m *memoryScoreEngines) Get(_ context.Context, tenantID string) (*ScoreEngine, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.rows[tenantID]
	if !ok {
		return nil, ErrNotFound
	}
	return &s, nil
}

func (m *memoryScoreEngines) Upsert(_ context.Context, s *ScoreEngine) error {
	s.UpdatedAt = time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[s.TenantID] = *s
	return nil
}

func (m *memoryScoreEngines) UpdateWeights(_ context.Context, tenantID string, w ScoreWeightUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[tenantID]
	if !ok {
		return ErrNotFound
	}
	row.WeightAI = w.WeightAI
	row.WeightRspamd = w.WeightRspamd
	row.WeightAttachments = w.WeightAttachments
	row.WeightLinks = w.WeightLinks
	row.UpdatedAt = time.Now().UTC()
	m.rows[tenantID] = row
	return nil
}

func (m *memoryScoreEngines) UpdateThresholds(_ context.Context, tenantID string, t ScoreThresholdUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[tenantID]
	if !ok {
		return ErrNotFound
	}
	row.ThresholdBlocked = t.Blocked
	row.ThresholdHigh = t.High
	row.ThresholdWarning = t.Warning
	row.ThresholdCaution = t.Caution
	row.ThresholdInfo = t.Info
	row.ThresholdTier1PassBelow = t.Tier1PassBelow
	row.ThresholdTier1FlagAbove = t.Tier1FlagAbove
	row.UpdatedAt = time.Now().UTC()
	m.rows[tenantID] = row
	return nil
}

// --- email classifications ----------------------------------------------

type memoryClassifications struct {
	mu   sync.RWMutex
	rows map[string]EmailClassification
}

func newMemoryClassifications() *memoryClassifications {
	return &memoryClassifications{rows: map[string]EmailClassification{}}
}

func (m *memoryClassifications) Upsert(_ context.Context, e *EmailClassification) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	e.UpdatedAt = time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[e.Domain+":"+e.Classification] = *e
	return nil
}

func (m *memoryClassifications) GetByDomain(_ context.Context, domain string) ([]EmailClassification, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]EmailClassification, 0)
	for _, e := range m.rows {
		if e.Domain == domain {
			out = append(out, e)
		}
	}
	return out, nil
}

// --- vendors ------------------------------------------------------------

type memoryVendors struct {
	mu   sync.RWMutex
	rows map[string]Vendor
}

func newMemoryVendors() *memoryVendors { return &memoryVendors{rows: map[string]Vendor{}} }

func vendorKey(v *Vendor) string { return v.TenantID + ":" + v.Domain }

func (m *memoryVendors) Upsert(_ context.Context, v *Vendor) error {
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if v.CreatedAt.IsZero() {
		v.CreatedAt = now
	}
	v.UpdatedAt = now
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[vendorKey(v)] = *v
	return nil
}

func (m *memoryVendors) GetByDomain(_ context.Context, tenantID, domain string) (*Vendor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.rows[tenantID+":"+domain]
	if !ok {
		return nil, ErrNotFound
	}
	return &v, nil
}

func (m *memoryVendors) ListApproved(_ context.Context, tenantID string) ([]Vendor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Vendor, 0)
	for _, v := range m.rows {
		if v.TenantID == tenantID && v.Approved {
			out = append(out, v)
		}
	}
	return out, nil
}

func (m *memoryVendors) List(_ context.Context, tenantID string, limit int) ([]Vendor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Vendor, 0)
	for _, v := range m.rows {
		if v.TenantID == tenantID {
			out = append(out, v)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (m *memoryVendors) Delete(_ context.Context, tenantID, domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID + ":" + domain
	delete(m.rows, key)
	return nil
}

// --- evaluation results -------------------------------------------------

type memoryEvalResults struct {
	mu     sync.RWMutex
	rows   []EvaluationResult
	byHash map[string]int
}

func newMemoryEvalResults() *memoryEvalResults {
	return &memoryEvalResults{byHash: map[string]int{}}
}

func evalKey(r *EvaluationResult) string {
	return r.TenantID + ":" + hex.EncodeToString(r.MessageIDHash)
}

func (m *memoryEvalResults) Create(_ context.Context, r *EvaluationResult) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	if r.EvaluatedAt.IsZero() {
		r.EvaluatedAt = now
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := evalKey(r)
	if _, exists := m.byHash[key]; exists {
		return ErrConflict
	}
	m.rows = append(m.rows, *r)
	m.byHash[key] = len(m.rows) - 1
	return nil
}

func (m *memoryEvalResults) GetByMessageHash(_ context.Context, tenantID string, messageIDHash []byte) (*EvaluationResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	idx, ok := m.byHash[tenantID+":"+hex.EncodeToString(messageIDHash)]
	if !ok {
		return nil, ErrNotFound
	}
	r := m.rows[idx]
	return &r, nil
}

func (m *memoryEvalResults) ListRecent(_ context.Context, tenantID string, limit int) ([]EvaluationResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]EvaluationResult, 0, len(m.rows))
	for i := len(m.rows) - 1; i >= 0; i-- {
		r := m.rows[i]
		if r.TenantID == tenantID {
			out = append(out, r)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// ListBySender returns rows for (tenantID, senderHash) sorted by
// EvaluatedAt descending and capped at
// min(limit, EvalListBySenderMaxLimit). Mirrors the Postgres
// backend's WHERE sender_hash IS NOT NULL guard by short-circuiting
// on an empty senderHash argument — callers must supply a
// non-empty pseudonym for the predicate to be meaningful.
func (m *memoryEvalResults) ListBySender(_ context.Context, tenantID string, senderHash []byte, limit int) ([]EvaluationResult, error) {
	limit = clampEvalListBySenderLimit(limit)
	if len(senderHash) == 0 {
		return []EvaluationResult{}, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]EvaluationResult, 0)
	for _, r := range m.rows {
		if r.TenantID != tenantID {
			continue
		}
		if len(r.SenderHash) == 0 {
			// Legacy row written before the WS-3b producer stamped
			// a hash. The Postgres partial index excludes these;
			// mirror that exclusion here so tests against the
			// in-memory registry see the same row set as production.
			continue
		}
		if !bytes.Equal(r.SenderHash, senderHash) {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].EvaluatedAt.After(out[j].EvaluatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// SetFinalVerdict mirrors the Postgres backend's update path.
// Validates the verdict against the schema's CHECK constraint
// values, then mutates the in-memory row in place. Returns
// ErrNotFound when no row matches (tenantID, messageIDHash) so
// the resolver's skip-with-reason path stays identical between
// the in-memory tests and the production backend.
func (m *memoryEvalResults) SetFinalVerdict(_ context.Context, tenantID string, messageIDHash []byte, verdict string) error {
	switch verdict {
	case "", "malicious", "suspicious", "benign":
	default:
		return errors.New("repository: SetFinalVerdict: invalid verdict")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Use the byHash secondary index rather than a linear scan
	// so the in-memory backend matches the production backend's
	// algorithmic shape (Postgres uses the same (tenant_id,
	// message_id_hash) UNIQUE index for its UPDATE WHERE). Every
	// other read path on memoryEvalResults already keys through
	// byHash; the early implementation here was a leftover from
	// before the index existed.
	idx, ok := m.byHash[tenantID+":"+hex.EncodeToString(messageIDHash)]
	if !ok {
		return ErrNotFound
	}
	m.rows[idx].FinalVerdict = verdict
	return nil
}

// --- communication histories --------------------------------------------

type memoryCommHistory struct {
	mu   sync.RWMutex
	rows map[string]CommunicationHistory
}

func newMemoryCommHistory() *memoryCommHistory {
	return &memoryCommHistory{rows: map[string]CommunicationHistory{}}
}

func commKey(tenantID string, sender, recipient []byte) string {
	return tenantID + ":" + hex.EncodeToString(sender) + ":" + hex.EncodeToString(recipient)
}

// cloneOrEmpty returns an independent copy of src. When src is nil it
// returns a non-nil zero-length []byte so the result matches the
// Postgres BYTEA NOT NULL column shape ("”::bytea"). Used by the
// memoryCommHistory write paths that mirror Postgres column semantics
// across the two backends.
func cloneOrEmpty(src []byte) []byte {
	if src == nil {
		return []byte{}
	}
	return append([]byte(nil), src...)
}

func (m *memoryCommHistory) Upsert(_ context.Context, h *CommunicationHistory) error {
	// h.ID generation is the one mutation we deliberately mirror
	// from the Postgres backend: pgCommHistory.Upsert also does
	// `h.ID = uuid.NewString()` when the caller passes the empty
	// string, so the two backends agree that ID-assignment-on-
	// missing is part of the Upsert contract. Every other field
	// the column-preservation logic below cares about is mutated
	// only on the local row copy, never on the caller's struct.
	if h.ID == "" {
		h.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	key := commKey(h.TenantID, h.SenderHash, h.RecipientHash)
	// Upsert is the ingestion-time write path. The persisted row
	// is built from a *local copy* of h so the caller's struct is
	// not mutated by the column-preservation logic below — this
	// matches the Postgres implementation, which writes via SQL
	// and leaves the Go struct untouched for every column except
	// the one ID mutation above. In particular FirstSeenAt and
	// UpdatedAt are now set on the row copy, not on *h, so a
	// caller inspecting `h.UpdatedAt` after Upsert sees the same
	// thing they passed in (typically the Go zero value), exactly
	// as they would with the pgCommHistory backend whose SQL uses
	// `updated_at = NOW()` and never reflects the post-write
	// timestamp back into the Go struct.
	//
	// On the existing-row branch the persisted row preserves the
	// three columns the Postgres ON CONFLICT clause deliberately
	// leaves out of its DO UPDATE SET:
	//
	//   - id            : the primary key is row-stable; Postgres
	//                     never re-assigns it on conflict. Memory
	//                     mirrors that, even though the caller's
	//                     h.ID was set to a fresh UUID at the top
	//                     of Upsert (same wasted-UUID quirk both
	//                     backends share for the new-row case).
	//   - first_seen_at : the rolling window's lower bound is
	//                     monotonic — once observed, the timestamp
	//                     of the first sighting must never advance
	//                     backwards. The Tier 0 FirstTimeExternal
	//                     heuristic depends on this stability.
	//   - typical_hour  : owned by UpdateCountsIfFresh (the
	//                     relationship-worker CAS path); Upsert
	//                     never overwrites the worker-computed
	//                     modal hour. This eliminates the Go
	//                     zero-value trap whereby h.TypicalHour
	//                     left at the int zero value (0 ==
	//                     midnight UTC) would silently clobber the
	//                     worker's value.
	row := *h
	if cur, ok := m.rows[key]; ok {
		row.ID = cur.ID
		row.FirstSeenAt = cur.FirstSeenAt
		row.TypicalHour = cur.TypicalHour
	} else {
		row.TypicalHour = TypicalHourUnset
		// New-row: mirror the Postgres column default
		// `first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
		// (migrations/0001_init.up.sql:216) when the caller
		// omitted it. nullableTime() in pgCommHistory.Upsert
		// passes nil to SQL for a zero FirstSeenAt, which lets
		// the column default fire; we do the equivalent here on
		// the row copy so the persisted state matches without
		// touching the caller's struct.
		if row.FirstSeenAt.IsZero() {
			row.FirstSeenAt = now
		}
	}
	// Mirror Postgres `updated_at = NOW()` SQL semantics on the
	// row copy so the persisted state has a fresh stamp but the
	// caller's *h.UpdatedAt is untouched.
	row.UpdatedAt = now
	m.rows[key] = row
	return nil
}

// directSetTypicalHourForTest bypasses the Upsert contract to seed a
// worker-computed modal hour into the in-memory row. It exists
// solely so the memory_test suite can lock in the
// Upsert-does-not-write-typical_hour contract without spinning up a
// full RelationshipJob. NOT for production use.
func (m *memoryCommHistory) directSetTypicalHourForTest(tenantID string, senderHash, recipientHash []byte, hour int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := commKey(tenantID, senderHash, recipientHash)
	cur, ok := m.rows[key]
	if !ok {
		return ErrNotFound
	}
	cur.TypicalHour = hour
	m.rows[key] = cur
	return nil
}

func (m *memoryCommHistory) Get(_ context.Context, tenantID string, senderHash, recipientHash []byte) (*CommunicationHistory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.rows[commKey(tenantID, senderHash, recipientHash)]
	if !ok {
		return nil, ErrNotFound
	}
	return &h, nil
}

// ListByTenant returns rows for tenantID whose LastSeenAt is at or
// after `since`, sorted by LastSeenAt descending and capped at
// min(limit, CommHistoryListByTenantMaxLimit). The clamp is
// identical to the Postgres implementation so tests using the
// in-memory registry behave identically to production.
func (m *memoryCommHistory) ListByTenant(_ context.Context, tenantID string, since time.Time, limit int) ([]CommunicationHistory, error) {
	limit = clampCommHistoryLimit(limit)
	m.mu.RLock()
	defer m.mu.RUnlock()
	rows := make([]CommunicationHistory, 0)
	for _, h := range m.rows {
		if h.TenantID != tenantID {
			continue
		}
		if !since.IsZero() && h.LastSeenAt.Before(since) {
			continue
		}
		rows = append(rows, h)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].LastSeenAt.After(rows[j].LastSeenAt)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

// UpdateCountsIfFresh is the optimistic-concurrency CAS write the
// relationship worker uses to avoid clobbering ingestion-time
// increments with a stale snapshot. See the docstring on
// CommunicationHistoryRepository.UpdateCountsIfFresh for the
// semantic contract; this implementation mirrors the Postgres
// version by gating the in-memory write on `UpdatedAt == readAt`.
func (m *memoryCommHistory) UpdateCountsIfFresh(_ context.Context, h *CommunicationHistory, readAt time.Time) (bool, error) {
	if h == nil || h.ID == "" {
		return false, errors.New("repository: UpdateCountsIfFresh requires a row id")
	}
	if h.TenantID == "" {
		// Mirror the Postgres implementation: tenant_id is part of
		// the optimistic-lock predicate so a poisoned row id cannot
		// reach across tenants.
		return false, errors.New("repository: UpdateCountsIfFresh requires a tenant id")
	}
	if readAt.IsZero() {
		return false, errors.New("repository: UpdateCountsIfFresh requires a non-zero readAt")
	}
	key := commKey(h.TenantID, h.SenderHash, h.RecipientHash)
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.rows[key]
	if !ok {
		return false, ErrNotFound
	}
	// Defence in depth: even though commKey already incorporates
	// tenantID, an attacker who somehow forged the in-memory map
	// keys would still be blocked by this tenant_id comparison.
	if cur.TenantID != h.TenantID {
		return false, ErrNotFound
	}
	if !cur.UpdatedAt.Equal(readAt) {
		return false, nil
	}
	cur.Count7d = h.Count7d
	cur.Relationship = h.Relationship
	// typical_hour: only overwrite when the worker has computed a
	// valid 0..23 modal hour. The sentinel -1 ("no baseline yet")
	// or any out-of-range value preserves the existing column
	// value — same contract as the Postgres implementation.
	if h.TypicalHour >= 0 && h.TypicalHour < 24 {
		cur.TypicalHour = h.TypicalHour
	}
	cur.UpdatedAt = time.Now().UTC()
	m.rows[key] = cur
	// UpdateCountsIfFresh contract: callers MUST NOT inspect *h
	// after a successful CAS; the canonical post-write row state
	// lives in the repository. The Postgres implementation uses
	// ExecContext (no RETURNING), so its caller sees no reflection
	// of the fresh UpdatedAt or merged TypicalHour either. Keeping
	// the in-memory implementation deliberately non-reflective
	// avoids a behaviour divergence that would otherwise hide
	// bugs in tests (memory) that production (Postgres) would
	// surface.
	return true, nil
}

// RecordSighting is the WS-4a incremental write path. See the
// docstring on CommunicationHistoryRepository.RecordSighting for the
// semantic contract; this in-memory implementation mirrors the
// Postgres SQL by performing an atomic-by-mutex compare-and-write on
// the keyed map row.
func (m *memoryCommHistory) RecordSighting(_ context.Context, s Sighting) error {
	if s.TenantID == "" {
		return errors.New("repository: RecordSighting requires a tenant id")
	}
	if len(s.SenderHash) == 0 || len(s.RecipientHash) == 0 {
		return errors.New("repository: RecordSighting requires non-empty sender and recipient hashes")
	}
	if s.SentAt.IsZero() {
		return errors.New("repository: RecordSighting requires a non-zero SentAt")
	}
	now := time.Now().UTC()
	key := commKey(s.TenantID, s.SenderHash, s.RecipientHash)
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.rows[key]
	if !ok {
		// New row: count_7d / count_30d start at 1 (this is the
		// first sighting). FirstSeenAt == LastSeenAt == SentAt.
		// TypicalHour is initialised to the sentinel so the
		// worker's CAS path stays in charge of computing it; if a
		// later Upsert path ever re-creates the row, the same
		// sentinel guard applies.
		//
		// SenderDomainHash is normalised to a non-nil zero-length
		// slice when the sighting carries no domain hash, to match
		// the Postgres backend which stores `''::bytea` for the
		// BYTEA NOT NULL column. Without this normalisation, the
		// memory row's SenderDomainHash would be nil while the
		// Postgres row's would be `[]byte{}`; both have len()==0
		// so functional behaviour is identical, but tests that
		// reach for `bytes.Equal(x, nil)` vs `bytes.Equal(x,
		// []byte{})` see different shapes across backends. Keeping
		// representations identical removes that footgun.
		row := CommunicationHistory{
			ID:               uuid.NewString(),
			TenantID:         s.TenantID,
			SenderHash:       append([]byte(nil), s.SenderHash...),
			RecipientHash:    append([]byte(nil), s.RecipientHash...),
			SenderDomainHash: cloneOrEmpty(s.SenderDomainHash),
			SenderDomain:     s.SenderDomain,
			Count7d:          1,
			Count30d:         1,
			FirstSeenAt:      s.SentAt,
			LastSeenAt:       s.SentAt,
			Relationship:     "",
			TypicalHour:      TypicalHourUnset,
			UpdatedAt:        now,
		}
		m.rows[key] = row
		return nil
	}
	// Existing row: atomic increment + last_seen_at advancement.
	cur.Count30d++
	cur.Count7d++
	if s.SentAt.After(cur.LastSeenAt) {
		cur.LastSeenAt = s.SentAt
	}
	// Backfill sender_domain only when the persisted row's domain
	// is empty AND the sighting carries a non-empty domain. See
	// the interface docstring for why this is a one-way
	// transition: filling-in a missing value is safe, but
	// overwriting a persisted value risks losing legitimate
	// publisher state on a forwarded message.
	if cur.SenderDomain == "" && s.SenderDomain != "" {
		cur.SenderDomain = s.SenderDomain
	}
	if len(cur.SenderDomainHash) == 0 && len(s.SenderDomainHash) > 0 {
		cur.SenderDomainHash = append([]byte(nil), s.SenderDomainHash...)
	}
	cur.UpdatedAt = now
	m.rows[key] = cur
	return nil
}

// ListBySender returns rows for (tenantID, senderHash) sorted by
// LastSeenAt descending and capped at
// min(limit, CommHistoryListByTenantMaxLimit). The clamp matches
// the Postgres backend so the WS-3b investigation API sees the
// same slice regardless of backend.
func (m *memoryCommHistory) ListBySender(_ context.Context, tenantID string, senderHash []byte, limit int) ([]CommunicationHistory, error) {
	limit = clampCommHistoryLimit(limit)
	if len(senderHash) == 0 {
		return []CommunicationHistory{}, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rows := make([]CommunicationHistory, 0)
	for _, h := range m.rows {
		if h.TenantID != tenantID {
			continue
		}
		if !bytes.Equal(h.SenderHash, senderHash) {
			continue
		}
		rows = append(rows, h)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].LastSeenAt.After(rows[j].LastSeenAt)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

// --- feedback events ----------------------------------------------------

type memoryFeedbackEvents struct {
	mu   sync.RWMutex
	rows []FeedbackEvent
}

func newMemoryFeedbackEvents() *memoryFeedbackEvents {
	return &memoryFeedbackEvents{}
}

func (m *memoryFeedbackEvents) Create(_ context.Context, e *FeedbackEvent) error {
	if e == nil {
		return ErrNotFound
	}
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = now
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows = append(m.rows, *e)
	return nil
}

func (m *memoryFeedbackEvents) Counts(_ context.Context, tenantID string, start, end time.Time) (FeedbackCounts, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var c FeedbackCounts
	for _, r := range m.rows {
		if r.TenantID != tenantID {
			continue
		}
		if !start.IsZero() && r.OccurredAt.Before(start) {
			continue
		}
		if !end.IsZero() && !r.OccurredAt.Before(end) {
			continue
		}
		switch r.Action {
		case "report_phishing":
			c.ReportedPhishing++
		case "mark_safe":
			c.MarkedSafe++
		case "trust_sender":
			c.TrustedSender++
		}
	}
	return c, nil
}

func (m *memoryFeedbackEvents) ListSince(_ context.Context, tenantID string, since time.Time) ([]FeedbackEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	const limit = 10000
	var out []FeedbackEvent
	for _, r := range m.rows {
		if r.TenantID != tenantID {
			continue
		}
		if !since.IsZero() && r.OccurredAt.Before(since) {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// --- group memberships ---------------------------------------------------

type memoryGroupMemberships struct {
	mu   sync.RWMutex
	rows []GroupMembership
}

func newMemoryGroupMemberships() *memoryGroupMemberships {
	return &memoryGroupMemberships{}
}

func (m *memoryGroupMemberships) Upsert(_ context.Context, gm *GroupMembership) error {
	if gm.CreatedAt.IsZero() {
		gm.CreatedAt = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.GroupID == gm.GroupID && r.UserID == gm.UserID {
			return nil // already exists
		}
	}
	m.rows = append(m.rows, *gm)
	return nil
}

func (m *memoryGroupMemberships) ListByGroup(_ context.Context, groupID string) ([]GroupMembership, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []GroupMembership
	for _, r := range m.rows {
		if r.GroupID == groupID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memoryGroupMemberships) ListByUser(_ context.Context, userID string) ([]GroupMembership, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []GroupMembership
	for _, r := range m.rows {
		if r.UserID == userID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memoryGroupMemberships) DeleteByGroup(_ context.Context, groupID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	filtered := m.rows[:0]
	for _, r := range m.rows {
		if r.GroupID != groupID {
			filtered = append(filtered, r)
		}
	}
	m.rows = filtered
	return nil
}

func (m *memoryGroupMemberships) ReplaceForGroup(_ context.Context, groupID string, userIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	filtered := m.rows[:0]
	for _, r := range m.rows {
		if r.GroupID != groupID {
			filtered = append(filtered, r)
		}
	}
	now := time.Now().UTC()
	for _, uid := range userIDs {
		filtered = append(filtered, GroupMembership{
			GroupID:   groupID,
			UserID:    uid,
			CreatedAt: now,
		})
	}
	m.rows = filtered
	return nil
}

// --- sync checkpoints ---------------------------------------------------

type memorySyncCheckpoints struct {
	mu   sync.RWMutex
	rows map[string]SyncCheckpoint // key: tenantID+":"+provider
}

func newMemorySyncCheckpoints() *memorySyncCheckpoints {
	return &memorySyncCheckpoints{rows: map[string]SyncCheckpoint{}}
}

func (m *memorySyncCheckpoints) Get(_ context.Context, tenantID, provider string) (*SyncCheckpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp, ok := m.rows[tenantID+":"+provider]
	if !ok {
		return nil, ErrNotFound
	}
	return &cp, nil
}

func (m *memorySyncCheckpoints) Upsert(_ context.Context, cp *SyncCheckpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp.UpdatedAt = time.Now().UTC()
	m.rows[cp.TenantID+":"+cp.Provider] = *cp
	return nil
}

// --- user behavioral baselines ------------------------------------------

type memoryBehavioralBaselines struct {
	mu   sync.RWMutex
	rows map[string]UserBehavioralBaseline // key: tenantID+":"+hex(userHash)+":"+hex(senderHash)
}

func newMemoryBehavioralBaselines() *memoryBehavioralBaselines {
	return &memoryBehavioralBaselines{rows: map[string]UserBehavioralBaseline{}}
}

func baselineKey(tenantID string, userHash, senderHash []byte) string {
	return tenantID + ":" + hex.EncodeToString(userHash) + ":" + hex.EncodeToString(senderHash)
}

func (m *memoryBehavioralBaselines) Upsert(_ context.Context, b *UserBehavioralBaseline) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b.ID == "" {
		h := hex.EncodeToString(b.UserEmailHash)
		if len(h) > 8 {
			h = h[:8]
		}
		b.ID = "mem-" + h
	}
	now := time.Now().UTC()
	b.UpdatedAt = now
	if b.CreatedAt.IsZero() {
		b.CreatedAt = now
	}
	key := baselineKey(b.TenantID, b.UserEmailHash, b.SenderDomainHash)
	m.rows[key] = *b
	return nil
}

func (m *memoryBehavioralBaselines) Get(_ context.Context, tenantID string, userHash, senderDomainHash []byte) (*UserBehavioralBaseline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := baselineKey(tenantID, userHash, senderDomainHash)
	b, ok := m.rows[key]
	if !ok {
		return nil, ErrNotFound
	}
	return &b, nil
}

// --- org graphs -------------------------------------------------------------

type memoryOrgGraphs struct {
	mu   sync.RWMutex
	rows map[string]OrgGraphSnapshot // keyed by tenant_id
}

func newMemoryOrgGraphs() *memoryOrgGraphs {
	return &memoryOrgGraphs{rows: map[string]OrgGraphSnapshot{}}
}

func (m *memoryOrgGraphs) Upsert(_ context.Context, s *OrgGraphSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == "" {
		id := s.TenantID
		if len(id) > 8 {
			id = id[:8]
		}
		s.ID = "mem-og-" + id
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	m.rows[s.TenantID] = *s
	return nil
}

func (m *memoryOrgGraphs) GetByTenant(_ context.Context, tenantID string) (*OrgGraphSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.rows[tenantID]
	if !ok {
		return nil, ErrNotFound
	}
	return &s, nil
}

// --- email verdict audits + banner state (WS-5A.6) ---------------------

type memoryEmailVerdictAudits struct {
	mu   sync.RWMutex
	rows map[string]EmailVerdictAudit // keyed by tenantID + "\x00" + dedupID
}

func newMemoryEmailVerdictAudits() *memoryEmailVerdictAudits {
	return &memoryEmailVerdictAudits{rows: map[string]EmailVerdictAudit{}}
}

func emailAuditKey(tenantID, dedupID string) string {
	return tenantID + "\x00" + dedupID
}

func (m *memoryEmailVerdictAudits) Insert(_ context.Context, row *EmailVerdictAudit) (bool, error) {
	if row == nil {
		return false, errors.New("repository: EmailVerdictAudits.Insert: row is nil")
	}
	if row.TenantID == "" {
		return false, errors.New("repository: EmailVerdictAudits.Insert: tenant_id required")
	}
	if row.DedupID == "" {
		return false, errors.New("repository: EmailVerdictAudits.Insert: dedup_id required")
	}
	if row.Resolution == "" {
		return false, errors.New("repository: EmailVerdictAudits.Insert: resolution required")
	}
	if row.ResolvedBy == "" {
		return false, errors.New("repository: EmailVerdictAudits.Insert: resolved_by required")
	}
	if row.SourceIncidentID == "" {
		return false, errors.New("repository: EmailVerdictAudits.Insert: source_incident_id required")
	}
	if row.ResolvedAt.IsZero() {
		return false, errors.New("repository: EmailVerdictAudits.Insert: resolved_at required")
	}
	if row.ID == "" {
		row.ID = uuid.NewString()
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	row.ResolvedAt = row.ResolvedAt.UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	key := emailAuditKey(row.TenantID, row.DedupID)
	if existing, exists := m.rows[key]; exists {
		// Surface the existing row's identity back to the
		// caller so the resolver can report the
		// duplicate's AuditID in its Outcome — matches the
		// Postgres backend's RETURNING-id-on-conflict
		// contract.
		row.ID = existing.ID
		row.CreatedAt = existing.CreatedAt
		return false, nil
	}
	m.rows[key] = *row
	return true, nil
}

func (m *memoryEmailVerdictAudits) GetByDedupID(_ context.Context, tenantID, dedupID string) (*EmailVerdictAudit, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rows[emailAuditKey(tenantID, dedupID)]
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}

type memoryBannerStates struct {
	mu   sync.RWMutex
	rows map[string]BannerState // keyed by tenantID + "\x00" + hex(messageIDHash)
}

func newMemoryBannerStates() *memoryBannerStates {
	return &memoryBannerStates{rows: map[string]BannerState{}}
}

func bannerKey(tenantID string, messageIDHash []byte) string {
	return tenantID + "\x00" + hex.EncodeToString(messageIDHash)
}

func (m *memoryBannerStates) Get(_ context.Context, tenantID string, messageIDHash []byte) (*BannerState, error) {
	if tenantID == "" {
		return nil, errors.New("repository: BannerStates.Get: tenant_id required")
	}
	if len(messageIDHash) == 0 {
		return nil, errors.New("repository: BannerStates.Get: message_id_hash required")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rows[bannerKey(tenantID, messageIDHash)]
	if !ok {
		return nil, ErrNotFound
	}
	// Defensive copy of the time pointers so callers can't
	// mutate the in-memory row through the returned aliases.
	out := r
	if r.DeliveredAt != nil {
		t := *r.DeliveredAt
		out.DeliveredAt = &t
	}
	if r.ReopenedAt != nil {
		t := *r.ReopenedAt
		out.ReopenedAt = &t
	}
	return &out, nil
}

func (m *memoryBannerStates) MarkDelivered(_ context.Context, in MarkDeliveredInput) error {
	if in.TenantID == "" {
		return errors.New("repository: BannerStates.MarkDelivered: tenant_id required")
	}
	if len(in.MessageIDHash) == 0 {
		return errors.New("repository: BannerStates.MarkDelivered: message_id_hash required")
	}
	at := in.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := bannerKey(in.TenantID, in.MessageIDHash)
	row, ok := m.rows[key]
	if !ok {
		row = BannerState{
			ID:            uuid.NewString(),
			TenantID:      in.TenantID,
			MessageIDHash: append([]byte(nil), in.MessageIDHash...),
			CreatedAt:     time.Now().UTC(),
		}
	}
	if row.DeliveredAt == nil {
		t := at.UTC()
		row.DeliveredAt = &t
	}
	if in.Reason != "" {
		row.LastReason = in.Reason
	}
	if in.Provider != "" {
		row.Provider = in.Provider
	}
	if in.DeliveredMessageID != "" {
		row.DeliveredMessageID = in.DeliveredMessageID
	}
	if in.DeliveredEmail != "" {
		row.DeliveredEmail = in.DeliveredEmail
	}
	row.UpdatedAt = time.Now().UTC()
	m.rows[key] = row
	return nil
}

func (m *memoryBannerStates) MarkReopened(_ context.Context, tenantID string, messageIDHash []byte, at time.Time, reason string) error {
	if tenantID == "" {
		return errors.New("repository: BannerStates.MarkReopened: tenant_id required")
	}
	if len(messageIDHash) == 0 {
		return errors.New("repository: BannerStates.MarkReopened: message_id_hash required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := bannerKey(tenantID, messageIDHash)
	row, ok := m.rows[key]
	if !ok {
		row = BannerState{
			ID:            uuid.NewString(),
			TenantID:      tenantID,
			MessageIDHash: append([]byte(nil), messageIDHash...),
			CreatedAt:     time.Now().UTC(),
		}
	}
	t := at.UTC()
	row.ReopenedAt = &t
	if reason != "" {
		row.LastReason = reason
	}
	row.UpdatedAt = time.Now().UTC()
	m.rows[key] = row
	return nil
}
