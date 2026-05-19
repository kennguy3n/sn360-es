package repository

import (
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

func (m *memoryCommHistory) Upsert(_ context.Context, h *CommunicationHistory) error {
	if h.ID == "" {
		h.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if h.FirstSeenAt.IsZero() {
		h.FirstSeenAt = now
	}
	h.UpdatedAt = now
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[commKey(h.TenantID, h.SenderHash, h.RecipientHash)] = *h
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
// after `since`, sorted by LastSeenAt descending. A non-positive
// limit disables the cap. Mirrors the Postgres implementation so
// tests using the in-memory registry behave identically to
// production.
func (m *memoryCommHistory) ListByTenant(_ context.Context, tenantID string, since time.Time, limit int) ([]CommunicationHistory, error) {
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
	if limit > 0 && len(rows) > limit {
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
	if !cur.UpdatedAt.Equal(readAt) {
		return false, nil
	}
	cur.Count7d = h.Count7d
	cur.Relationship = h.Relationship
	cur.UpdatedAt = time.Now().UTC()
	m.rows[key] = cur
	// Reflect the write back to the caller so callers that inspect
	// `h.UpdatedAt` after the CAS see the fresh stamp.
	h.UpdatedAt = cur.UpdatedAt
	return true, nil
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
