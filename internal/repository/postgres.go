package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// NewPostgresRegistry constructs a Registry backed by the SN360-ES
// Postgres schema defined under `migrations/`.
func NewPostgresRegistry(db *postgres.DB) *Registry {
	if db == nil {
		panic("repository: db is required")
	}
	return &Registry{
		Tenants:                &pgTenants{db: db},
		Users:                  &pgUsers{db: db},
		Groups:                 &pgGroups{db: db},
		Labels:                 &pgLabels{db: db},
		ScoreEngines:           &pgScoreEngines{db: db},
		EmailClassifications:   &pgClassifications{db: db},
		Vendors:                &pgVendors{db: db},
		EvaluationResults:      &pgEvalResults{db: db},
		CommunicationHistories: &pgCommHistory{db: db},
		FeedbackEvents:         &pgFeedbackEvents{db: db},
	}
}

// --- tenants ------------------------------------------------------------

type pgTenants struct{ db *postgres.DB }

func (p *pgTenants) Create(ctx context.Context, t *Tenant) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	meta, _ := json.Marshal(t.Metadata)
	_, err := p.db.ExecContext(ctx, `
INSERT INTO tenants (id, name, display_name, provider, primary_domain, region, kms_key_arn,
                     score_base, retention_days, locale, status, metadata)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
`,
		t.ID, t.Name, t.DisplayName, t.Provider, t.PrimaryDomain, t.Region, t.KMSKeyARN,
		t.ScoreBase, t.RetentionDays, t.Locale, t.Status, meta,
	)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (p *pgTenants) GetByID(ctx context.Context, id string) (*Tenant, error) {
	return p.scanOne(ctx, "WHERE id=$1 AND deleted_at IS NULL", id)
}

func (p *pgTenants) GetByName(ctx context.Context, name string) (*Tenant, error) {
	return p.scanOne(ctx, "WHERE name=$1 AND deleted_at IS NULL", name)
}

func (p *pgTenants) UpdateStatus(ctx context.Context, id, status string) error {
	res, err := p.db.ExecContext(ctx, `UPDATE tenants SET status=$1, updated_at=NOW() WHERE id=$2`, status, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *pgTenants) List(ctx context.Context, limit int) ([]Tenant, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT id,name,display_name,provider,primary_domain,region,kms_key_arn,score_base,retention_days,
       locale,status,metadata,created_at,updated_at
  FROM tenants
 WHERE deleted_at IS NULL
 ORDER BY name
 LIMIT NULLIF($1,0)
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Tenant, 0)
	for rows.Next() {
		var t Tenant
		var meta []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.DisplayName, &t.Provider, &t.PrimaryDomain, &t.Region,
			&t.KMSKeyARN, &t.ScoreBase, &t.RetentionDays, &t.Locale, &t.Status, &meta,
			&t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(meta, &t.Metadata)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *pgTenants) scanOne(ctx context.Context, where string, args ...any) (*Tenant, error) {
	q := `
SELECT id,name,display_name,provider,primary_domain,region,kms_key_arn,score_base,retention_days,
       locale,status,metadata,created_at,updated_at
  FROM tenants ` + where + ` LIMIT 1`
	row := p.db.QueryRowContext(ctx, q, args...)
	var t Tenant
	var meta []byte
	err := row.Scan(&t.ID, &t.Name, &t.DisplayName, &t.Provider, &t.PrimaryDomain, &t.Region,
		&t.KMSKeyARN, &t.ScoreBase, &t.RetentionDays, &t.Locale, &t.Status, &meta,
		&t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(meta, &t.Metadata)
	return &t, nil
}

// --- users --------------------------------------------------------------

type pgUsers struct{ db *postgres.DB }

func (p *pgUsers) Upsert(ctx context.Context, u *User) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO users (id, tenant_id, email_hash, role, department, sensitivity_tier, resilience_score, vulnerability, locale)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (tenant_id, email_hash) DO UPDATE SET
    role=EXCLUDED.role,
    department=EXCLUDED.department,
    sensitivity_tier=EXCLUDED.sensitivity_tier,
    resilience_score=EXCLUDED.resilience_score,
    vulnerability=EXCLUDED.vulnerability,
    locale=EXCLUDED.locale,
    updated_at=NOW()
`,
		u.ID, u.TenantID, u.EmailHash, u.Role, u.Department, u.SensitivityTier, u.ResilienceScore, u.Vulnerability, u.Locale,
	)
	return err
}

func (p *pgUsers) GetByHash(ctx context.Context, tenantID string, emailHash []byte) (*User, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT id,tenant_id,email_hash,role,department,sensitivity_tier,resilience_score,vulnerability,locale,created_at,updated_at
  FROM users WHERE tenant_id=$1 AND email_hash=$2 LIMIT 1`, tenantID, emailHash)
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.EmailHash, &u.Role, &u.Department, &u.SensitivityTier,
		&u.ResilienceScore, &u.Vulnerability, &u.Locale, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (p *pgUsers) List(ctx context.Context, tenantID string, limit int) ([]User, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT id,tenant_id,email_hash,role,department,sensitivity_tier,resilience_score,vulnerability,locale,created_at,updated_at
  FROM users WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT NULLIF($2,0)`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.EmailHash, &u.Role, &u.Department, &u.SensitivityTier,
			&u.ResilienceScore, &u.Vulnerability, &u.Locale, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// --- groups -------------------------------------------------------------

type pgGroups struct{ db *postgres.DB }

func (p *pgGroups) Create(ctx context.Context, g *Group) error {
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO groups (id, tenant_id, name, description, risk_class)
VALUES ($1,$2,$3,$4,$5)`,
		g.ID, g.TenantID, g.Name, g.Description, g.RiskClass)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (p *pgGroups) GetByName(ctx context.Context, tenantID, name string) (*Group, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT id,tenant_id,name,COALESCE(description,''),risk_class,created_at,updated_at
  FROM groups WHERE tenant_id=$1 AND name=$2 LIMIT 1`, tenantID, name)
	var g Group
	err := row.Scan(&g.ID, &g.TenantID, &g.Name, &g.Description, &g.RiskClass, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &g, err
}

func (p *pgGroups) List(ctx context.Context, tenantID string) ([]Group, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT id,tenant_id,name,COALESCE(description,''),risk_class,created_at,updated_at
  FROM groups WHERE tenant_id=$1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.TenantID, &g.Name, &g.Description, &g.RiskClass, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// --- labels -------------------------------------------------------------

type pgLabels struct{ db *postgres.DB }

func (p *pgLabels) Upsert(ctx context.Context, l *Label) error {
	if l.ID == "" {
		l.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO labels (id, tenant_id, provider, tier, category, name, color_bg, color_fg, preset, visible)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (tenant_id, provider, tier, category) DO UPDATE SET
    name=EXCLUDED.name,
    color_bg=EXCLUDED.color_bg,
    color_fg=EXCLUDED.color_fg,
    preset=EXCLUDED.preset,
    visible=EXCLUDED.visible,
    updated_at=NOW()
`,
		l.ID, l.TenantID, l.Provider, l.Tier, l.Category, l.Name, l.ColorBG, l.ColorFG, l.Preset, l.Visible)
	return err
}

func (p *pgLabels) ListByTenant(ctx context.Context, tenantID, provider string) ([]Label, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT id,tenant_id,provider,tier,COALESCE(category,''),name,COALESCE(color_bg,''),COALESCE(color_fg,''),
       COALESCE(preset,0),visible,created_at,updated_at
  FROM labels WHERE tenant_id=$1 AND provider=$2 ORDER BY tier`, tenantID, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Label
	for rows.Next() {
		var l Label
		if err := rows.Scan(&l.ID, &l.TenantID, &l.Provider, &l.Tier, &l.Category, &l.Name,
			&l.ColorBG, &l.ColorFG, &l.Preset, &l.Visible, &l.CreatedAt, &l.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// --- score engines ------------------------------------------------------

type pgScoreEngines struct{ db *postgres.DB }

func (p *pgScoreEngines) Get(ctx context.Context, tenantID string) (*ScoreEngine, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT tenant_id, score_base, weight_ai, weight_rspamd, weight_attachments, weight_links,
       threshold_blocked, threshold_high, threshold_warning, threshold_caution, threshold_info,
       subject_tag_enabled, subject_tag_prefix, updated_at
  FROM score_engine WHERE tenant_id=$1`, tenantID)
	var s ScoreEngine
	err := row.Scan(&s.TenantID, &s.ScoreBase, &s.WeightAI, &s.WeightRspamd, &s.WeightAttachments, &s.WeightLinks,
		&s.ThresholdBlocked, &s.ThresholdHigh, &s.ThresholdWarning, &s.ThresholdCaution, &s.ThresholdInfo,
		&s.SubjectTagEnabled, &s.SubjectTagPrefix, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &s, err
}

func (p *pgScoreEngines) Upsert(ctx context.Context, s *ScoreEngine) error {
	_, err := p.db.ExecContext(ctx, `
INSERT INTO score_engine (tenant_id, score_base, weight_ai, weight_rspamd, weight_attachments, weight_links,
                          threshold_blocked, threshold_high, threshold_warning, threshold_caution, threshold_info,
                          subject_tag_enabled, subject_tag_prefix)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (tenant_id) DO UPDATE SET
    score_base=EXCLUDED.score_base,
    weight_ai=EXCLUDED.weight_ai,
    weight_rspamd=EXCLUDED.weight_rspamd,
    weight_attachments=EXCLUDED.weight_attachments,
    weight_links=EXCLUDED.weight_links,
    threshold_blocked=EXCLUDED.threshold_blocked,
    threshold_high=EXCLUDED.threshold_high,
    threshold_warning=EXCLUDED.threshold_warning,
    threshold_caution=EXCLUDED.threshold_caution,
    threshold_info=EXCLUDED.threshold_info,
    subject_tag_enabled=EXCLUDED.subject_tag_enabled,
    subject_tag_prefix=EXCLUDED.subject_tag_prefix,
    updated_at=NOW()
`,
		s.TenantID, s.ScoreBase, s.WeightAI, s.WeightRspamd, s.WeightAttachments, s.WeightLinks,
		s.ThresholdBlocked, s.ThresholdHigh, s.ThresholdWarning, s.ThresholdCaution, s.ThresholdInfo,
		s.SubjectTagEnabled, s.SubjectTagPrefix,
	)
	return err
}

// --- email classifications ----------------------------------------------

type pgClassifications struct{ db *postgres.DB }

func (p *pgClassifications) Upsert(ctx context.Context, e *EmailClassification) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO email_classifications (id, domain, classification, source)
VALUES ($1,$2,$3,$4)
ON CONFLICT (domain, classification) DO UPDATE SET
    source=EXCLUDED.source,
    updated_at=NOW()
`,
		e.ID, e.Domain, e.Classification, e.Source)
	return err
}

func (p *pgClassifications) GetByDomain(ctx context.Context, domain string) ([]EmailClassification, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT id, domain, classification, source, updated_at
  FROM email_classifications WHERE domain=$1`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EmailClassification
	for rows.Next() {
		var e EmailClassification
		if err := rows.Scan(&e.ID, &e.Domain, &e.Classification, &e.Source, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- vendors ------------------------------------------------------------

type pgVendors struct{ db *postgres.DB }

func (p *pgVendors) Upsert(ctx context.Context, v *Vendor) error {
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO vendors (id, tenant_id, domain, display_name, approved, auto_discovered, confidence, last_seen_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (tenant_id, domain) DO UPDATE SET
    display_name=EXCLUDED.display_name,
    approved=EXCLUDED.approved,
    auto_discovered=EXCLUDED.auto_discovered,
    confidence=EXCLUDED.confidence,
    last_seen_at=EXCLUDED.last_seen_at,
    updated_at=NOW()
`,
		v.ID, v.TenantID, v.Domain, v.DisplayName, v.Approved, v.AutoDiscovered, v.Confidence, nullableTime(v.LastSeenAt))
	return err
}

func (p *pgVendors) GetByDomain(ctx context.Context, tenantID, domain string) (*Vendor, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT id,tenant_id,domain,COALESCE(display_name,''),approved,auto_discovered,confidence,
       COALESCE(last_seen_at,'epoch'::timestamptz),created_at,updated_at
  FROM vendors WHERE tenant_id=$1 AND domain=$2`, tenantID, domain)
	var v Vendor
	err := row.Scan(&v.ID, &v.TenantID, &v.Domain, &v.DisplayName, &v.Approved, &v.AutoDiscovered,
		&v.Confidence, &v.LastSeenAt, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &v, err
}

func (p *pgVendors) ListApproved(ctx context.Context, tenantID string) ([]Vendor, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT id,tenant_id,domain,COALESCE(display_name,''),approved,auto_discovered,confidence,
       COALESCE(last_seen_at,'epoch'::timestamptz),created_at,updated_at
  FROM vendors WHERE tenant_id=$1 AND approved=TRUE ORDER BY domain`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vendor
	for rows.Next() {
		var v Vendor
		if err := rows.Scan(&v.ID, &v.TenantID, &v.Domain, &v.DisplayName, &v.Approved, &v.AutoDiscovered,
			&v.Confidence, &v.LastSeenAt, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// --- evaluation results -------------------------------------------------

type pgEvalResults struct{ db *postgres.DB }

func (p *pgEvalResults) Create(ctx context.Context, r *EvaluationResult) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO evaluation_results (id, tenant_id, message_id_hash, correlation_id, score, tier,
                                primary_category, secondary_categories, reason_codes,
                                degraded, degraded_services,
                                tier0_outcome, tier1_outcome, tier2_outcome, rspamd_outcome,
                                evaluated_at)
VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,NULLIF($7,''),$8,$9,$10,$11,
        NULLIF($12,'')::JSONB, NULLIF($13,'')::JSONB, NULLIF($14,'')::JSONB, NULLIF($15,'')::JSONB,
        COALESCE($16, NOW()))
`,
		r.ID, r.TenantID, r.MessageIDHash, r.CorrelationID, r.Score, r.Tier,
		r.Primary, pq.Array(r.Secondary), pq.Array(r.ReasonCodes),
		r.Degraded, pq.Array(r.DegradedServices),
		stringOrEmpty(r.Tier0OutcomeJSON), stringOrEmpty(r.Tier1OutcomeJSON),
		stringOrEmpty(r.Tier2OutcomeJSON), stringOrEmpty(r.RspamdOutcomeJSON),
		nullableTime(r.EvaluatedAt),
	)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (p *pgEvalResults) GetByMessageHash(ctx context.Context, tenantID string, messageIDHash []byte) (*EvaluationResult, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT id, tenant_id, message_id_hash, COALESCE(correlation_id,''), score, tier,
       COALESCE(primary_category,''), secondary_categories, reason_codes, degraded, degraded_services,
       COALESCE(tier0_outcome::text,''), COALESCE(tier1_outcome::text,''),
       COALESCE(tier2_outcome::text,''), COALESCE(rspamd_outcome::text,''),
       evaluated_at, created_at
  FROM evaluation_results WHERE tenant_id=$1 AND message_id_hash=$2`, tenantID, messageIDHash)
	return scanEval(row)
}

func (p *pgEvalResults) ListRecent(ctx context.Context, tenantID string, limit int) ([]EvaluationResult, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT id, tenant_id, message_id_hash, COALESCE(correlation_id,''), score, tier,
       COALESCE(primary_category,''), secondary_categories, reason_codes, degraded, degraded_services,
       COALESCE(tier0_outcome::text,''), COALESCE(tier1_outcome::text,''),
       COALESCE(tier2_outcome::text,''), COALESCE(rspamd_outcome::text,''),
       evaluated_at, created_at
  FROM evaluation_results WHERE tenant_id=$1 ORDER BY evaluated_at DESC LIMIT NULLIF($2,0)`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvaluationResult
	for rows.Next() {
		r, err := scanEvalRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func scanEval(row *sql.Row) (*EvaluationResult, error) {
	var (
		r                           EvaluationResult
		secondary, reasons, degSvcs pq.StringArray
		t0, t1, t2, rsp             string
	)
	err := row.Scan(&r.ID, &r.TenantID, &r.MessageIDHash, &r.CorrelationID, &r.Score, &r.Tier,
		&r.Primary, &secondary, &reasons, &r.Degraded, &degSvcs, &t0, &t1, &t2, &rsp,
		&r.EvaluatedAt, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Secondary, r.ReasonCodes, r.DegradedServices = []string(secondary), []string(reasons), []string(degSvcs)
	if t0 != "" {
		r.Tier0OutcomeJSON = []byte(t0)
	}
	if t1 != "" {
		r.Tier1OutcomeJSON = []byte(t1)
	}
	if t2 != "" {
		r.Tier2OutcomeJSON = []byte(t2)
	}
	if rsp != "" {
		r.RspamdOutcomeJSON = []byte(rsp)
	}
	return &r, nil
}

func scanEvalRows(rows *sql.Rows) (*EvaluationResult, error) {
	var (
		r                           EvaluationResult
		secondary, reasons, degSvcs pq.StringArray
		t0, t1, t2, rsp             string
	)
	if err := rows.Scan(&r.ID, &r.TenantID, &r.MessageIDHash, &r.CorrelationID, &r.Score, &r.Tier,
		&r.Primary, &secondary, &reasons, &r.Degraded, &degSvcs, &t0, &t1, &t2, &rsp,
		&r.EvaluatedAt, &r.CreatedAt); err != nil {
		return nil, err
	}
	r.Secondary, r.ReasonCodes, r.DegradedServices = []string(secondary), []string(reasons), []string(degSvcs)
	if t0 != "" {
		r.Tier0OutcomeJSON = []byte(t0)
	}
	if t1 != "" {
		r.Tier1OutcomeJSON = []byte(t1)
	}
	if t2 != "" {
		r.Tier2OutcomeJSON = []byte(t2)
	}
	if rsp != "" {
		r.RspamdOutcomeJSON = []byte(rsp)
	}
	return &r, nil
}

// --- communication histories --------------------------------------------

type pgCommHistory struct{ db *postgres.DB }

func (p *pgCommHistory) Upsert(ctx context.Context, h *CommunicationHistory) error {
	if h.ID == "" {
		h.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO communication_histories (id, tenant_id, sender_hash, recipient_hash, sender_domain_hash,
                                     sender_domain, count_7d, count_30d, first_seen_at, last_seen_at, relationship)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9,NOW()),COALESCE($10,NOW()),$11)
ON CONFLICT (tenant_id, sender_hash, recipient_hash) DO UPDATE SET
    sender_domain_hash=EXCLUDED.sender_domain_hash,
    sender_domain=EXCLUDED.sender_domain,
    count_7d=EXCLUDED.count_7d,
    count_30d=EXCLUDED.count_30d,
    last_seen_at=EXCLUDED.last_seen_at,
    relationship=EXCLUDED.relationship,
    updated_at=NOW()
`,
		h.ID, h.TenantID, h.SenderHash, h.RecipientHash, h.SenderDomainHash,
		h.SenderDomain, h.Count7d, h.Count30d, nullableTime(h.FirstSeenAt), nullableTime(h.LastSeenAt), h.Relationship,
	)
	return err
}

// ListByTenant returns every CommunicationHistory row for `tenantID`
// whose last_seen_at is at or after `since`, ordered by last_seen_at
// descending so the relationship worker re-processes the freshest
// rows first. A non-positive `limit` is treated as "no cap"; in that
// case we pass NULL to the SQL LIMIT placeholder which Postgres
// interprets as unlimited.
func (p *pgCommHistory) ListByTenant(ctx context.Context, tenantID string, since time.Time, limit int) ([]CommunicationHistory, error) {
	var limitArg interface{}
	if limit > 0 {
		limitArg = limit
	}
	rows, err := p.db.QueryContext(ctx, `
SELECT id, tenant_id, sender_hash, recipient_hash, sender_domain_hash, COALESCE(sender_domain, ''),
       count_7d, count_30d, first_seen_at, last_seen_at, relationship, updated_at
  FROM communication_histories
 WHERE tenant_id=$1 AND last_seen_at >= $2
 ORDER BY last_seen_at DESC
 LIMIT $3`,
		tenantID, since, limitArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]CommunicationHistory, 0)
	for rows.Next() {
		var h CommunicationHistory
		if err := rows.Scan(&h.ID, &h.TenantID, &h.SenderHash, &h.RecipientHash, &h.SenderDomainHash, &h.SenderDomain,
			&h.Count7d, &h.Count30d, &h.FirstSeenAt, &h.LastSeenAt, &h.Relationship, &h.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *pgCommHistory) Get(ctx context.Context, tenantID string, senderHash, recipientHash []byte) (*CommunicationHistory, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT id, tenant_id, sender_hash, recipient_hash, sender_domain_hash, COALESCE(sender_domain, ''),
       count_7d, count_30d, first_seen_at, last_seen_at, relationship, updated_at
  FROM communication_histories WHERE tenant_id=$1 AND sender_hash=$2 AND recipient_hash=$3`,
		tenantID, senderHash, recipientHash)
	var h CommunicationHistory
	err := row.Scan(&h.ID, &h.TenantID, &h.SenderHash, &h.RecipientHash, &h.SenderDomainHash, &h.SenderDomain,
		&h.Count7d, &h.Count30d, &h.FirstSeenAt, &h.LastSeenAt, &h.Relationship, &h.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &h, err
}

// --- feedback events ----------------------------------------------------

type pgFeedbackEvents struct{ db *postgres.DB }

func (p *pgFeedbackEvents) Create(ctx context.Context, e *FeedbackEvent) error {
	if e == nil {
		return errors.New("repository: feedback event is required")
	}
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO feedback_events (id, tenant_id, pseudo_message_id, action, tier, correlation_id, occurred_at)
VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),COALESCE($7,NOW()))
`,
		e.ID, e.TenantID, e.PseudoMessageID, e.Action, e.Tier,
		e.CorrelationID, nullableTime(e.OccurredAt),
	)
	return err
}

func (p *pgFeedbackEvents) Counts(ctx context.Context, tenantID string, start, end time.Time) (FeedbackCounts, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT
    COUNT(*) FILTER (WHERE action = 'report_phishing') AS reported,
    COUNT(*) FILTER (WHERE action = 'mark_safe')       AS marked,
    COUNT(*) FILTER (WHERE action = 'trust_sender')    AS trusted
  FROM feedback_events
 WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3`,
		tenantID, start, end)
	var c FeedbackCounts
	if err := row.Scan(&c.ReportedPhishing, &c.MarkedSafe, &c.TrustedSender); err != nil {
		return FeedbackCounts{}, err
	}
	return c, nil
}

// --- helpers ------------------------------------------------------------

// pgUniqueViolationCode is the SQLSTATE for unique_violation.
// https://www.postgresql.org/docs/current/errcodes-appendix.html
const pgUniqueViolationCode = "23505"

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation. It supports both pgx/v5 (the default driver in this repo —
// `*pgconn.PgError`) and lib/pq (legacy callers — `*pq.Error`) by
// inspecting the typed SQLSTATE rather than message text, which is
// locale-dependent and brittle across driver upgrades.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgxErr *pgconn.PgError
	if errors.As(err, &pgxErr) {
		return pgxErr.Code == pgUniqueViolationCode
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return string(pqErr.Code) == pgUniqueViolationCode
	}
	return false
}

func nullableTime(t interface{}) interface{} {
	type zeroable interface {
		IsZero() bool
	}
	if z, ok := t.(zeroable); ok && z.IsZero() {
		return nil
	}
	return t
}

func stringOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return string(b)
}
