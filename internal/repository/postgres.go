package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
		GroupMemberships:       &pgGroupMemberships{db: db},
		Labels:                 &pgLabels{db: db},
		ScoreEngines:           &pgScoreEngines{db: db},
		EmailClassifications:   &pgClassifications{db: db},
		Vendors:                &pgVendors{db: db},
		EvaluationResults:      &pgEvalResults{db: db},
		CommunicationHistories: &pgCommHistory{db: db},
		FeedbackEvents:         &pgFeedbackEvents{db: db},
		AuditLogs:              NewPgAuditLogs(db),
		SyncCheckpoints:        &pgSyncCheckpoints{db: db},
		BehavioralBaselines:    &pgBehavioralBaselines{db: db},
		OrgGraphs:              &pgOrgGraphs{db: db},
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

func (p *pgUsers) Count(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE tenant_id=$1`, tenantID).Scan(&n)
	return n, err
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

func (p *pgGroups) Upsert(ctx context.Context, g *Group) error {
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO groups (id, tenant_id, name, description, risk_class)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (tenant_id, name) DO UPDATE SET
    description=EXCLUDED.description, risk_class=EXCLUDED.risk_class, updated_at=NOW()`,
		g.ID, g.TenantID, g.Name, g.Description, g.RiskClass)
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

func (p *pgGroups) Count(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups WHERE tenant_id=$1`, tenantID).Scan(&n)
	return n, err
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
       threshold_tier1_pass_below, threshold_tier1_flag_above,
       subject_tag_enabled, subject_tag_prefix, updated_at
  FROM score_engine WHERE tenant_id=$1`, tenantID)
	var s ScoreEngine
	err := row.Scan(&s.TenantID, &s.ScoreBase, &s.WeightAI, &s.WeightRspamd, &s.WeightAttachments, &s.WeightLinks,
		&s.ThresholdBlocked, &s.ThresholdHigh, &s.ThresholdWarning, &s.ThresholdCaution, &s.ThresholdInfo,
		&s.ThresholdTier1PassBelow, &s.ThresholdTier1FlagAbove,
		&s.SubjectTagEnabled, &s.SubjectTagPrefix, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &s, err
}

// UpdateWeights writes exactly the four weight columns + updated_at
// for tenantID in a single SQL UPDATE. Returns ErrNotFound when no
// row exists so the caller can fall through to Upsert for first-time
// seeding. This is the column-scoped write that closes the
// read-modify-write race between concurrent weight and threshold
// writers; threshold columns are not in the SET list.
func (p *pgScoreEngines) UpdateWeights(ctx context.Context, tenantID string, w ScoreWeightUpdate) error {
	res, err := p.db.ExecContext(ctx, `
UPDATE score_engine SET
    weight_ai=$2,
    weight_rspamd=$3,
    weight_attachments=$4,
    weight_links=$5,
    updated_at=NOW()
  WHERE tenant_id=$1`,
		tenantID, w.WeightAI, w.WeightRspamd, w.WeightAttachments, w.WeightLinks)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateThresholds writes exactly the banner + Tier 1 threshold
// columns + updated_at for tenantID in a single SQL UPDATE. Returns
// ErrNotFound when no row exists. Weight columns are not in the SET
// list so a concurrent UpdateWeights against the same tenant cannot
// race; the DB CHECK on threshold_tier1_pass_below <
// threshold_tier1_flag_above (migration 0013) also stops a
// misbehaving caller from inserting a logically-inverted row.
func (p *pgScoreEngines) UpdateThresholds(ctx context.Context, tenantID string, t ScoreThresholdUpdate) error {
	res, err := p.db.ExecContext(ctx, `
UPDATE score_engine SET
    threshold_blocked=$2,
    threshold_high=$3,
    threshold_warning=$4,
    threshold_caution=$5,
    threshold_info=$6,
    threshold_tier1_pass_below=$7,
    threshold_tier1_flag_above=$8,
    updated_at=NOW()
  WHERE tenant_id=$1`,
		tenantID, t.Blocked, t.High, t.Warning, t.Caution, t.Info, t.Tier1PassBelow, t.Tier1FlagAbove)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *pgScoreEngines) Upsert(ctx context.Context, s *ScoreEngine) error {
	_, err := p.db.ExecContext(ctx, `
INSERT INTO score_engine (tenant_id, score_base, weight_ai, weight_rspamd, weight_attachments, weight_links,
                          threshold_blocked, threshold_high, threshold_warning, threshold_caution, threshold_info,
                          threshold_tier1_pass_below, threshold_tier1_flag_above,
                          subject_tag_enabled, subject_tag_prefix)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
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
    threshold_tier1_pass_below=EXCLUDED.threshold_tier1_pass_below,
    threshold_tier1_flag_above=EXCLUDED.threshold_tier1_flag_above,
    subject_tag_enabled=EXCLUDED.subject_tag_enabled,
    subject_tag_prefix=EXCLUDED.subject_tag_prefix,
    updated_at=NOW()
`,
		s.TenantID, s.ScoreBase, s.WeightAI, s.WeightRspamd, s.WeightAttachments, s.WeightLinks,
		s.ThresholdBlocked, s.ThresholdHigh, s.ThresholdWarning, s.ThresholdCaution, s.ThresholdInfo,
		s.ThresholdTier1PassBelow, s.ThresholdTier1FlagAbove,
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

func (p *pgVendors) List(ctx context.Context, tenantID string, limit int) ([]Vendor, error) {
	// LIMIT NULLIF($2, 0) treats limit=0 as "no limit" by collapsing
	// the parameter to NULL (which PostgreSQL accepts as unbounded
	// LIMIT). Keeps the query fully parameterized — no fmt.Sprintf'd
	// SQL fragments — so the planner can cache one plan and pgx can
	// type-check the argument.
	const q = `
SELECT id,tenant_id,domain,COALESCE(display_name,''),approved,auto_discovered,confidence,
       COALESCE(last_seen_at,'epoch'::timestamptz),created_at,updated_at
  FROM vendors WHERE tenant_id=$1 ORDER BY domain LIMIT NULLIF($2, 0)`
	rows, err := p.db.QueryContext(ctx, q, tenantID, limit)
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

func (p *pgVendors) Delete(ctx context.Context, tenantID, domain string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM vendors WHERE tenant_id=$1 AND domain=$2`, tenantID, domain)
	return err
}

// --- evaluation results -------------------------------------------------

type pgEvalResults struct{ db *postgres.DB }

func (p *pgEvalResults) Create(ctx context.Context, r *EvaluationResult) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	// secondary_categories / reason_codes / degraded_services are NOT NULL
	// columns with an empty-array default in the schema. pq.Array translates
	// a nil slice to a Postgres NULL, which would violate the NOT NULL
	// constraint, so we normalise to an empty slice here.
	secondary := r.Secondary
	if secondary == nil {
		secondary = []string{}
	}
	reasons := r.ReasonCodes
	if reasons == nil {
		reasons = []string{}
	}
	degradedSvcs := r.DegradedServices
	if degradedSvcs == nil {
		degradedSvcs = []string{}
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
		r.Primary, pq.Array(secondary), pq.Array(reasons),
		r.Degraded, pq.Array(degradedSvcs),
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
	// Upsert is the ingestion-time write path. It does NOT touch
	// the typical_hour column — the only writer of typical_hour is
	// UpdateCountsIfFresh (the relationship-worker CAS path), which
	// has its own CASE guard on the worker's freshly-computed modal
	// hour.
	//
	// Excluding typical_hour from this SQL eliminates a Go zero-value
	// trap: CommunicationHistory.TypicalHour is an int whose zero
	// value (0) happens to be the valid hour "midnight UTC". An
	// ingestion-time caller that constructs a CommunicationHistory
	// struct literal without explicitly setting TypicalHour would
	// otherwise silently overwrite the worker-computed modal hour
	// with 00:00 UTC on every Upsert. Keeping typical_hour out of
	// the column list lets new rows fall back to the migration 0007
	// column default (-1, "no baseline yet") and existing rows keep
	// whatever the worker last wrote.
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
// rows first. A non-positive `limit` is treated as "no cap" by way
// of `LIMIT NULLIF($3,0)` — Postgres interprets `LIMIT NULL` as
// unlimited, which matches the established pattern used by every
// other LIMIT-driven query in this file (e.g. tenants.List at
// `LIMIT NULLIF($1,0)`, users.List at `LIMIT NULLIF($2,0)`,
// evaluation_results.ListRecent at `LIMIT NULLIF($2,0)`).
func (p *pgCommHistory) ListByTenant(ctx context.Context, tenantID string, since time.Time, limit int) ([]CommunicationHistory, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT id, tenant_id, sender_hash, recipient_hash, sender_domain_hash, COALESCE(sender_domain, ''),
       count_7d, count_30d, first_seen_at, last_seen_at, relationship,
       COALESCE(typical_hour, -1), updated_at
  FROM communication_histories
 WHERE tenant_id=$1 AND last_seen_at >= $2
 ORDER BY last_seen_at DESC
 LIMIT NULLIF($3,0)`,
		tenantID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]CommunicationHistory, 0)
	for rows.Next() {
		var h CommunicationHistory
		if err := rows.Scan(&h.ID, &h.TenantID, &h.SenderHash, &h.RecipientHash, &h.SenderDomainHash, &h.SenderDomain,
			&h.Count7d, &h.Count30d, &h.FirstSeenAt, &h.LastSeenAt, &h.Relationship,
			&h.TypicalHour, &h.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateCountsIfFresh applies the relationship-worker's recomputed
// Count7d + Relationship to the row IFF its updated_at still matches
// `readAt`. The WHERE-clause acts as an optimistic-concurrency guard
// against ingestion-time Upsert racing with the worker's stale
// snapshot (loaded by ListByTenant N seconds earlier). Returns
// (true, nil) when one row was updated and (false, nil) when the
// guard rejected the write because ingestion produced a fresher
// snapshot in the meantime — see the interface docstring on
// CommunicationHistoryRepository.UpdateCountsIfFresh for why the
// (false, nil) case is treated as success by the worker.
//
// Only the worker-mutated columns (count_7d, relationship,
// updated_at) are touched. The ingestion-bumped columns (count_30d,
// last_seen_at, sender_domain, sender_domain_hash) stay at whatever
// value the latest writer produced, so a worker that missed a
// concurrent ingestion-time Upsert still does not regress those
// fields. The id column is used as the WHERE key so a row whose
// (sender_hash, recipient_hash) somehow got remapped between the
// list and the update doesn't get cross-updated.
func (p *pgCommHistory) UpdateCountsIfFresh(ctx context.Context, h *CommunicationHistory, readAt time.Time) (bool, error) {
	if h == nil || h.ID == "" {
		return false, errors.New("repository: UpdateCountsIfFresh requires a row id")
	}
	if readAt.IsZero() {
		// A zero readAt would match every row whose updated_at is
		// also zero — a class of bug we'd rather surface than
		// silently overwrite the wrong row.
		return false, errors.New("repository: UpdateCountsIfFresh requires a non-zero readAt")
	}
	// Only overwrite typical_hour when the worker has computed a
	// fresh modal hour in the valid 0..23 range. Passing the
	// snapshot's value back unchanged would re-write the same
	// number every cycle (harmless) but reserving the sentinel -1
	// path lets a future caller explicitly skip the column.
	typicalHour := h.TypicalHour
	res, err := p.db.ExecContext(ctx, `
UPDATE communication_histories
   SET count_7d = $1,
       relationship = $2,
       typical_hour = CASE
           WHEN $5 >= 0 AND $5 < 24 THEN $5
           ELSE communication_histories.typical_hour
       END,
       updated_at = NOW()
 WHERE id = $3 AND updated_at = $4
`, h.Count7d, h.Relationship, h.ID, readAt, typicalHour)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (p *pgCommHistory) Get(ctx context.Context, tenantID string, senderHash, recipientHash []byte) (*CommunicationHistory, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT id, tenant_id, sender_hash, recipient_hash, sender_domain_hash, COALESCE(sender_domain, ''),
       count_7d, count_30d, first_seen_at, last_seen_at, relationship,
       COALESCE(typical_hour, -1), updated_at
  FROM communication_histories WHERE tenant_id=$1 AND sender_hash=$2 AND recipient_hash=$3`,
		tenantID, senderHash, recipientHash)
	var h CommunicationHistory
	err := row.Scan(&h.ID, &h.TenantID, &h.SenderHash, &h.RecipientHash, &h.SenderDomainHash, &h.SenderDomain,
		&h.Count7d, &h.Count30d, &h.FirstSeenAt, &h.LastSeenAt, &h.Relationship, &h.TypicalHour, &h.UpdatedAt)
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

func (p *pgFeedbackEvents) ListSince(ctx context.Context, tenantID string, since time.Time) ([]FeedbackEvent, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT id, tenant_id, pseudo_message_id, action, tier, COALESCE(correlation_id,''), occurred_at, created_at
  FROM feedback_events
 WHERE tenant_id = $1 AND occurred_at >= $2
 ORDER BY occurred_at
 LIMIT 10000`, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedbackEvent
	for rows.Next() {
		var e FeedbackEvent
		if err := rows.Scan(&e.ID, &e.TenantID, &e.PseudoMessageID, &e.Action, &e.Tier, &e.CorrelationID, &e.OccurredAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- group memberships --------------------------------------------------

type pgGroupMemberships struct{ db *postgres.DB }

func (p *pgGroupMemberships) Upsert(ctx context.Context, gm *GroupMembership) error {
	if gm.CreatedAt.IsZero() {
		gm.CreatedAt = time.Now().UTC()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO group_memberships (group_id, user_id, created_at)
VALUES ($1,$2,$3)
ON CONFLICT (group_id, user_id) DO NOTHING`,
		gm.GroupID, gm.UserID, gm.CreatedAt)
	return err
}

func (p *pgGroupMemberships) ListByGroup(ctx context.Context, groupID string) ([]GroupMembership, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT group_id, user_id, created_at FROM group_memberships WHERE group_id=$1`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMembership
	for rows.Next() {
		var gm GroupMembership
		if err := rows.Scan(&gm.GroupID, &gm.UserID, &gm.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, gm)
	}
	return out, rows.Err()
}

func (p *pgGroupMemberships) ListByUser(ctx context.Context, userID string) ([]GroupMembership, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT group_id, user_id, created_at FROM group_memberships WHERE user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMembership
	for rows.Next() {
		var gm GroupMembership
		if err := rows.Scan(&gm.GroupID, &gm.UserID, &gm.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, gm)
	}
	return out, rows.Err()
}

func (p *pgGroupMemberships) DeleteByGroup(ctx context.Context, groupID string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM group_memberships WHERE group_id=$1`, groupID)
	return err
}

func (p *pgGroupMemberships) ReplaceForGroup(ctx context.Context, groupID string, userIDs []string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("replace group memberships: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	_, err = tx.ExecContext(ctx, `DELETE FROM group_memberships WHERE group_id=$1`, groupID)
	if err != nil {
		return err
	}
	if len(userIDs) == 0 {
		return tx.Commit()
	}
	now := time.Now().UTC()
	// Single-round-trip insert: unnest the user_id slice into rows
	// rather than issuing one INSERT per user. The ON CONFLICT clause
	// stays so duplicate user_ids within the same batch — or a stale
	// row left by a crash mid-DELETE — don't fail the whole
	// transaction.
	_, err = tx.ExecContext(ctx, `
INSERT INTO group_memberships (group_id, user_id, created_at)
SELECT $1, uid, $2 FROM unnest($3::text[]) AS uid
ON CONFLICT (group_id, user_id) DO NOTHING`, groupID, now, pq.Array(userIDs))
	if err != nil {
		return err
	}
	return tx.Commit()
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

// --- sync checkpoints ---------------------------------------------------

type pgSyncCheckpoints struct{ db *postgres.DB }

func (p *pgSyncCheckpoints) Get(ctx context.Context, tenantID, provider string) (*SyncCheckpoint, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT tenant_id, provider, delta_token, updated_at
  FROM sync_checkpoints WHERE tenant_id=$1 AND provider=$2`, tenantID, provider)
	var cp SyncCheckpoint
	err := row.Scan(&cp.TenantID, &cp.Provider, &cp.DeltaToken, &cp.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &cp, err
}

func (p *pgSyncCheckpoints) Upsert(ctx context.Context, cp *SyncCheckpoint) error {
	_, err := p.db.ExecContext(ctx, `
INSERT INTO sync_checkpoints (tenant_id, provider, delta_token, updated_at)
VALUES ($1,$2,$3,NOW())
ON CONFLICT (tenant_id, provider) DO UPDATE SET
    delta_token=EXCLUDED.delta_token,
    updated_at=NOW()
`, cp.TenantID, cp.Provider, cp.DeltaToken)
	return err
}

// --- user behavioral baselines ------------------------------------------

type pgBehavioralBaselines struct{ db *postgres.DB }

func (p *pgBehavioralBaselines) Upsert(ctx context.Context, b *UserBehavioralBaseline) error {
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO user_behavioral_baselines
    (id, tenant_id, user_email_hash, sender_domain_hash,
     typical_send_hours, typical_device_types, avg_messages_per_week,
     last_seen_at, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),NOW())
ON CONFLICT (tenant_id, user_email_hash, sender_domain_hash) DO UPDATE SET
    typical_send_hours=EXCLUDED.typical_send_hours,
    typical_device_types=EXCLUDED.typical_device_types,
    avg_messages_per_week=EXCLUDED.avg_messages_per_week,
    last_seen_at=EXCLUDED.last_seen_at,
    updated_at=NOW()
`, b.ID, b.TenantID, b.UserEmailHash, b.SenderDomainHash,
		pq.Array(b.TypicalSendHours), pq.Array(b.TypicalDeviceTypes),
		b.AvgMessagesPerWeek, sql.NullTime{Time: b.LastSeenAt, Valid: !b.LastSeenAt.IsZero()})
	return err
}

func (p *pgBehavioralBaselines) Get(ctx context.Context, tenantID string, userHash, senderDomainHash []byte) (*UserBehavioralBaseline, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT id, tenant_id, user_email_hash, sender_domain_hash,
       typical_send_hours, typical_device_types, avg_messages_per_week,
       last_seen_at, created_at, updated_at
  FROM user_behavioral_baselines
 WHERE tenant_id=$1 AND user_email_hash=$2 AND sender_domain_hash=$3`,
		tenantID, userHash, senderDomainHash)
	var b UserBehavioralBaseline
	var lastSeen sql.NullTime
	err := row.Scan(&b.ID, &b.TenantID, &b.UserEmailHash, &b.SenderDomainHash,
		pq.Array(&b.TypicalSendHours), pq.Array(&b.TypicalDeviceTypes),
		&b.AvgMessagesPerWeek, &lastSeen, &b.CreatedAt, &b.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		b.LastSeenAt = lastSeen.Time
	}
	return &b, nil
}

// --- org graphs -------------------------------------------------------------

type pgOrgGraphs struct{ db *postgres.DB }

func (p *pgOrgGraphs) Upsert(ctx context.Context, s *OrgGraphSnapshot) error {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	_, err := p.db.ExecContext(ctx, `
INSERT INTO org_graphs
    (id, tenant_id, built_at, graph_json, high_risk_user_ids,
     department_count, employee_count, group_count, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
    built_at=EXCLUDED.built_at,
    graph_json=EXCLUDED.graph_json,
    high_risk_user_ids=EXCLUDED.high_risk_user_ids,
    department_count=EXCLUDED.department_count,
    employee_count=EXCLUDED.employee_count,
    group_count=EXCLUDED.group_count
`, s.ID, s.TenantID, s.BuiltAt, s.GraphJSON,
		pq.Array(s.HighRiskIDs), s.DepartmentCount, s.EmployeeCount, s.GroupCount)
	return err
}

func (p *pgOrgGraphs) GetByTenant(ctx context.Context, tenantID string) (*OrgGraphSnapshot, error) {
	row := p.db.QueryRowContext(ctx, `
SELECT id, tenant_id, built_at, graph_json, high_risk_user_ids,
       department_count, employee_count, group_count, created_at
  FROM org_graphs WHERE tenant_id=$1`, tenantID)
	var s OrgGraphSnapshot
	err := row.Scan(&s.ID, &s.TenantID, &s.BuiltAt, &s.GraphJSON,
		pq.Array(&s.HighRiskIDs), &s.DepartmentCount, &s.EmployeeCount,
		&s.GroupCount, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func stringOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return string(b)
}
