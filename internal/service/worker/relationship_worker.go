package worker

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/relationship"
)

// CommunicationStore is the read side the relationship worker needs.
// It returns the per-(tenant) communication aggregates produced by
// the ingestion + management pipeline.
type CommunicationStore interface {
	ListByTenant(ctx context.Context, tenantID string, since time.Time, limit int) ([]repository.CommunicationHistory, error)
}

// TenantLister enumerates the tenants the worker should iterate
// over. The Postgres TenantRepository satisfies this.
type TenantLister interface {
	List(ctx context.Context, limit int) ([]repository.Tenant, error)
}

// CommunicationUpserter is the small write surface the relationship
// worker needs to persist refreshed counts. repository.CommunicationHistoryRepository
// already satisfies it.
type CommunicationUpserter interface {
	Upsert(ctx context.Context, h *repository.CommunicationHistory) error
}

// RelationshipJobConfig wires the relationship-aggregation worker.
type RelationshipJobConfig struct {
	// Interval is the gap between cycles. Required.
	Interval time.Duration
	// Tenants enumerates the tenants to process per cycle.
	Tenants TenantLister
	// Communications loads recent communication aggregates for a
	// tenant.
	Communications CommunicationStore
	// Upserter persists refreshed counts.
	Upserter CommunicationUpserter
	// Window is the lookback window applied to the
	// CommunicationStore query (default 30d).
	Window time.Duration
	// MaxPerTenant caps the number of communication rows refreshed
	// per cycle (default 1000).
	MaxPerTenant int
	// Logger is the structured logger; defaults to slog.Default().
	Logger *slog.Logger
}

// RelationshipJob refreshes the per-(tenant, sender, recipient)
// relationship counts that the ingestion pipeline relies on for
// Tier-0 routing. It walks every tenant, loads the recent
// CommunicationHistory rows, and re-upserts each one with refreshed
// 7-day / 30-day counts so the downstream classifier always sees
// up-to-date totals.
type RelationshipJob struct {
	cfg          RelationshipJobConfig
	interval     time.Duration
	window       time.Duration
	maxPerTenant int
	logger       *slog.Logger
}

// NewRelationshipJob constructs the job and applies defaults.
func NewRelationshipJob(cfg RelationshipJobConfig) (*RelationshipJob, error) {
	if cfg.Interval <= 0 {
		return nil, errors.New("worker: relationship interval must be > 0")
	}
	if cfg.Tenants == nil {
		return nil, errors.New("worker: relationship requires a TenantLister")
	}
	if cfg.Communications == nil {
		return nil, errors.New("worker: relationship requires a CommunicationStore")
	}
	if cfg.Upserter == nil {
		return nil, errors.New("worker: relationship requires an Upserter")
	}
	window := cfg.Window
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	maxPerTenant := cfg.MaxPerTenant
	if maxPerTenant <= 0 {
		maxPerTenant = 1000
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &RelationshipJob{
		cfg:          cfg,
		interval:     cfg.Interval,
		window:       window,
		maxPerTenant: maxPerTenant,
		logger:       logger,
	}, nil
}

// Name implements Job.
func (j *RelationshipJob) Name() string { return "relationship-aggregation" }

// Interval implements Job.
func (j *RelationshipJob) Interval() time.Duration { return j.interval }

// Run implements Job.
func (j *RelationshipJob) Run(ctx context.Context) error {
	tenants, err := j.cfg.Tenants.List(ctx, 0)
	if err != nil {
		return err
	}
	since := time.Now().UTC().Add(-j.window)
	var firstErr error
	processed := 0
	for _, t := range tenants {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, err := j.cfg.Communications.ListByTenant(ctx, t.ID, since, j.maxPerTenant)
		if err != nil {
			j.logger.Warn("worker.relationship: list communication histories failed",
				slog.String("tenant_id", t.ID), slog.Any("error", err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for i := range rows {
			h := rows[i]
			h.UpdatedAt = time.Now().UTC()
			if err := j.cfg.Upserter.Upsert(ctx, &h); err != nil {
				j.logger.Warn("worker.relationship: upsert failed",
					slog.String("tenant_id", t.ID), slog.Any("error", err))
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			processed++
		}
	}
	j.logger.Info("worker.relationship: cycle complete",
		slog.Int("tenants", len(tenants)),
		slog.Int("rows", processed))
	return firstErr
}

// VendorJobConfig wires the vendor-discovery worker.
type VendorJobConfig struct {
	Interval         time.Duration
	Tenants          TenantLister
	Communications   CommunicationStore
	Discovery        *relationship.VendorDiscovery
	VendorRepository repository.VendorRepository
	Window           time.Duration
	Logger           *slog.Logger
}

// VendorJob runs the recurring vendor-discovery heuristic. It walks
// every tenant, builds SenderObservations from the 30-day window of
// CommunicationHistory rows, asks the Discovery service for the
// best candidates, and persists the ones above the auto-approve
// threshold.
type VendorJob struct {
	cfg      VendorJobConfig
	interval time.Duration
	window   time.Duration
	logger   *slog.Logger
}

// NewVendorJob constructs the job with sensible defaults.
func NewVendorJob(cfg VendorJobConfig) (*VendorJob, error) {
	if cfg.Interval <= 0 {
		return nil, errors.New("worker: vendor interval must be > 0")
	}
	if cfg.Tenants == nil {
		return nil, errors.New("worker: vendor requires a TenantLister")
	}
	if cfg.Communications == nil {
		return nil, errors.New("worker: vendor requires a CommunicationStore")
	}
	if cfg.Discovery == nil {
		return nil, errors.New("worker: vendor requires a Discovery service")
	}
	window := cfg.Window
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &VendorJob{
		cfg:      cfg,
		interval: cfg.Interval,
		window:   window,
		logger:   logger,
	}, nil
}

// Name implements Job.
func (j *VendorJob) Name() string { return "vendor-discovery" }

// Interval implements Job.
func (j *VendorJob) Interval() time.Duration { return j.interval }

// Run implements Job.
func (j *VendorJob) Run(ctx context.Context) error {
	tenants, err := j.cfg.Tenants.List(ctx, 0)
	if err != nil {
		return err
	}
	since := time.Now().UTC().Add(-j.window)
	var firstErr error
	totalProposed := 0
	for _, t := range tenants {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, err := j.cfg.Communications.ListByTenant(ctx, t.ID, since, 10000)
		if err != nil {
			j.logger.Warn("worker.vendor: list communication histories failed",
				slog.String("tenant_id", t.ID), slog.Any("error", err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		obs := buildSenderObservations(rows)
		props, err := j.cfg.Discovery.Propose(ctx, t.ID, obs)
		if err != nil {
			j.logger.Warn("worker.vendor: propose failed",
				slog.String("tenant_id", t.ID), slog.Any("error", err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		totalProposed += len(props)
		if j.cfg.VendorRepository == nil {
			continue
		}
		for _, p := range props {
			v := &repository.Vendor{
				TenantID:       t.ID,
				Domain:         p.Domain,
				AutoDiscovered: true,
				Approved:       p.AutoApprove,
				Confidence:     p.Confidence,
				LastSeenAt:     time.Now().UTC(),
			}
			if err := j.cfg.VendorRepository.Upsert(ctx, v); err != nil {
				j.logger.Warn("worker.vendor: upsert vendor failed",
					slog.String("tenant_id", t.ID),
					slog.String("domain", p.Domain),
					slog.Any("error", err))
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	j.logger.Info("worker.vendor: cycle complete",
		slog.Int("tenants", len(tenants)),
		slog.Int("proposed", totalProposed))
	return firstErr
}

// buildSenderObservations turns CommunicationHistory rows into the
// SenderObservation shape the VendorDiscovery service expects.
// Observations are grouped by the plaintext SenderDomain — converting
// SenderDomainHash bytes to a string produces binary gibberish that
// can never match against real domains in VendorRepository.GetByDomain.
// Rows missing a plaintext SenderDomain are skipped so the discovery
// service never receives a junk-keyed observation.
func buildSenderObservations(rows []repository.CommunicationHistory) []relationship.SenderObservation {
	type acc struct {
		inbound      int
		distinctRecs map[string]struct{}
		firstSeen    time.Time
		lastSeen     time.Time
		domain       string
	}
	by := make(map[string]*acc)
	for _, r := range rows {
		domain := strings.ToLower(strings.TrimSpace(r.SenderDomain))
		if domain == "" {
			continue
		}
		a, ok := by[domain]
		if !ok {
			a = &acc{distinctRecs: map[string]struct{}{}, domain: domain}
			by[domain] = a
		}
		a.inbound += r.Count30d
		a.distinctRecs[string(r.RecipientHash)] = struct{}{}
		if a.firstSeen.IsZero() || r.FirstSeenAt.Before(a.firstSeen) {
			a.firstSeen = r.FirstSeenAt
		}
		if r.LastSeenAt.After(a.lastSeen) {
			a.lastSeen = r.LastSeenAt
		}
	}
	out := make([]relationship.SenderObservation, 0, len(by))
	for _, a := range by {
		out = append(out, relationship.SenderObservation{
			Domain:             a.domain,
			InboundCount:       a.inbound,
			DistinctRecipients: len(a.distinctRecs),
			FirstSeen:          a.firstSeen,
			LastSeen:           a.lastSeen,
		})
	}
	return out
}
