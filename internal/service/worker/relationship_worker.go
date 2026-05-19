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
// worker needs to persist refreshed counts. It is the
// optimistic-concurrency CAS view of
// repository.CommunicationHistoryRepository, NOT the full Upsert
// surface — the worker carries a stale snapshot across the
// list/decide/write boundary, so the only safe write is one that
// gates on the snapshot's UpdatedAt matching the row's current
// UpdatedAt. repository.CommunicationHistoryRepository satisfies
// this interface; the full-replacement Upsert stays the
// ingestion-time path.
type CommunicationUpserter interface {
	UpdateCountsIfFresh(ctx context.Context, h *repository.CommunicationHistory, readAt time.Time) (bool, error)
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
	// Baselines is the optional behavioral baseline repository.
	// When non-nil the worker extracts per-(user, sender_domain)
	// send-hour distributions from CommunicationHistory rows and
	// upserts them during each aggregation cycle.
	Baselines repository.UserBehavioralBaselineRepository
	// Hasher produces PII-safe hashes for the baseline keys.
	// Required when Baselines is non-nil.
	Hasher func(tenantID, input string) ([]byte, error)
}

// RelationshipJob refreshes the per-(tenant, sender, recipient)
// relationship counts that the ingestion pipeline relies on for
// Tier-0 routing. It walks every tenant and, for every recent
// CommunicationHistory row:
//
//   - Time-decays Count7d to zero when LastSeenAt has aged past the
//     rolling 7-day window. The ingestion-time upsert is monotonic
//     (it only ever increments), so without a periodic reset the
//     counter inflates indefinitely; this worker is the reset
//     authority. Count30d does not need a parallel decay step
//     because rows older than the 30-day window are excluded by the
//     ListByTenant `since` filter and therefore aren't loaded.
//   - Re-classifies the Relationship label by feeding the (possibly
//     decayed) counts and plaintext SenderDomain into
//     relationship.Classifier. The Classifier subsumes the
//     Partner / Customer / RecurringService / FirstTimeExternal /
//     LapsedContact taxonomy and produces the same value the
//     ingestion poller would compute for a fresh message.
//   - Persists the refreshed row via the Upserter's optimistic-
//     concurrency CAS write. The CAS guard prevents the worker's
//     stale-snapshot write from overwriting a fresher ingestion-time
//     Upsert that landed between ListByTenant and this point. When
//     the guard rejects the write (ingestion produced a fresher
//     snapshot in the meantime) the worker treats it as success and
//     leaves the ingestion value in place — re-running the decay
//     against ingestion's fresher counts would just resurrect the
//     same race on the next cycle.
//
// Rows missing the plaintext SenderDomain (legacy rows that
// pre-date migration 0004) still flow through the CAS path so
// UpdatedAt advances, but skip reclassification — the Classifier
// rejects an empty domain.
//
// Rows missing an UpdatedAt stamp are skipped entirely — the CAS
// guard requires a non-zero readAt to disambiguate "matches every
// row whose updated_at is also zero" from "matches the snapshot we
// loaded". Such rows are a database invariant violation in
// production (every Postgres Upsert path stamps updated_at), so
// skipping them surfaces the corruption via the
// `worker.relationship: skipped row with zero updated_at` log line
// rather than silently doing the wrong thing.
type RelationshipJob struct {
	cfg          RelationshipJobConfig
	interval     time.Duration
	window       time.Duration
	maxPerTenant int
	logger       *slog.Logger
	classifier   *relationship.Classifier
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
		classifier:   relationship.NewClassifier(relationship.ClassifyConfig{}),
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
	now := time.Now().UTC()
	since := now.Add(-j.window)
	recentCutoff := now.Add(-7 * 24 * time.Hour)
	var firstErr error
	processed := 0
	decayed7d := 0
	reclassified := 0
	raceSkipped := 0
	corruptSkipped := 0
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

			// Decay Count7d to zero when LastSeenAt has aged past
			// the rolling 7-day window. The ingestion-time upsert
			// is monotonic, so without a periodic reset the counter
			// inflates forever; this worker is the reset authority.
			if h.Count7d > 0 && h.LastSeenAt.Before(recentCutoff) {
				h.Count7d = 0
				decayed7d++
			}

			// Re-classify the relationship label using the
			// (possibly decayed) counts plus the plaintext
			// SenderDomain so downstream Tier-0 routing always
			// sees an up-to-date taxonomy. Rows with non-positive
			// Count30d are skipped because the Classifier treats
			// zero-count summaries as FirstTimeExternal — a value
			// that would be wrong for a row that necessarily had
			// historical activity to exist.
			domain := strings.ToLower(strings.TrimSpace(h.SenderDomain))
			if domain != "" && h.Count30d > 0 {
				// UniqueRecipients is 1 by construction: each
				// CommunicationHistory row represents a single
				// (sender, recipient) pair (the table's primary key
				// is the (tenant, sender_hash, recipient_hash)
				// triple), so a single row is one unique recipient
				// by definition. The Classifier only consumes this
				// field to gate Partner promotion, which is a
				// per-domain-aggregate concern handled separately by
				// VendorJob.buildSenderObservations below; passing 1
				// here keeps Relationship reclassification a
				// per-pair operation and avoids cross-row coupling.
				sum := relationship.CommunicationSummary{
					SenderDomain:     domain,
					InboundCount:     h.Count30d,
					FirstSeen:        h.FirstSeenAt,
					LastSeen:         h.LastSeenAt,
					UniqueRecipients: 1,
				}
				cat, cerr := j.classifier.Classify(ctx, "", sum)
				if cerr == nil && string(cat) != h.Relationship {
					h.Relationship = string(cat)
					reclassified++
				}
			}

			// Capture the snapshot's UpdatedAt as the CAS guard so
			// the write only lands if ingestion has not produced a
			// fresher version of this row between ListByTenant
			// (above) and now. A zero UpdatedAt means the row never
			// went through the canonical Postgres Upsert path, so
			// the CAS would either match every zero-updated_at row
			// (Postgres) or hit an error (the validation guard in
			// UpdateCountsIfFresh) — either way the safe action is
			// to skip rather than overwrite arbitrary state.
			readAt := h.UpdatedAt
			if readAt.IsZero() {
				j.logger.Warn("worker.relationship: skipped row with zero updated_at",
					slog.String("tenant_id", t.ID),
					slog.String("row_id", h.ID))
				corruptSkipped++
				continue
			}
			updated, err := j.cfg.Upserter.UpdateCountsIfFresh(ctx, &h, readAt)
			if err != nil {
				j.logger.Warn("worker.relationship: update-if-fresh failed",
					slog.String("tenant_id", t.ID), slog.Any("error", err))
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if !updated {
				raceSkipped++
				continue
			}
			processed++

			// Populate per-user behavioral baselines when the
			// baseline repository is wired.
			if j.cfg.Baselines != nil && j.cfg.Hasher != nil && len(h.RecipientHash) > 0 && len(h.SenderDomainHash) > 0 {
				sendHour := h.LastSeenAt.Hour()
				var avgPerWeek float64
				if h.Count30d > 0 {
					avgPerWeek = float64(h.Count30d) / 4.0
				}
				bl := &repository.UserBehavioralBaseline{
					TenantID:           t.ID,
					UserEmailHash:      h.RecipientHash,
					SenderDomainHash:   h.SenderDomainHash,
					TypicalSendHours:   []int{sendHour},
					AvgMessagesPerWeek: avgPerWeek,
					LastSeenAt:         h.LastSeenAt,
				}
				if berr := j.cfg.Baselines.Upsert(ctx, bl); berr != nil {
					j.logger.Warn("worker.relationship: baseline upsert failed",
						slog.String("tenant_id", t.ID), slog.Any("error", berr))
				}
			}
		}
	}
	j.logger.Info("worker.relationship: cycle complete",
		slog.Int("tenants", len(tenants)),
		slog.Int("rows", processed),
		slog.Int("decayed_count_7d", decayed7d),
		slog.Int("reclassified", reclassified),
		slog.Int("race_skipped", raceSkipped),
		slog.Int("corrupt_skipped", corruptSkipped))
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
