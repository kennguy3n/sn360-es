package worker

import (
	"context"
	"encoding/binary"
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
	// Hasher is a configuration-level parity guard: the worker
	// writes per-(tenant, recipient_hash, sender_domain_hash)
	// rows into BehavioralBaselines using the already-hashed
	// columns on CommunicationHistory, so the function itself is
	// never invoked inside Run. It is required to be non-nil only
	// to ensure the deployment has wired the same PII hasher that
	// (a) the ingestion pipeline used to produce h.RecipientHash
	// and h.SenderDomainHash, and (b) the read side (e.g. the
	// Tier 0 ATO heuristic looking up a baseline by hashed
	// recipient) will use to query these rows back. Without that
	// guarantee the worker's writes would land in keys nothing
	// can ever look up; the guard surfaces the misconfiguration
	// at job-construction time instead of producing silently
	// orphaned rows. Required when Baselines is non-nil.
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

	// lastCycleStartedAt is a per-tenant map of "the wall-clock
	// start time of the last cycle that completed processing for
	// this tenant." The baseline-accumulation path uses the
	// per-tenant value as the lower bound for "this row has
	// genuinely new activity since we last sampled it": a
	// comm-history row whose LastSeenAt has not advanced past this
	// watermark must already have been sampled by an earlier
	// cycle, so re-appending would inflate the histogram with a
	// duplicate of an existing event. Without the watermark, the
	// default Window=30d / Interval=4h pairing would re-sample the
	// same LastSeenAt up to ~180 times for a single underlying
	// message — saturating the 168-sample FIFO cap with one pair's
	// stale timestamp and destroying the histogram's ability to
	// represent the actual message-time distribution that
	// relationship.BaselineAnomalyCheck consumes.
	//
	// Per-tenant rather than global: if tenant A succeeds but
	// tenant B's ListByTenant fails partway through a cycle, only
	// A's watermark advances. B's stays at its previous value so
	// the next cycle re-evaluates B's rows from the last
	// successful watermark — no histogram samples are lost just
	// because a peer tenant failed.
	//
	// Process-local rather than persisted: a worker restart resets
	// the map to empty, which means the first post-restart cycle
	// re-samples every in-window row once per tenant. That bounded
	// double-count (one extra sample per row per restart) is
	// preferable to the chronic over-sampling described above, and
	// it remains capped by the 168-entry FIFO. Persisting the
	// watermark in a config table would harden this further but is
	// out of scope for the baseline-accumulation fix.
	//
	// Lifecycle: at the bottom of each Run we prune entries whose
	// tenant ID no longer appears in the active Tenants.List set,
	// so deleted/deactivated tenants do not accumulate zombie
	// watermarks across years of cycles. The pruning is keyed on
	// the canonical Tenants.List output (the same source the row
	// loop iterates), so a transient failure in a peer tenant's
	// ListByTenant call (handled above) does NOT cause that tenant
	// to be pruned — the tenant is still present in `tenants`, only
	// its ListByTenant returned an error.
	//
	// Concurrency: Run is invoked serially by the scheduler so the
	// map needs no mutex; one writer, no concurrent readers.
	lastCycleStartedAt map[string]time.Time
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
	// CommunicationHistoryRepository.ListByTenant silently clamps
	// `limit` to CommHistoryListByTenantMaxLimit, so a worker
	// configured above the cap would otherwise miss the
	// difference and quietly process fewer rows per cycle than
	// the operator asked for. Warn at config time AND clamp the
	// internal field so j.maxPerTenant always reflects what
	// ListByTenant will actually return — any future code that
	// reads j.maxPerTenant for progress reporting, pagination, or
	// metrics sees the effective value rather than the operator's
	// over-large configured value. Operators who legitimately
	// need to iterate more rows per tenant per cycle must page
	// across multiple ListByTenant calls (see the docstring on
	// CommunicationHistoryRepository).
	if maxPerTenant > repository.CommHistoryListByTenantMaxLimit {
		logger.Warn("worker.relationship: MaxPerTenant exceeds repository cap; clamping to the cap",
			slog.Int("configured_max_per_tenant", maxPerTenant),
			slog.Int("repository_cap", repository.CommHistoryListByTenantMaxLimit))
		maxPerTenant = repository.CommHistoryListByTenantMaxLimit
	}
	return &RelationshipJob{
		cfg:                cfg,
		interval:           cfg.Interval,
		window:             window,
		maxPerTenant:       maxPerTenant,
		logger:             logger,
		classifier:         relationship.NewClassifier(relationship.ClassifyConfig{}),
		lastCycleStartedAt: map[string]time.Time{},
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
			// Watermark NOT advanced: this tenant's lastCycleStartedAt
			// keeps its previous value so the next cycle re-evaluates
			// rows from the last point we successfully sampled. A
			// partial outage of one tenant must not cost histogram
			// samples on the recovery cycle.
			continue
		}
		// Snapshot this tenant's previous-cycle watermark before
		// the row loop. The row loop uses it as the "genuinely new
		// activity since last cycle" gate; we advance the stored
		// watermark to `now` only AFTER the row loop completes so
		// a ctx cancellation mid-loop (handled inside the loop)
		// leaves the watermark untouched and the next cycle picks
		// up where this one left off. The zero value on the very
		// first per-tenant cycle (map miss) lets every in-window
		// row seed the histogram with one bootstrap sample.
		prevCycleStartedAt := j.lastCycleStartedAt[t.ID]
		// Per-tenant, per-cycle baseline cache: many communication
		// history rows share the same (recipient, sender_domain)
		// baseline. The cache collapses N rows-per-baseline into a
		// single Baselines.Get for the whole cycle; subsequent
		// rows pick up the running-aggregate state that
		// persistBaselineUpdate writes back into the cache. The
		// cache is created fresh per tenant so cross-tenant state
		// can never leak.
		cache := make(baselineCache)
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

			// Behavioral baseline accumulation: append the current
			// LastSeenAt hour to the existing per-(user,
			// sender_domain) send-hour distribution rather than
			// overwriting it with a single-element slice. The
			// accumulated histogram is what
			// relationship.BaselineAnomalyCheck consumes (see
			// internal/service/relationship/timing.go) — feeding it
			// a length-1 slice every cycle would collapse the
			// distribution and make the histogram useless.
			//
			// The modal (most-frequent) hour computed from the
			// updated distribution is then mirrored onto
			// h.TypicalHour so the worker's CAS write below
			// propagates it to communication_histories.typical_hour
			// for the Tier 0 ATO heuristic to read on the hot path.
			//
			// Important: the baseline preparation is split from its
			// persistence. prepareBaselineUpdate is read-only — it
			// fetches the prior baseline, appends sendHour to the
			// in-memory slice, and returns the prepared struct
			// without writing it back. The actual Upsert happens
			// only AFTER the canonical communication-history CAS
			// succeeds (see persistBaselineUpdate below), so a CAS
			// race rejection cannot leave a phantom sample in the
			// histogram that a subsequent cycle would observe and
			// double-count.
			modalHour := -1
			var preparedBaseline *repository.UserBehavioralBaseline
			// Only feed the baseline when this row genuinely had
			// new activity since the previous cycle. If LastSeenAt
			// has not advanced past prevCycleStartedAt the row was
			// already sampled in an earlier cycle and re-appending
			// the same hour would double-count the same underlying
			// message — which, with Window≫Interval, would saturate
			// the 168-sample FIFO cap with a single pair's timestamp
			// and destroy the histogram's representativeness.
			//
			// On the very first Run after process start
			// prevCycleStartedAt is the zero value, so every
			// in-window row passes this gate and seeds the
			// histogram with one bootstrap sample. The modal-hour
			// mirror to h.TypicalHour and the CAS write below still
			// run on every row regardless — only the histogram
			// append is gated.
			if j.cfg.Baselines != nil && j.cfg.Hasher != nil &&
				len(h.RecipientHash) > 0 && len(h.SenderDomainHash) > 0 &&
				h.LastSeenAt.After(prevCycleStartedAt) {
				sendHour := h.LastSeenAt.UTC().Hour()
				accumulated, bl := j.prepareBaselineUpdate(ctx, t.ID, h, sendHour, cache)
				if len(accumulated) > 0 {
					modalHour = modalHourOf(accumulated)
				}
				preparedBaseline = bl
			}
			if modalHour >= 0 && modalHour < 24 {
				h.TypicalHour = modalHour
			} else if h.TypicalHour < 0 || h.TypicalHour >= 24 {
				// Carry forward an existing valid value; otherwise
				// fall back to the sentinel so the repository's
				// CASE guard leaves the column untouched.
				h.TypicalHour = repository.TypicalHourUnset
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
				// Drop preparedBaseline on the floor — its append
				// was drawn from a stale snapshot, so persisting it
				// would pollute the histogram with a phantom
				// sample. The next cycle will re-read the row and
				// re-prepare against the fresher LastSeenAt.
				continue
			}
			// CAS landed — now safe to persist the prepared
			// baseline. A best-effort Upsert: persistence failure is
			// logged and the cycle still counts as processed, since
			// the canonical communication-history write succeeded.
			// The per-cycle cache is updated through persistBaselineUpdate
			// so subsequent rows for the same (recipient, sender_domain)
			// pair see the running aggregate.
			j.persistBaselineUpdate(ctx, t.ID, preparedBaseline, cache)
			processed++
		}
		// Tenant row loop reached its natural end (i.e. did not bail
		// out via ListByTenant failure above). Advance this tenant's
		// baseline-sampling watermark to `now` so the next cycle's
		// gate treats only rows whose LastSeenAt has moved past `now`
		// as genuinely new activity. Per-row failures inside the loop
		// (CAS race, hasher error, persistBaselineUpdate error) are
		// not tenant-level failures — they are individually logged
		// and counted but do not invalidate the cycle's watermark
		// advance.
		j.lastCycleStartedAt[t.ID] = now
	}
	// Prune watermark entries for tenants that no longer appear in
	// the canonical Tenants.List output. Deleted/deactivated
	// tenants would otherwise leave their entries in
	// lastCycleStartedAt indefinitely; in a long-running worker
	// processing tenant churn over years that map would grow
	// without bound. We use the same `tenants` slice the row loop
	// iterated above — a transient ListByTenant failure on a peer
	// tenant kept that tenant in the slice (the per-row error path
	// above does `continue`, not `delete`), so the prune does NOT
	// drop tenants whose data plane is briefly unreachable.
	pruned := 0
	if len(j.lastCycleStartedAt) > 0 {
		activeTenantIDs := make(map[string]struct{}, len(tenants))
		for _, t := range tenants {
			activeTenantIDs[t.ID] = struct{}{}
		}
		for tenantID := range j.lastCycleStartedAt {
			if _, ok := activeTenantIDs[tenantID]; !ok {
				delete(j.lastCycleStartedAt, tenantID)
				pruned++
			}
		}
	}
	j.logger.Info("worker.relationship: cycle complete",
		slog.Int("tenants", len(tenants)),
		slog.Int("rows", processed),
		slog.Int("decayed_count_7d", decayed7d),
		slog.Int("reclassified", reclassified),
		slog.Int("race_skipped", raceSkipped),
		slog.Int("corrupt_skipped", corruptSkipped),
		slog.Int("watermarks_pruned", pruned))
	return firstErr
}

// maxBaselineSendHours caps the per-(user, sender_domain)
// typical_send_hours slice so the column does not grow unbounded
// across years of cycles. 168 entries = one full week of hourly
// samples, which is enough resolution for the
// relationship.BaselineAnomalyCheck histogram to detect off-window
// sends without consuming a megabyte per pair in the worst case.
const maxBaselineSendHours = 168

// baselineCache is a per-tenant, per-cycle memoisation map for
// UserBehavioralBaseline lookups. A communication_histories scan
// can return many rows that share the same (recipient,
// sender_domain) pair — e.g. ten distinct senders within
// acme.example all writing to charlie@us.example produce ten rows
// keyed by (sender_hash, recipient_hash) but they all roll up to
// the same baseline keyed by (user_email_hash, sender_domain_hash).
// Without caching, prepareBaselineUpdate would re-issue the same
// Baselines.Get against Postgres N times per cycle; with caching,
// each unique baseline is fetched exactly once and the prepared
// hour is folded into the cached entry by persistBaselineUpdate so
// subsequent rows in the same cycle see the cumulative state.
//
// The cache is scoped to one tenant's iteration of the Run loop
// and discarded at the end of that tenant's pass — it is not a
// long-lived cache, just per-cycle memoisation. A nil value in the
// map encodes a negative result ("ErrNotFound was returned on
// first lookup") so subsequent rows for the same key skip the DB
// hit entirely.
type baselineCache map[string]*repository.UserBehavioralBaseline

// baselineCacheKey encodes the two hash byte-slices into a single
// string key that is unambiguously decomposable back into the
// original pair. The encoding is length-prefixed (4-byte
// big-endian length || bytes, twice) rather than
// separator-delimited:
//
// Today both hashes are fixed-width BLAKE2 outputs and a simple
// NUL separator would not collide, but "both inputs are always
// fixed-width" is a convention enforced nowhere in the type
// system — a future change to a variable-width hash (or to a
// composite key that includes a hashing salt or scheme identifier)
// that contained a literal NUL byte would silently collide under
// the old `recipient + "\x00" + domain` scheme. With a length
// prefix the encoding is injective by construction: the byte at
// each offset is decoded as part of either a length header or its
// declared payload, so no two distinct (recipientHash,
// senderDomainHash) pairs can ever produce the same key string
// regardless of how either hash's contents or width evolve. The
// negligible per-row cost (8 bytes of length headers + one byte
// allocation) buys collision-resistance that is correct by
// construction rather than by convention.
func baselineCacheKey(recipientHash, senderDomainHash []byte) string {
	buf := make([]byte, 0, 4+len(recipientHash)+4+len(senderDomainHash))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(recipientHash)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, recipientHash...)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(senderDomainHash)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, senderDomainHash...)
	return string(buf)
}

// prepareBaselineUpdate computes the accumulated send-hour
// distribution for this (tenant, user, sender_domain) tuple
// without writing it back. The returned baseline struct is ready
// for Upsert via persistBaselineUpdate once the canonical
// communication-history CAS has succeeded; deferring the write
// avoids polluting the histogram with phantom samples drawn from
// snapshots that ultimately lose a CAS race against ingestion.
//
// The function consults the per-cycle `cache` first to avoid the
// N+1 Get pattern for rows that share a baseline key. On a miss,
// it loads the prior baseline (if any), records the outcome in
// the cache (including the negative ErrNotFound case), appends
// sendHour to the TypicalSendHours slice (FIFO-capped at
// maxBaselineSendHours), recomputes AvgMessagesPerWeek from the
// snapshot's 30-day count, and returns:
//   - the in-memory accumulated hours slice (post-append,
//     post-trim), used by the caller to compute the modal hour;
//   - the prepared *repository.UserBehavioralBaseline ready for
//     Upsert, or nil if there is nothing meaningful to persist.
//
// A transient baseline-Get failure (other than ErrNotFound) is
// logged and the cache is NOT poisoned with a negative entry —
// the next row whose key collides will retry the Get against a
// healthy DB. The current row is skipped to preserve the existing
// histogram.
func (j *RelationshipJob) prepareBaselineUpdate(
	ctx context.Context,
	tenantID string,
	h repository.CommunicationHistory,
	sendHour int,
	cache baselineCache,
) ([]int, *repository.UserBehavioralBaseline) {
	if sendHour < 0 || sendHour >= 24 {
		return nil, nil
	}
	if j.cfg.Baselines == nil || j.cfg.Hasher == nil {
		return nil, nil
	}
	if len(h.RecipientHash) == 0 || len(h.SenderDomainHash) == 0 {
		return nil, nil
	}

	// Look up (or load) the prior baseline through the per-cycle
	// cache. A cache hit returns the value as-is (nil means
	// "ErrNotFound was cached on first encounter"); a cache miss
	// falls through to Baselines.Get and records the result.
	//
	// On a transient Get failure (DB timeout, connection blip) we
	// return (nil, nil) and leave the cache empty for this key —
	// subsequent rows that share the key will retry the Get rather
	// than silently inheriting the failure.
	key := baselineCacheKey(h.RecipientHash, h.SenderDomainHash)
	var prev *repository.UserBehavioralBaseline
	if cached, ok := cache[key]; ok {
		prev = cached
	} else {
		loaded, gerr := j.cfg.Baselines.Get(ctx, tenantID, h.RecipientHash, h.SenderDomainHash)
		switch {
		case gerr == nil:
			prev = loaded
			cache[key] = loaded
		case errors.Is(gerr, repository.ErrNotFound):
			prev = nil
			cache[key] = nil
		default:
			j.logger.Warn("worker.relationship: baseline get failed; skipping cycle to preserve histogram",
				slog.String("tenant_id", tenantID), slog.Any("error", gerr))
			return nil, nil
		}
	}

	var existingHours []int
	if prev != nil {
		existingHours = append(existingHours, prev.TypicalSendHours...)
	}
	existingHours = append(existingHours, sendHour)
	// FIFO trim: drop the oldest samples once the slice exceeds
	// the cap. The histogram is order-insensitive (it just counts
	// per-hour occurrences) so any eviction policy works; FIFO
	// is the simplest and keeps the most recent week of behaviour
	// in the window.
	if len(existingHours) > maxBaselineSendHours {
		existingHours = existingHours[len(existingHours)-maxBaselineSendHours:]
	}
	updated := existingHours

	var avgPerWeek float64
	if h.Count30d > 0 {
		avgPerWeek = float64(h.Count30d) / 4.0
	}

	bl := &repository.UserBehavioralBaseline{
		TenantID:           tenantID,
		UserEmailHash:      h.RecipientHash,
		SenderDomainHash:   h.SenderDomainHash,
		TypicalSendHours:   updated,
		AvgMessagesPerWeek: avgPerWeek,
		LastSeenAt:         h.LastSeenAt,
	}
	if prev != nil {
		// Preserve the row id and device-type distribution that
		// upstream callers (future: client fingerprint worker) may
		// have populated. Upsert is keyed on (tenant_id,
		// user_email_hash, sender_domain_hash) so the id is
		// optional, but carrying it forward keeps the row stable
		// across cycles for log-tailing.
		bl.ID = prev.ID
		bl.TypicalDeviceTypes = prev.TypicalDeviceTypes
		bl.CreatedAt = prev.CreatedAt
	}
	return updated, bl
}

// persistBaselineUpdate writes a prepared baseline back to the
// repository. Called by Run only after the canonical
// communication-history CAS write has succeeded, so a CAS race
// rejection never produces a phantom sample in the histogram.
// Persistence failures are logged and swallowed: the canonical
// CAS has already committed and the next worker cycle will re-
// derive the baseline from scratch.
//
// On a successful Upsert the per-cycle cache entry is replaced
// with the just-persisted baseline so subsequent rows for the
// same (recipient, sender_domain) tuple in the same cycle see the
// cumulative accumulated hours instead of a stale start-of-cycle
// snapshot. Without this write-through, multiple rows sharing a
// key would each see only the original hours plus their own
// sample, losing the running aggregation across the cycle.
func (j *RelationshipJob) persistBaselineUpdate(
	ctx context.Context,
	tenantID string,
	bl *repository.UserBehavioralBaseline,
	cache baselineCache,
) {
	if bl == nil || j.cfg.Baselines == nil {
		return
	}
	if berr := j.cfg.Baselines.Upsert(ctx, bl); berr != nil {
		j.logger.Warn("worker.relationship: baseline upsert failed",
			slog.String("tenant_id", tenantID), slog.Any("error", berr))
		return
	}
	if cache != nil {
		cache[baselineCacheKey(bl.UserEmailHash, bl.SenderDomainHash)] = bl
	}
}

// modalHourOf returns the most-frequent hour-of-day from hours.
// Out-of-range entries are skipped. Returns -1 when no in-range
// samples are present so the caller's CASE-guarded write leaves
// communication_histories.typical_hour at its previous value.
//
// Ties are broken by lowest hour, which is deterministic and lets
// tests assert exact values without depending on map iteration
// order.
func modalHourOf(hours []int) int {
	if len(hours) == 0 {
		return -1
	}
	var counts [24]int
	total := 0
	for _, h := range hours {
		if h < 0 || h >= 24 {
			continue
		}
		counts[h]++
		total++
	}
	if total == 0 {
		return -1
	}
	// best := 0 is safe because the `total > 0` early-return
	// above guarantees at least one counts[h] >= 1 exists, so the
	// `c > best` comparison admits the first non-zero bucket on
	// strict-greater semantics. Initialising to 0 instead of -1
	// avoids the intermediate "mode = 0, best = 0" state that
	// briefly appears when counts[0] == 0, which reads as a bug
	// on first inspection. The result is identical.
	mode, best := -1, 0
	for h, c := range counts {
		if c > best {
			mode, best = h, c
		}
	}
	return mode
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
