package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/handler"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/internal/service/dashboard"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/internal/service/onboarding"
	"github.com/kennguy3n/sn360-es/internal/service/tier0"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

// redisLabelCache adapts redis.Client to action.LabelCache.
type redisLabelCache struct{ client *redis.Client }

func (c redisLabelCache) Get(ctx context.Context, key string) (string, error) {
	v, ok, err := c.client.Get(ctx, key)
	if err != nil || !ok {
		return "", err
	}
	return v, nil
}

func (c redisLabelCache) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.client.Set(ctx, key, value, ttl)
}

// memoryLabelCache is the in-process fallback when Redis is not
// configured. Goroutine-safe; respects the supplied TTL.
//
// Expired entries are evicted lazily on Get and proactively by the
// janitor goroutine started via runJanitor(ctx). Without the
// janitor, keys that are written once and never read again would
// linger forever — Set overwrites the slot but does not sweep peers,
// so a long-running process can accumulate unbounded entries.
type memoryLabelCache struct {
	mu      sync.Mutex
	entries map[string]memoryLabelEntry
}

type memoryLabelEntry struct {
	value     string
	expiresAt time.Time
}

// memoryLabelCacheJanitorInterval is how often the janitor sweeps
// expired entries. Five minutes balances "bound memory growth" with
// "do not wake up frequently on idle deployments".
const memoryLabelCacheJanitorInterval = 5 * time.Minute

func newMemoryLabelCache() *memoryLabelCache {
	return &memoryLabelCache{entries: make(map[string]memoryLabelEntry)}
}

func (c *memoryLabelCache) Get(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return "", nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		delete(c.entries, key)
		return "", nil
	}
	return e.value, nil
}

func (c *memoryLabelCache) Set(_ context.Context, key, value string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := time.Time{}
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	c.entries[key] = memoryLabelEntry{value: value, expiresAt: exp}
	return nil
}

// sweepExpired removes every entry whose TTL has passed. Returns the
// number of entries evicted so the caller can log it.
func (c *memoryLabelCache) sweepExpired(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for k, e := range c.entries {
		if e.expiresAt.IsZero() {
			continue
		}
		if now.After(e.expiresAt) {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// runJanitor evicts expired entries on a fixed cadence until ctx is
// cancelled. It is intentionally blocking so callers can wrap it in
// a tracked goroutine (see application.StartBackground).
func (c *memoryLabelCache) runJanitor(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = memoryLabelCacheJanitorInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n := c.sweepExpired(now); n > 0 && logger != nil {
				logger.Debug("sn360-es: memoryLabelCache janitor swept entries",
					slog.Int("evicted", n))
			}
		}
	}
}

// newLabelCache picks the redis-backed adapter when redis is wired,
// otherwise it falls back to the in-memory implementation. Both
// satisfy action.LabelCache so the applier wiring is identical.
//
// When the in-memory cache is selected the returned *memoryLabelCache
// is also returned so the caller can wire its janitor goroutine —
// this avoids unbounded growth in long-running deployments that have
// not configured Redis. The second return value is nil for the redis
// path because the redis server enforces TTL eviction itself.
func newLabelCache(r *redis.Client) (action.LabelCache, *memoryLabelCache) {
	if r != nil {
		return redisLabelCache{client: r}, nil
	}
	mem := newMemoryLabelCache()
	return mem, mem
}

// redisURLStore adapts our redis.Client to the action.URLStore
// interface — the rewriter only needs Get/Set/TTL helpers.
type redisURLStore struct{ client *redis.Client }

func (s redisURLStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl)
}

func (s redisURLStore) Get(ctx context.Context, key string) (string, bool, error) {
	return s.client.Get(ctx, key)
}

// redisSingleUseStore adapts redis.Client to action.SingleUseStore via
// SET NX: the first MarkConsumed for a token id creates the key (so the
// caller is the first redeemer) and a replay finds it present. The key
// carries a TTL >= the token's remaining lifetime so a jti cannot be
// replayed within its validity window, after which Redis reclaims it.
type redisSingleUseStore struct {
	client *redis.Client
	prefix string
}

func (s redisSingleUseStore) MarkConsumed(ctx context.Context, id string, ttl time.Duration) (bool, error) {
	if id == "" {
		return false, errors.New("action: empty token id")
	}
	// Floor a non-positive TTL the same way InMemorySingleUseStore does:
	// a zero TTL would tell Redis to create a key with no expiry, leaking
	// the consumed-jti entry forever. Both SingleUseStore backends must
	// honor the same contract regardless of caller.
	if ttl <= 0 {
		ttl = time.Minute
	}
	set, err := s.client.SetNX(ctx, s.prefix+id, "1", ttl)
	if err != nil {
		return false, fmt.Errorf("action: single-use store: %w", err)
	}
	// SetNX set=true => key created (fresh token); set=false => the
	// key already existed (token already redeemed within its TTL).
	return !set, nil
}

// redisQuarantineStore adapts redis.Client to action.QuarantineStore.
// The quarantine service writes hex-encoded encrypted records keyed by
// QuarantineKey(tenant, pseudo_message_id).
type redisQuarantineStore struct{ client *redis.Client }

func (s redisQuarantineStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl)
}

func (s redisQuarantineStore) Get(ctx context.Context, key string) (string, bool, error) {
	return s.client.Get(ctx, key)
}

func (s redisQuarantineStore) Del(ctx context.Context, keys ...string) error {
	return s.client.Del(ctx, keys...)
}

// GetDel proxies to the redis client's atomic GETDEL primitive so
// the release flow can claim ownership of a quarantine reference in
// a single round-trip. Returns (value, true, nil) when the key
// existed, ("", false, nil) when the key was already absent, and
// errors on transport failure.
func (s redisQuarantineStore) GetDel(ctx context.Context, key string) (string, bool, error) {
	return s.client.GetDel(ctx, key)
}

// memoryQuarantineStore is the in-memory fallback used when Redis is
// not configured. It is goroutine-safe and respects the TTL parameter
// so dev / unit-test behaviour matches the redis path.
type memoryQuarantineStore struct {
	mu   sync.Mutex
	rows map[string]memoryQuarantineEntry
}

type memoryQuarantineEntry struct {
	value   string
	expires time.Time
}

func newMemoryQuarantineStore() *memoryQuarantineStore {
	return &memoryQuarantineStore{rows: map[string]memoryQuarantineEntry{}}
}

func (m *memoryQuarantineStore) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var expires time.Time
	if ttl > 0 {
		expires = time.Now().Add(ttl)
	}
	m.rows[key] = memoryQuarantineEntry{value: value, expires: expires}
	return nil
}

func (m *memoryQuarantineStore) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.rows[key]
	if !ok {
		return "", false, nil
	}
	if !entry.expires.IsZero() && time.Now().After(entry.expires) {
		delete(m.rows, key)
		return "", false, nil
	}
	return entry.value, true, nil
}

func (m *memoryQuarantineStore) Del(_ context.Context, keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.rows, k)
	}
	return nil
}

// GetDel is the in-memory twin of redisQuarantineStore.GetDel.
// Holding the mutex across the read-and-delete makes the operation
// atomic with respect to concurrent goroutines in the same process,
// which is the only concurrency model the memory fallback ever sees
// (it's single-replica by definition).
func (m *memoryQuarantineStore) GetDel(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.rows[key]
	if !ok {
		return "", false, nil
	}
	if !entry.expires.IsZero() && time.Now().After(entry.expires) {
		delete(m.rows, key)
		return "", false, nil
	}
	delete(m.rows, key)
	return entry.value, true, nil
}

// latestVerdictReevaluator implements action.QuarantineReevaluator by
// reading the most recent evaluation_result for the (tenant,
// pseudo_message_id) tuple from the repository.
type latestVerdictReevaluator struct {
	repo   repository.EvaluationResultRepository
	logger *slog.Logger
}

func newLatestVerdictReevaluator(repos *repository.Registry, logger *slog.Logger) *latestVerdictReevaluator {
	var r repository.EvaluationResultRepository
	if repos != nil {
		r = repos.EvaluationResults
	}
	return &latestVerdictReevaluator{repo: r, logger: logger}
}

// Reevaluate satisfies action.QuarantineReevaluator.
func (r *latestVerdictReevaluator) Reevaluate(ctx context.Context, tenantID, pseudoMessageID string) (dto.EvaluateResult, error) {
	if r.repo == nil {
		if r.logger != nil {
			r.logger.WarnContext(ctx,
				"release: no evaluation_results repo; returning conservative still-blocked verdict",
				slog.String("tenant_id", tenantID),
			)
		}
		return dto.EvaluateResult{
			TenantID:  tenantID,
			MessageID: pseudoMessageID,
			Tier:      constant.TierBlocked,
		}, nil
	}
	row, err := r.repo.GetByMessageHash(ctx, tenantID, []byte(pseudoMessageID))
	if errors.Is(err, repository.ErrNotFound) {
		return dto.EvaluateResult{
			TenantID:  tenantID,
			MessageID: pseudoMessageID,
			Tier:      constant.TierBlocked,
		}, nil
	}
	if err != nil {
		return dto.EvaluateResult{}, fmt.Errorf("reevaluator: lookup verdict: %w", err)
	}
	secondary := make([]constant.Category, 0, len(row.Secondary))
	for _, s := range row.Secondary {
		secondary = append(secondary, constant.Category(s))
	}
	return dto.EvaluateResult{
		TenantID:    row.TenantID,
		MessageID:   pseudoMessageID,
		Tier:        constant.Tier(row.Tier),
		Primary:     constant.Category(row.Primary),
		Secondary:   secondary,
		Score:       row.Score,
		ReasonCodes: row.ReasonCodes,
		Degraded:    row.Degraded,
		EvaluatedAt: row.EvaluatedAt,
	}, nil
}

// feedbackCountsAdapter converts repository.FeedbackEventRepository
// into the dashboard.FeedbackSource interface.
type feedbackCountsAdapter struct {
	repo repository.FeedbackEventRepository
}

func (a feedbackCountsAdapter) Counts(ctx context.Context, tenantID string, start, end time.Time) (dashboard.FeedbackCounts, error) {
	counts, err := a.repo.Counts(ctx, tenantID, start, end)
	if err != nil {
		return dashboard.FeedbackCounts{}, err
	}
	return dashboard.FeedbackCounts{
		ReportedPhishing: counts.ReportedPhishing,
		MarkedSafe:       counts.MarkedSafe,
		TrustedSender:    counts.TrustedSender,
	}, nil
}

// interstitialThreatIntel adapts the cache-fronted Tier 0 threat-intel
// checker to handler.ThreatIntel, giving the interstitial click handler
// a time-of-click recheck. It reuses the SAME StoreTIChecker (and its
// Redis negative cache) the evaluation pipeline uses, so a URL that was
// clean at delivery but later added to a feed is blocked when the
// recipient clicks the rewritten link — and cache entries are shared
// across the delivery-time and click-time lookups.
type interstitialThreatIntel struct {
	checker *tier0.StoreTIChecker
	logger  *slog.Logger
}

// CheckURL implements handler.ThreatIntel. It fails OPEN: an intel
// store / cache outage must not break legitimate clicks, since the
// message already passed full evaluation at delivery time. Only a
// confirmed block/quarantine-tier match (severity >= 50) blocks the
// click; lower-severity (flag-only) matches still redirect.
func (a interstitialThreatIntel) CheckURL(ctx context.Context, original string) (bool, string) {
	if a.checker == nil {
		return true, ""
	}
	matches, err := a.checker.CheckURL(ctx, original)
	if err != nil {
		if a.logger != nil {
			a.logger.WarnContext(ctx, "interstitial: threat-intel recheck failed; allowing click",
				slog.Any("error", err))
		}
		return true, ""
	}
	if len(matches) == 0 {
		return true, ""
	}
	strongest, _ := tier0.PickStrongest(matches)
	category, forced := tier0.SeverityTier(strongest.Severity)
	if !forced {
		return true, ""
	}
	return false, interstitialBlockReason(category)
}

// interstitialBlockReason renders a recipient-appropriate (no PII,
// no raw URL) explanation for the block page from the forced category.
func interstitialBlockReason(category constant.Category) string {
	switch category {
	case constant.CategoryLikelyPhishing:
		return "This destination is on a known phishing or malware threat-intelligence list."
	case constant.CategorySuspiciousURL:
		return "This destination matches a suspicious-URL threat-intelligence indicator."
	default:
		return "This destination matches a threat-intelligence indicator."
	}
}

// quarantineReleaseCountsAdapter converts a
// repository.QuarantineReleaseAuditRepository into the dashboard
// QuarantineReleaseCountsReader interface so the dashboard's
// quarantine panel can surface Released / Refused counts from the
// WS-3a self-service release audit trail (migration 0022).
type quarantineReleaseCountsAdapter struct {
	repo repository.QuarantineReleaseAuditRepository
}

func (a quarantineReleaseCountsAdapter) CountByOutcome(ctx context.Context, tenantID string, start, end time.Time) (dashboard.QuarantineReleaseCounts, error) {
	counts, err := a.repo.CountByOutcome(ctx, tenantID, start, end)
	if err != nil {
		return dashboard.QuarantineReleaseCounts{}, err
	}
	return dashboard.QuarantineReleaseCounts{
		Released: counts.Released,
		Refused:  counts.Refused,
	}, nil
}

// passthroughEncryptor is a last-resort URLEncryptor that returns the
// input unchanged.
type passthroughEncryptor struct{}

func (passthroughEncryptor) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func (passthroughEncryptor) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	return append([]byte(nil), ciphertext...), nil
}

// tierDeciderAdapter bridges the production *action.TierDecider to the
// evaluate package's TierDecider interface.
type tierDeciderAdapter struct{ decider *action.TierDecider }

func (a tierDeciderAdapter) Decide(score int, primary constant.Category, _ dto.RiskSignals) constant.Tier {
	if a.decider == nil {
		return constant.TierInformational
	}
	return a.decider.Decide(dto.EvaluateResult{Score: score, Primary: primary})
}

// escalationPublisherAdapter narrows events.EventService down to the
// (Publish-only) shape the escalation service requires.
type escalationPublisherAdapter struct{ bus events.EventService }

func (a escalationPublisherAdapter) Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	if a.bus == nil {
		return nil
	}
	return a.bus.Publish(ctx, subject, data, opts...)
}

// Tier 0 and Fallback adapters used to live here. After Group 1b
// unified the gate / evaluator signatures (Apply(req, signals) →
// Tier0Outcome and Evaluate(ctx, req, signals) → EvaluateResult),
// *tier0.Gate satisfies evaluate.Tier0BatchGate directly and
// *evaluate.Evaluator satisfies evaluate.MessageEvaluator directly,
// so no wrapper types are needed here. The Tier 0 bypass →
// EvaluateResult translation moved into evaluate.tier0BypassResult
// so the batch path owns the same outcome shape the per-message
// evaluator produces.

// loggingAuditLog implements agent.AuditLog by emitting structured
// log lines.
type loggingAuditLog struct {
	logger *slog.Logger
}

func (l loggingAuditLog) Record(_ context.Context, entry agent.AuditEntry) error {
	l.logger.Info("agent.audit",
		slog.String("agent", entry.Agent),
		slog.String("tenant_id", entry.TenantID),
		slog.String("action", entry.Action),
		slog.String("reason", entry.Reason),
		slog.Time("occurred_at", entry.OccurredAt),
		slog.Any("detail", entry.Detail))
	return nil
}

// evalLookupAdapter wraps the EvaluationResultRepository so the
// support agent can fetch the stored verdict for a message.
type evalLookupAdapter struct {
	repos *repository.Registry
}

func (a evalLookupAdapter) FindResult(ctx context.Context, tenantID, messageID string) (dto.EvaluateResult, error) {
	if a.repos == nil || a.repos.EvaluationResults == nil {
		return dto.EvaluateResult{}, fmt.Errorf("evaluation lookup: not wired")
	}
	row, err := a.repos.EvaluationResults.GetByMessageHash(ctx, tenantID, []byte(messageID))
	if err != nil {
		return dto.EvaluateResult{}, err
	}
	return dto.EvaluateResult{
		TenantID:    row.TenantID,
		MessageID:   messageID,
		Tier:        constant.Tier(row.Tier),
		Primary:     constant.Category(row.Primary),
		Score:       row.Score,
		ReasonCodes: row.ReasonCodes,
		EvaluatedAt: row.EvaluatedAt,
	}, nil
}

// tuningResultAdapter exposes the FeedbackEventRepository as the
// ResultRepository surface the tuning agent needs.
type tuningResultAdapter struct {
	repos *repository.Registry
}

func (a tuningResultAdapter) RecentFeedback(ctx context.Context, tenantID string, since time.Time) ([]agent.Feedback, error) {
	if a.repos == nil || a.repos.FeedbackEvents == nil {
		return nil, nil
	}
	rows, err := a.repos.FeedbackEvents.ListSince(ctx, tenantID, since)
	if err != nil {
		return nil, err
	}
	out := make([]agent.Feedback, 0, len(rows))
	for _, r := range rows {
		out = append(out, agent.Feedback{
			TenantID:   r.TenantID,
			MessageID:  r.PseudoMessageID,
			Action:     agent.FeedbackKind(r.Action),
			PriorTier:  constant.Tier(r.Tier),
			OccurredAt: r.OccurredAt,
		})
	}
	return out, nil
}

func (a tuningResultAdapter) CurrentWeights(ctx context.Context, tenantID string) (agent.ScoreWeights, error) {
	if a.repos == nil || a.repos.ScoreEngines == nil {
		return agent.ScoreWeights{}, fmt.Errorf("tuning: score engines not wired")
	}
	row, err := a.repos.ScoreEngines.Get(ctx, tenantID)
	if err != nil {
		return agent.ScoreWeights{}, err
	}
	// score_engine stores weights as integer percentages in [0, 100]
	// (the inverse of clampWeightToPercent in postgresConfigStore).
	// agent.ScoreWeights, however, is a renormalised float in [0, 1]
	// — tuning.clampWeights clamps to that range and divides by the
	// sum. Returning the raw integer here would push clampWeights
	// out of its operating range: every weight > 1 would clamp to 1
	// and renormalise to 1/N, silently corrupting the tenant's
	// learned distribution on the very next tuning pass. Divide by
	// 100 so the [0, 1] contract is preserved.
	return agent.ScoreWeights{
		AI:          float64(row.WeightAI) / 100.0,
		Rspamd:      float64(row.WeightRspamd) / 100.0,
		Attachments: float64(row.WeightAttachments) / 100.0,
		Links:       float64(row.WeightLinks) / 100.0,
	}, nil
}

// tenantScoringConfigAdapter is the evaluate.TenantScoringConfigLoader
// the production wiring hands to the evaluator and batch
// orchestrator. It reads the same score_engine row that
// tuningResultAdapter writes through, translates DB integer
// percentages back into the [0, 1] float weights the evaluator
// expects, and caches per-tenant results with a short TTL to keep
// hot-path latency bounded.
//
// The cache is deliberately tiny: hot-path evaluation runs at high
// QPS but the working set is bounded by the number of active
// tenants. A 60s TTL means the tuning agent's writes propagate to
// evaluation inside one minute — well below the per-tenant tuning
// cadence (which itself is on the order of hours) so latency in
// propagation is operationally invisible. Failed loads are not
// cached negatively; instead the evaluator's resolveTenantConfig
// falls back to the static defaults on error.
type tenantScoringConfigAdapter struct {
	repo repository.ScoreEngineRepository
	ttl  time.Duration

	mu    sync.RWMutex
	cache map[string]tenantScoringConfigCacheEntry

	// onInvalidate is called (without holding mu) for every
	// Invalidate(tenantID) call. The slm.Router registers its
	// Invalidate method here so per-tenant Tier 2 client caches are
	// cleared at the same time as the scoring-config cache —
	// without this hook the Router would keep handing back a stale
	// override client after an admin flips score_engine.tier2_provider.
	// Composition root sets the hook after both the adapter and
	// router exist; nil is fine, the adapter just skips the call.
	onInvalidate func(tenantID string)
}

type tenantScoringConfigCacheEntry struct {
	value evaluate.TenantScoringConfig
	// tier2Provider is the per-tenant Tier 2 (SLM) provider name
	// override loaded from score_engine.tier2_provider. The empty
	// string means "no override, use the deployment default".
	// Cached alongside value so a single score_engine load
	// services both the scoring-config lookup AND the Tier 2
	// provider lookup without two round trips per tenant.
	tier2Provider string
	expiresAt     time.Time
}

// newTenantScoringConfigAdapter constructs an adapter with the
// supplied repo + cache TTL. ttl <= 0 falls back to 60s.
func newTenantScoringConfigAdapter(repo repository.ScoreEngineRepository, ttl time.Duration) *tenantScoringConfigAdapter {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &tenantScoringConfigAdapter{
		repo:  repo,
		ttl:   ttl,
		cache: make(map[string]tenantScoringConfigCacheEntry),
	}
}

// LoadTenantScoringConfig implements evaluate.TenantScoringConfigLoader.
// Returns (zero, nil) on repository.ErrNotFound so the evaluator's
// resolveTenantConfig falls through to its static defaults — that
// pattern is documented on the interface as "no override, use the
// static defaults from Config" and is the desired behaviour for
// tenants that have not yet been tuned.
func (a *tenantScoringConfigAdapter) LoadTenantScoringConfig(ctx context.Context, tenantID string) (evaluate.TenantScoringConfig, error) {
	if a == nil || a.repo == nil || tenantID == "" {
		return evaluate.TenantScoringConfig{}, nil
	}
	if cached, ok := a.lookup(tenantID); ok {
		return cached, nil
	}
	tc, _, err := a.loadAndCacheTenantRow(ctx, tenantID)
	return tc, err
}

// loadAndCacheTenantRow is the single source of truth for hydrating
// the per-tenant cache from a score_engine row. It is called by both
// LoadTenantScoringConfig and LoadTenantTier2Provider so the DB-to-
// cache derivation lives in one place; schema additions (new
// columns, new derived fields) propagate to both callers
// automatically and there is no chance of lockstep mutation bugs
// where one method updates the derivation logic and the other
// silently keeps the old shape.
//
// On ErrNotFound the helper caches a "no row" sentinel (zero config,
// empty tier2Provider) so we don't hammer Postgres for every
// evaluation of an unconfigured tenant, and reports no error — the
// evaluator's static defaults are the documented contract for that
// state. Other DB errors are surfaced so the caller can decide
// whether to fail open (Router) or propagate (LoadTenantScoringConfig).
func (a *tenantScoringConfigAdapter) loadAndCacheTenantRow(
	ctx context.Context, tenantID string,
) (evaluate.TenantScoringConfig, string, error) {
	row, err := a.repo.Get(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			a.storeFull(tenantID, evaluate.TenantScoringConfig{}, "")
			return evaluate.TenantScoringConfig{}, "", nil
		}
		return evaluate.TenantScoringConfig{}, "", err
	}
	// score_engine columns are NOT NULL so a found row always
	// carries thresholds; populate the pointers from the row so
	// the evaluator distinguishes "row exists with PassBelow=0"
	// from "no row at all" instead of collapsing both onto the
	// static defaults.
	pass := row.ThresholdTier1PassBelow
	flag := row.ThresholdTier1FlagAbove
	tc := evaluate.TenantScoringConfig{
		Weights: evaluate.Weights{
			AI:          float64(row.WeightAI) / 100.0,
			Rspamd:      float64(row.WeightRspamd) / 100.0,
			Attachments: float64(row.WeightAttachments) / 100.0,
			Links:       float64(row.WeightLinks) / 100.0,
		},
		Tier1PassThreshold: &pass,
		Tier1FlagThreshold: &flag,
	}
	tier2Provider := ""
	if row.Tier2Provider != nil {
		tier2Provider = *row.Tier2Provider
	}
	a.storeFull(tenantID, tc, tier2Provider)
	return tc, tier2Provider, nil
}

// LoadTenantTier2Provider implements slm.TenantProviderLoader. It
// resolves the per-tenant Tier 2 provider override from the same
// score_engine row that LoadTenantScoringConfig consults; an empty
// return value means "no override, use the deployment default",
// which is the steady-state expectation for the majority of
// tenants.
//
// Errors are surfaced upstream so the slm.Router can log them and
// fall back to the deployment default — a transient DB blip never
// fails Tier 2 evaluation outright.
func (a *tenantScoringConfigAdapter) LoadTenantTier2Provider(ctx context.Context, tenantID string) (string, error) {
	if a == nil || a.repo == nil || tenantID == "" {
		return "", nil
	}
	if cached, ok := a.lookupTier2Provider(tenantID); ok {
		return cached, nil
	}
	_, tier2Provider, err := a.loadAndCacheTenantRow(ctx, tenantID)
	return tier2Provider, err
}

// lookupTier2Provider returns the cached tier2Provider string for
// tenantID and whether the entry was a live (non-expired) cache hit.
// Distinguishes "miss" (load required) from "hit with empty
// override" (use deployment default) via the bool.
func (a *tenantScoringConfigAdapter) lookupTier2Provider(tenantID string) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	entry, ok := a.cache[tenantID]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.tier2Provider, true
}

func (a *tenantScoringConfigAdapter) lookup(tenantID string) (evaluate.TenantScoringConfig, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	entry, ok := a.cache[tenantID]
	if !ok {
		return evaluate.TenantScoringConfig{}, false
	}
	if time.Now().After(entry.expiresAt) {
		return evaluate.TenantScoringConfig{}, false
	}
	return entry.value, true
}

// storeFull writes both the scoring config and the Tier 2 provider
// override for tenantID under the cache's TTL. There is no
// single-arg store(...) shortcut by design: every caller must be
// explicit about whether it knows the tier2Provider value, because
// passing the wrong default (e.g. "") on a code path that has a
// real row would silently cache an empty override and make the
// Router fall through to the deployment default until the TTL
// elapsed. The ErrNotFound path in LoadTenantScoringConfig is the
// only caller that should pass "".
func (a *tenantScoringConfigAdapter) storeFull(tenantID string, tc evaluate.TenantScoringConfig, tier2Provider string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cache[tenantID] = tenantScoringConfigCacheEntry{
		value:         tc,
		tier2Provider: tier2Provider,
		expiresAt:     time.Now().Add(a.ttl),
	}
}

// sweepExpired removes every cache entry whose TTL has passed and
// returns the number of entries evicted so the caller can log it.
// Matches the memoryLabelCache pattern (lazy eviction on lookup +
// proactive janitor) so a multi-tenant SaaS with churn does not
// accumulate entries for deactivated tenants indefinitely.
func (a *tenantScoringConfigAdapter) sweepExpired(now time.Time) int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	removed := 0
	for k, e := range a.cache {
		if now.After(e.expiresAt) {
			delete(a.cache, k)
			removed++
		}
	}
	return removed
}

// tenantScoringConfigJanitorInterval is how often the janitor sweeps
// expired entries. Two ttls is conservative enough to evict entries
// well before unbounded growth becomes operationally visible while
// keeping the wakeup rate near-idle on small deployments.
const tenantScoringConfigJanitorInterval = 2 * time.Minute

// runJanitor evicts expired entries on a fixed cadence until ctx is
// cancelled. It is intentionally blocking so callers can wrap it in
// a tracked goroutine (see application.StartBackground), matching
// memoryLabelCache.runJanitor.
func (a *tenantScoringConfigAdapter) runJanitor(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if a == nil {
		return
	}
	if interval <= 0 {
		interval = tenantScoringConfigJanitorInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n := a.sweepExpired(now); n > 0 && logger != nil {
				logger.Debug("sn360-es: tenantScoringConfigAdapter janitor swept entries",
					slog.Int("evicted", n))
			}
		}
	}
}

// Invalidate drops the cached entry for tenantID so the next
// LoadTenantScoringConfig call re-reads from the repository. The
// tuning agent's UpdateWeights / UpdateThresholds path can call this
// after a successful write so its own subsequent reads see the new
// values without waiting for TTL expiry.
func (a *tenantScoringConfigAdapter) Invalidate(tenantID string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	delete(a.cache, tenantID)
	hook := a.onInvalidate
	a.mu.Unlock()
	// Call the downstream hook (e.g. slm.Router.Invalidate) outside
	// the lock so it cannot deadlock against any goroutine that
	// re-enters the adapter while invalidation propagates.
	if hook != nil {
		hook(tenantID)
	}
}

// SetOnInvalidate installs a callback fired (without holding the
// adapter's lock) for every Invalidate(tenantID). Used by the
// composition root to wire slm.Router.Invalidate so a tuning write —
// or any future admin write that calls Invalidate — clears both
// caches together. Passing nil clears any prior hook. Safe for
// concurrent calls with Invalidate; the hook is read under the same
// lock that protects the cache map.
func (a *tenantScoringConfigAdapter) SetOnInvalidate(hook func(tenantID string)) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.onInvalidate = hook
	a.mu.Unlock()
}

func (a tuningResultAdapter) CurrentThresholds(ctx context.Context, tenantID string) (agent.Thresholds, error) {
	if a.repos == nil || a.repos.ScoreEngines == nil {
		return agent.Thresholds{}, fmt.Errorf("tuning: score engines not wired")
	}
	row, err := a.repos.ScoreEngines.Get(ctx, tenantID)
	if err != nil {
		return agent.Thresholds{}, err
	}
	return agent.Thresholds{
		Tier1PassBelow: row.ThresholdTier1PassBelow,
		Tier1FlagAbove: row.ThresholdTier1FlagAbove,
		BannerBlocked:  row.ThresholdBlocked,
		BannerHighRisk: row.ThresholdHigh,
		BannerWarning:  row.ThresholdWarning,
		BannerCaution:  row.ThresholdCaution,
		BannerInfo:     row.ThresholdInfo,
	}, nil
}

// scoringConfigInvalidator is the tiny surface postgresConfigStore
// needs to evict cached per-tenant scoring config after a write. It
// is intentionally smaller than tenantScoringConfigAdapter so tests
// can substitute a fake without dragging in the full cache.
type scoringConfigInvalidator interface {
	Invalidate(tenantID string)
}

// postgresConfigStore is the production ConfigStore implementation
// backed by the score_engine table (repository.ScoreEngineRepository).
// It is safe for concurrent use across AND within a single tenant.
//
// Steady-state writes go through column-scoped UPDATEs
// (repo.UpdateWeights / repo.UpdateThresholds), which set ONLY the
// columns owned by that write path. A concurrent UpdateWeights and
// UpdateThresholds against the same tenant therefore cannot
// overwrite each other — the read-modify-write race that a full-row
// Upsert would introduce simply does not exist for the steady-state
// path.
//
// First-time seeding (no row yet for the tenant) is detected when
// the column-scoped UPDATE returns repository.ErrNotFound. We then
// fall back to loadOrSeed + Upsert to materialise the row from the
// schema defaults plus the incoming write. The seed path is
// idempotent under concurrent first-time writers thanks to Postgres'
// ON CONFLICT (tenant_id) DO UPDATE in pgScoreEngines.Upsert, and
// because the onboarding agent always seeds before tuning runs in
// practice, the seed branch is rarely taken at all once a tenant is
// live.
//
// invalidator, when non-nil, is notified after every successful
// UpdateWeights / UpdateThresholds so the evaluator-side cache
// (tenantScoringConfigAdapter) does not return stale values for the
// TTL window after a tuning write. Nil is permitted for tests and
// keeps the store usable without a cache wired in.
type postgresConfigStore struct {
	repo        repository.ScoreEngineRepository
	invalidator scoringConfigInvalidator
}

func newPostgresConfigStore(repo repository.ScoreEngineRepository, inv scoringConfigInvalidator) *postgresConfigStore {
	return &postgresConfigStore{repo: repo, invalidator: inv}
}

func (s *postgresConfigStore) invalidate(tenantID string) {
	if s.invalidator != nil {
		s.invalidator.Invalidate(tenantID)
	}
}

// loadOrSeed returns the score_engine row for tenantID, falling back
// to the schema defaults (matching migrations/0001_init.up.sql plus
// migrations/0013_score_engine_tier1_thresholds.up.sql and
// migrations/0014_score_engine_weight_defaults.up.sql) if no row
// exists yet. The seeded row is NOT persisted until the caller does
// its own Upsert; this keeps row creation idempotent with the rest
// of the onboarding flow.
//
// The seeded weights/thresholds mirror the onboarding agent's
// DefaultWeights and DefaultThresholds (see
// internal/service/agent/onboarding.go) so a tenant whose row is
// materialised through this fallback path lands on the same
// configuration the onboarding agent would have seeded.
func (s *postgresConfigStore) loadOrSeed(ctx context.Context, tenantID string) (*repository.ScoreEngine, error) {
	row, err := s.repo.Get(ctx, tenantID)
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	return &repository.ScoreEngine{
		TenantID:                tenantID,
		ScoreBase:               100,
		WeightAI:                60,
		WeightRspamd:            10,
		WeightAttachments:       15,
		WeightLinks:             15,
		ThresholdBlocked:        85,
		ThresholdHigh:           70,
		ThresholdWarning:        50,
		ThresholdCaution:        30,
		ThresholdInfo:           15,
		ThresholdTier1PassBelow: 20,
		ThresholdTier1FlagAbove: 60,
		SubjectTagEnabled:       false,
		SubjectTagPrefix:        "",
	}, nil
}

func (s *postgresConfigStore) UpdateWeights(ctx context.Context, tenantID string, w agent.ScoreWeights) error {
	if s.repo == nil {
		return fmt.Errorf("postgres config store: score-engine repository is nil")
	}
	// agent.ScoreWeights are floats in [0, 1] (renormalised in
	// tuning.clampWeights). Persisting them as the integer percentage
	// keeps wire-compat with the existing score_engine row shape used
	// by tuningResultAdapter.CurrentWeights below.
	update := repository.ScoreWeightUpdate{
		WeightAI:          clampWeightToPercent(w.AI),
		WeightRspamd:      clampWeightToPercent(w.Rspamd),
		WeightAttachments: clampWeightToPercent(w.Attachments),
		WeightLinks:       clampWeightToPercent(w.Links),
	}
	// Steady-state path: column-scoped UPDATE so a concurrent
	// UpdateThresholds against the same tenant cannot clobber these
	// four columns.
	err := s.repo.UpdateWeights(ctx, tenantID, update)
	if err == nil {
		s.invalidate(tenantID)
		return nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("postgres config store: update tenant %q weights: %w", tenantID, err)
	}
	// First-time seed: there is no row yet for this tenant. Fall back
	// to loadOrSeed + Upsert so the row materialises with the schema
	// defaults plus the incoming weights. This branch is racy only
	// against another first-time writer for the same tenant, in which
	// case Upsert's ON CONFLICT (tenant_id) keeps the table
	// consistent.
	row, err := s.loadOrSeed(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("postgres config store: seed tenant %q: %w", tenantID, err)
	}
	row.WeightAI = update.WeightAI
	row.WeightRspamd = update.WeightRspamd
	row.WeightAttachments = update.WeightAttachments
	row.WeightLinks = update.WeightLinks
	if err := s.repo.Upsert(ctx, row); err != nil {
		return fmt.Errorf("postgres config store: upsert tenant %q weights: %w", tenantID, err)
	}
	s.invalidate(tenantID)
	return nil
}

func (s *postgresConfigStore) UpdateThresholds(ctx context.Context, tenantID string, t agent.Thresholds) error {
	if s.repo == nil {
		return fmt.Errorf("postgres config store: score-engine repository is nil")
	}
	update := repository.ScoreThresholdUpdate{
		Blocked:        t.BannerBlocked,
		High:           t.BannerHighRisk,
		Warning:        t.BannerWarning,
		Caution:        t.BannerCaution,
		Info:           t.BannerInfo,
		Tier1PassBelow: t.Tier1PassBelow,
		Tier1FlagAbove: t.Tier1FlagAbove,
	}
	// Steady-state path: column-scoped UPDATE so a concurrent
	// UpdateWeights cannot clobber these threshold columns and the
	// schema CHECK on threshold_tier1_pass_below <
	// threshold_tier1_flag_above (migration 0013) is enforced by the
	// DB on every write.
	err := s.repo.UpdateThresholds(ctx, tenantID, update)
	if err == nil {
		s.invalidate(tenantID)
		return nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("postgres config store: update tenant %q thresholds: %w", tenantID, err)
	}
	row, err := s.loadOrSeed(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("postgres config store: seed tenant %q: %w", tenantID, err)
	}
	row.ThresholdBlocked = update.Blocked
	row.ThresholdHigh = update.High
	row.ThresholdWarning = update.Warning
	row.ThresholdCaution = update.Caution
	row.ThresholdInfo = update.Info
	row.ThresholdTier1PassBelow = update.Tier1PassBelow
	row.ThresholdTier1FlagAbove = update.Tier1FlagAbove
	if err := s.repo.Upsert(ctx, row); err != nil {
		return fmt.Errorf("postgres config store: upsert tenant %q thresholds: %w", tenantID, err)
	}
	s.invalidate(tenantID)
	return nil
}

// clampWeightToPercent maps the agent's renormalised float weight
// (`0 ≤ w ≤ 1`) onto the integer percentage column type used by the
// score_engine table.
func clampWeightToPercent(w float64) int {
	if w <= 0 {
		return 0
	}
	if w >= 1 {
		return 100
	}
	return int(w*100 + 0.5)
}

// memoryConfigStore is the dev/test-only ConfigStore implementation.
//
// It is selected only when Postgres is unreachable (e.g. local
// `go test` without docker, or a smoke run without PG_HOST set) —
// production wiring in wire_services.go prefers postgresConfigStore.
// All state is held in-process and is lost on every restart, so any
// tuning agent decisions written through this store are forgotten
// next time the binary starts. The boot gate in
// assertProductionDurableStores promotes the slog.Warn it emits to a
// hard error when SN360ES_ENV=production.
type memoryConfigStore struct {
	mu         sync.Mutex
	weights    map[string]agent.ScoreWeights
	thresholds map[string]agent.Thresholds
}

func newMemoryConfigStore() *memoryConfigStore {
	return &memoryConfigStore{
		weights:    map[string]agent.ScoreWeights{},
		thresholds: map[string]agent.Thresholds{},
	}
}

func (s *memoryConfigStore) UpdateWeights(_ context.Context, tenantID string, w agent.ScoreWeights) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.weights[tenantID] = w
	return nil
}

func (s *memoryConfigStore) UpdateThresholds(_ context.Context, tenantID string, t agent.Thresholds) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.thresholds[tenantID] = t
	return nil
}

// piiHasherAdapter implements agent.PIIHasher by wrapping
// privacy.Pseudonymizer with a deterministic tenant key derivation.
type piiHasherAdapter struct {
	pseudo privacy.Pseudonymizer
	secret string
}

func (h *piiHasherAdapter) HashPII(tenantID string, input string) string {
	key := sha256.Sum256([]byte(h.secret + ":" + tenantID))
	return h.pseudo.HashOrEmpty(key[:], input)
}

// userPersisterAdapter implements agent.UserPersister by upserting
// discovered users and groups into the Postgres repositories.
type userPersisterAdapter struct {
	users  repository.UserRepository
	groups repository.GroupRepository
	hasher agent.PIIHasher
}

func (p *userPersisterAdapter) PersistDiscoveredUsers(ctx context.Context, tenantID string, users []agent.DiscoveredUser, groups []agent.DiscoveredGroup) error {
	now := time.Now().UTC()
	for _, g := range groups {
		if err := p.groups.Upsert(ctx, &repository.Group{
			ID:          g.ID,
			TenantID:    tenantID,
			Name:        g.Name,
			Description: g.Description,
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			return fmt.Errorf("persist group %s: %w", g.ID, err)
		}
	}
	for _, u := range users {
		if u.Email == "" {
			continue
		}
		var emailHash []byte
		if p.hasher != nil {
			emailHash = []byte(p.hasher.HashPII(tenantID, u.Email))
		}
		if err := p.users.Upsert(ctx, &repository.User{
			ID:              u.ID,
			TenantID:        tenantID,
			EmailHash:       emailHash,
			Role:            u.JobTitle,
			Department:      u.Department,
			SensitivityTier: u.SensitivityHint.DBTier(),
			CreatedAt:       now,
			UpdatedAt:       now,
		}); err != nil {
			return fmt.Errorf("persist user %s: %w", u.ID, err)
		}
	}
	return nil
}

// vendorScannerAdapter implements agent.VendorScanner using the
// communication-history repository.
type vendorScannerAdapter struct {
	histories repository.CommunicationHistoryRepository
}

func (v *vendorScannerAdapter) ScanRecentSenders(ctx context.Context, tenantID string, since time.Time) ([]agent.VendorCandidate, error) {
	// Pass the documented hard cap explicitly rather than relying on
	// the repository's clamp default. Vendor discovery only needs
	// the top-N most-recent senders per tenant; if a tenant ever
	// exceeds the cap, vendor discovery will resume from the
	// freshest rows on the next worker pass.
	histories, err := v.histories.ListByTenant(ctx, tenantID, since, repository.CommHistoryListByTenantMaxLimit)
	if err != nil {
		return nil, err
	}
	var candidates []agent.VendorCandidate
	for _, h := range histories {
		count := h.Count30d
		candidates = append(candidates, agent.VendorCandidate{
			Domain:     h.SenderDomain,
			SeenCount:  count,
			Confidence: vendorConfidence(count),
		})
	}
	return candidates, nil
}

func vendorConfidence(count int) float64 {
	switch {
	case count >= 50:
		return 0.95
	case count >= 20:
		return 0.85
	case count >= 10:
		return 0.75
	case count >= 5:
		return 0.65
	default:
		return 0.5
	}
}

// agentEventBusAdapter narrows the full event.Service surface to the
// minimal Publish(ctx, subject, data) shape the agent package depends on.
type agentEventBusAdapter struct {
	bus events.EventService
}

func (a agentEventBusAdapter) Publish(ctx context.Context, subject string, data []byte) error {
	return a.bus.Publish(ctx, subject, data)
}

// agentPublisherFromBus returns nil when bus is nil; otherwise the
// adapter that satisfies agent.EventPublisher.
func agentPublisherFromBus(bus events.EventService) agent.EventPublisher {
	if bus == nil {
		return nil
	}
	return agentEventBusAdapter{bus: bus}
}

// registryLabelApplier dispatches EnsureTierLabels to whichever
// provider (Gmail / Outlook) is registered for the tenant.
type registryLabelApplier struct {
	registry *providerRegistry
}

func (r registryLabelApplier) EnsureTierLabels(ctx context.Context, tenantID, mailbox string) error {
	entry := r.registry.lookup(tenantID)
	if entry == nil {
		return nil
	}
	if entry.labelProvider == nil {
		return nil
	}
	tiers := []constant.Tier{
		constant.TierBlocked,
		constant.TierHighRisk,
		constant.TierWarning,
		constant.TierCaution,
		constant.TierInformational,
	}
	for _, t := range tiers {
		if _, err := entry.labelProvider.EnsureLabel(ctx, mailbox, "SN360 / "+string(t), action.ColorFor(t)); err != nil {
			return err
		}
	}
	return nil
}

// workerLockAdapter adapts *redis.DistributedLock to the worker
// package's DistributedLock interface.
type workerLockAdapter struct {
	lock *redis.DistributedLock
}

func (a workerLockAdapter) Acquire(ctx context.Context) (bool, error) {
	return a.lock.Acquire(ctx)
}

func (a workerLockAdapter) Release(ctx context.Context) error {
	_, err := a.lock.Release(ctx)
	return err
}

// workerLockNoop is returned when the Redis lock primitive cannot
// be constructed.
type workerLockNoop struct{}

func (workerLockNoop) Acquire(context.Context) (bool, error) { return true, nil }
func (workerLockNoop) Release(context.Context) error         { return nil }

// workerMetricsAdapter funnels Job runner outcomes into the
// telemetry.Metrics counters.
type workerMetricsAdapter struct {
	m *telemetry.Metrics
}

func (a workerMetricsAdapter) ObserveCycle(name string, duration time.Duration, err error) {
	if a.m == nil {
		return
	}
	a.m.ObserveWorkerCycle(name, duration, err)
}

// intelTier0Observer adapts *telemetry.Metrics to the
// tier0.TIObserver interface so the gate can emit `ti_match`
// lookup / match counters without importing the telemetry
// package directly.
type intelTier0Observer struct {
	m *telemetry.Metrics
}

func (o intelTier0Observer) ObserveLookup(outcome string) {
	if o.m == nil || o.m.IntelTier0Lookups == nil {
		return
	}
	o.m.IntelTier0Lookups.WithLabelValues(outcome).Inc()
}

func (o intelTier0Observer) ObserveMatch(tier string) {
	if o.m == nil || o.m.IntelTier0Matches == nil {
		return
	}
	o.m.IntelTier0Matches.WithLabelValues(tier).Inc()
}

// intelWorkerMetricsAdapter implements
// worker.IntelMetricsRecorder against the telemetry registry.
type intelWorkerMetricsAdapter struct {
	m *telemetry.Metrics
}

func (a intelWorkerMetricsAdapter) ObserveIntelPoll(feed, outcome string, latency time.Duration, indicators int) {
	if a.m == nil {
		return
	}
	if a.m.IntelFeedPolled != nil {
		a.m.IntelFeedPolled.WithLabelValues(feed, outcome).Inc()
	}
	if a.m.IntelFeedLatency != nil {
		a.m.IntelFeedLatency.WithLabelValues(feed).Observe(latency.Seconds())
	}
	if outcome == "ok" && a.m.IntelFeedIndicators != nil && indicators > 0 {
		a.m.IntelFeedIndicators.WithLabelValues(feed).Add(float64(indicators))
	}
}

func (a intelWorkerMetricsAdapter) ObserveIntelStale(feed string) {
	if a.m == nil || a.m.IntelFeedStale == nil {
		return
	}
	a.m.IntelFeedStale.WithLabelValues(feed).Inc()
}

func (a intelWorkerMetricsAdapter) ObserveIntelGC(deleted int) {
	if a.m == nil || a.m.IntelGCDeleted == nil || deleted == 0 {
		return
	}
	a.m.IntelGCDeleted.Add(float64(deleted))
}

// ingestionLockAdapter adapts *redis.DistributedLock to the
// ingestion.DistributedLock interface.
type ingestionLockAdapter struct {
	lock *redis.DistributedLock
}

func (a ingestionLockAdapter) Acquire(ctx context.Context) (bool, error) {
	return a.lock.Acquire(ctx)
}

func (a ingestionLockAdapter) Release(ctx context.Context) error {
	_, err := a.lock.Release(ctx)
	return err
}

// onboardingServiceAdapter wraps *onboarding.Service to implement
// handler.OnboardingService by adding the Status method backed by
// the repository layer.
type onboardingServiceAdapter struct {
	svc   *onboarding.Service
	repos *repository.Registry
}

func (a *onboardingServiceAdapter) AuthURL(provider onboarding.ProviderType, tenantID string) (string, error) {
	return a.svc.AuthURL(provider, tenantID)
}

func (a *onboardingServiceAdapter) HandleCallback(ctx context.Context, stateTok, code string) (string, onboarding.ProviderType, error) {
	return a.svc.HandleCallback(ctx, stateTok, code)
}

func (a *onboardingServiceAdapter) Revoke(ctx context.Context, tenantID string, provider onboarding.ProviderType) error {
	return a.svc.Revoke(ctx, tenantID, provider)
}

func (a *onboardingServiceAdapter) Status(ctx context.Context, tenantID string) (handler.OnboardingStatus, error) {
	status := handler.OnboardingStatus{TenantID: tenantID, Status: "not_started"}
	if a.repos == nil {
		return status, nil
	}
	if a.repos.Users != nil {
		n, err := a.repos.Users.Count(ctx, tenantID)
		if err == nil {
			status.UsersDiscovered = n
		}
	}
	if a.repos.Groups != nil {
		n, err := a.repos.Groups.Count(ctx, tenantID)
		if err == nil {
			status.GroupsDiscovered = n
		}
	}
	switch {
	case status.UsersDiscovered > 0 || status.GroupsDiscovered > 0:
		status.Status = "completed"
	case a.svc != nil:
		for _, p := range []onboarding.ProviderType{onboarding.ProviderGoogle, onboarding.ProviderMicrosoft} {
			if a.svc.HasToken(ctx, tenantID, p) {
				status.Status = "in_progress"
				break
			}
		}
	}
	return status, nil
}

// aesGCMTokenEncryptor implements onboarding.TokenEncryptor using
// AES-256-GCM. Used to encrypt OAuth tokens at rest in Postgres.
type aesGCMTokenEncryptor struct {
	aead cipher.AEAD
}

func newAESGCMTokenEncryptor(key []byte) (*aesGCMTokenEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("token encryptor: key must be 32 bytes (got %d)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("token encryptor: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("token encryptor: %w", err)
	}
	return &aesGCMTokenEncryptor{aead: aead}, nil
}

func (e *aesGCMTokenEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *aesGCMTokenEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(ciphertext) < ns+e.aead.Overhead() {
		return nil, fmt.Errorf("token encryptor: ciphertext too short")
	}
	return e.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}
