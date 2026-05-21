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
	"github.com/kennguy3n/sn360-es/internal/service/onboarding"
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
	return agent.ScoreWeights{
		AI:          float64(row.WeightAI),
		Rspamd:      float64(row.WeightRspamd),
		Attachments: float64(row.WeightAttachments),
		Links:       float64(row.WeightLinks),
	}, nil
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
		BannerBlocked:  row.ThresholdBlocked,
		BannerHighRisk: row.ThresholdHigh,
		BannerWarning:  row.ThresholdWarning,
		BannerCaution:  row.ThresholdCaution,
		BannerInfo:     row.ThresholdInfo,
	}, nil
}

// memoryConfigStore is a tiny in-memory ConfigStore implementation
// used until the management service exposes a proper score-engine
// write endpoint.
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
	histories, err := v.histories.ListByTenant(ctx, tenantID, since, 0)
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
