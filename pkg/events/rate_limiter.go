package events

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// RateLimitConfig configures per-tenant rate limiting for the event bus.
type RateLimitConfig struct {
	// MaxPerTenantPerSecond is the maximum number of messages any single
	// tenant can consume per second. Defaults to 100.
	MaxPerTenantPerSecond int
	// BurstSize is the token bucket burst capacity. Defaults to
	// 2x MaxPerTenantPerSecond.
	BurstSize int
	// IdleTTL is how long a tenant's bucket may sit untouched before it
	// becomes eligible for eviction. A bucket idle for this long has
	// refilled to full capacity, so dropping it is lossless. Defaults
	// to 10 minutes.
	IdleTTL time.Duration
	// SweepInterval bounds how often the idle-bucket sweep runs (it is
	// piggy-backed on the consume path under the existing lock, so it
	// never runs more than once per interval). Defaults to 1 minute.
	SweepInterval time.Duration
	// Logger for rate-limit events.
	Logger *slog.Logger
	// Clock for testing.
	Clock func() time.Time
}

// tokenBucket is a simple per-tenant token bucket rate limiter.
type tokenBucket struct {
	tokens    float64
	maxTokens float64
	rate      float64 // tokens per second
	lastFill  time.Time
}

func (b *tokenBucket) allow(now time.Time) bool {
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastFill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RateLimitedEventService wraps an EventService with per-tenant rate
// limiting on the consumer side. When a tenant exceeds its rate limit,
// messages are nacked with a backoff so the broker re-delivers them
// after the bucket refills.
type RateLimitedEventService struct {
	inner         EventService
	cfg           RateLimitConfig
	log           *slog.Logger
	now           func() time.Time
	idleTTL       time.Duration
	sweepInterval time.Duration
	mu            sync.Mutex
	buckets       map[string]*tokenBucket
	lastSweep     time.Time
}

// NewRateLimitedEventService wraps the inner service with rate limiting.
func NewRateLimitedEventService(inner EventService, cfg RateLimitConfig) *RateLimitedEventService {
	if cfg.MaxPerTenantPerSecond <= 0 {
		cfg.MaxPerTenantPerSecond = 100
	}
	if cfg.BurstSize <= 0 {
		cfg.BurstSize = cfg.MaxPerTenantPerSecond * 2
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 10 * time.Minute
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &RateLimitedEventService{
		inner:         inner,
		cfg:           cfg,
		log:           cfg.Logger,
		now:           cfg.Clock,
		idleTTL:       cfg.IdleTTL,
		sweepInterval: cfg.SweepInterval,
		buckets:       make(map[string]*tokenBucket),
		lastSweep:     cfg.Clock(),
	}
}

// Publish delegates to the inner service (publish-side is not rate limited).
func (s *RateLimitedEventService) Publish(ctx context.Context, subject string, data []byte, opts ...PublishOption) error {
	return s.inner.Publish(ctx, subject, data, opts...)
}

// Subscribe wraps the inner subscription with per-tenant rate limiting.
func (s *RateLimitedEventService) Subscribe(ctx context.Context, subject string, handler MessageHandler, opts ...SubscribeOption) (Subscription, error) {
	wrapped := func(ctx context.Context, msg Message) error {
		tenantID := msg.Headers()[HeaderTenantID]
		if tenantID != "" && !s.allow(tenantID) {
			s.log.WarnContext(ctx, "rate_limiter: tenant rate limited",
				slog.String("tenant", tenantID),
				slog.String("subject", subject))
			return msg.Nak(time.Second)
		}
		return handler(ctx, msg)
	}
	return s.inner.Subscribe(ctx, subject, wrapped, opts...)
}

// Health delegates to the inner service.
func (s *RateLimitedEventService) Health(ctx context.Context) error {
	return s.inner.Health(ctx)
}

// Close delegates to the inner service.
func (s *RateLimitedEventService) Close() error {
	return s.inner.Close()
}

func (s *RateLimitedEventService) allow(tenantID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepIdle(now)
	b, ok := s.buckets[tenantID]
	if !ok {
		b = &tokenBucket{
			tokens:    float64(s.cfg.BurstSize),
			maxTokens: float64(s.cfg.BurstSize),
			rate:      float64(s.cfg.MaxPerTenantPerSecond),
			lastFill:  now,
		}
		s.buckets[tenantID] = b
	}
	return b.allow(now)
}

// sweepIdle evicts per-tenant buckets that have been untouched for at
// least IdleTTL, at most once per SweepInterval. It is called on the
// consume path with s.mu already held, so it adds no goroutine or
// shutdown surface.
//
// Eviction is lossless: a bucket only qualifies once it has both sat
// idle for IdleTTL and refilled back to full capacity, so a tenant
// that returns after the idle window is handed a freshly-full bucket —
// the identical state it would have observed had the entry survived.
// This keeps the map proportional to the active-tenant working set
// rather than the count of tenants ever seen by the process.
func (s *RateLimitedEventService) sweepIdle(now time.Time) {
	if now.Sub(s.lastSweep) < s.sweepInterval {
		return
	}
	s.lastSweep = now
	for id, b := range s.buckets {
		if now.Sub(b.lastFill) < s.idleTTL {
			continue
		}
		projected := b.tokens + now.Sub(b.lastFill).Seconds()*b.rate
		if projected >= b.maxTokens {
			delete(s.buckets, id)
		}
	}
}

// compile-time assertion
var _ EventService = (*RateLimitedEventService)(nil)
