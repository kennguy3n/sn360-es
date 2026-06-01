package evaluate

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Tier2FallbackConfig configures the primary + fallback Tier 2 client.
type Tier2FallbackConfig struct {
	// Primary is the self-hosted SLM client.
	Primary Tier2Client
	// Fallback is the external LLM endpoint (OpenAI/Anthropic/Bedrock).
	// When nil, fallback is disabled.
	Fallback Tier2Client
	// FallbackURL is the OpenAI-compatible endpoint for the external
	// provider. Used to construct the fallback client when Fallback is nil.
	FallbackURL string
	// FallbackAPIKey is the API key for the external provider.
	FallbackAPIKey string
	// FallbackModel is the model name for the external provider.
	// Defaults to "gpt-4o-mini".
	FallbackModel string
	// CircuitBreakerThreshold is the number of consecutive primary
	// failures before the circuit opens. Defaults to 3.
	CircuitBreakerThreshold int
	// CircuitBreakerTimeout is how long the circuit stays open before
	// attempting to half-open (test primary again). Defaults to 60s.
	CircuitBreakerTimeout time.Duration
	// Logger for fallback events.
	Logger *slog.Logger
}

type circuitState int32

const (
	circuitClosed   circuitState = 0
	circuitOpen     circuitState = 1
	circuitHalfOpen circuitState = 2
)

// Tier2FallbackClient wraps primary and fallback Tier2Clients with a
// circuit breaker. When the primary is healthy, all requests go to it.
// After CircuitBreakerThreshold consecutive failures, the circuit opens
// and requests go to the fallback. The circuit half-opens after the
// timeout to test the primary again.
type Tier2FallbackClient struct {
	primary  Tier2Client
	fallback Tier2Client
	log      *slog.Logger

	threshold int
	timeout   time.Duration

	mu               sync.Mutex
	state            circuitState
	consecutiveFails int
	openedAt         time.Time

	primaryCalls  atomic.Uint64
	fallbackCalls atomic.Uint64
}

// NewTier2FallbackClient constructs the client with circuit breaker logic.
func NewTier2FallbackClient(cfg Tier2FallbackConfig) (*Tier2FallbackClient, error) {
	if cfg.Primary == nil {
		return nil, ErrTier2Required
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.CircuitBreakerThreshold <= 0 {
		cfg.CircuitBreakerThreshold = 3
	}
	if cfg.CircuitBreakerTimeout <= 0 {
		cfg.CircuitBreakerTimeout = 60 * time.Second
	}

	fallback := cfg.Fallback
	if fallback == nil && cfg.FallbackURL != "" {
		model := cfg.FallbackModel
		if model == "" {
			model = "gpt-4o-mini"
		}
		// Temperature is left nil so the underlying
		// ternarybonsai provider applies its DefaultTemperature
		// (0.1, historically). Tier2FallbackConfig pre-dates the
		// generic provider abstraction; new callers that want a
		// different temperature should construct the fallback
		// through slm.New directly and inject it via
		// cfg.Fallback.
		fb, err := NewTier2HTTPClient(Tier2HTTPConfig{
			URL:       cfg.FallbackURL,
			APIKey:    cfg.FallbackAPIKey,
			Model:     model,
			Timeout:   30 * time.Second,
			MaxTokens: 512,
		})
		if err != nil {
			return nil, err
		}
		fallback = fb
	}

	return &Tier2FallbackClient{
		primary:   cfg.Primary,
		fallback:  fallback,
		log:       cfg.Logger,
		threshold: cfg.CircuitBreakerThreshold,
		timeout:   cfg.CircuitBreakerTimeout,
	}, nil
}

// ErrTier2Required is returned when the primary Tier 2 client is nil.
var ErrTier2Required = errNew("tier2_fallback: primary client is required")

// Evaluate implements Tier2Client with circuit breaker fallback.
func (c *Tier2FallbackClient) Evaluate(ctx context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	state := c.currentState()

	switch state {
	case circuitClosed, circuitHalfOpen:
		c.primaryCalls.Add(1)
		result, err := c.primary.Evaluate(ctx, req, hint)
		if err == nil {
			c.recordSuccess()
			return result, nil
		}
		c.recordFailure()
		if c.fallback == nil {
			return dto.Tier2Outcome{}, err
		}
		c.log.WarnContext(ctx, "tier2_fallback: primary failed, using fallback",
			slog.Any("error", err))
		c.fallbackCalls.Add(1)
		return c.fallback.Evaluate(ctx, req, hint)

	case circuitOpen:
		if c.fallback == nil {
			return dto.Tier2Outcome{}, errNew("tier2_fallback: circuit open and no fallback configured")
		}
		c.fallbackCalls.Add(1)
		return c.fallback.Evaluate(ctx, req, hint)

	default:
		panic(fmt.Sprintf("tier2_fallback: unexpected circuit state %d", state))
	}
}

func (c *Tier2FallbackClient) currentState() circuitState {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == circuitOpen && time.Since(c.openedAt) > c.timeout {
		c.state = circuitHalfOpen
		c.log.Info("tier2_fallback: circuit half-open, testing primary")
	}
	return c.state
}

func (c *Tier2FallbackClient) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consecutiveFails = 0
	if c.state == circuitHalfOpen {
		c.state = circuitClosed
		c.log.Info("tier2_fallback: circuit closed, primary recovered")
	}
}

func (c *Tier2FallbackClient) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consecutiveFails++
	if c.consecutiveFails >= c.threshold && c.state != circuitOpen {
		c.state = circuitOpen
		c.openedAt = time.Now()
		c.log.Warn("tier2_fallback: circuit opened",
			slog.Int("consecutive_failures", c.consecutiveFails))
	}
}

// Metrics returns the call counts for primary and fallback.
type Tier2FallbackMetrics struct {
	PrimaryCalls  uint64 `json:"primary_calls"`
	FallbackCalls uint64 `json:"fallback_calls"`
	CircuitState  string `json:"circuit_state"`
}

// Metrics returns the current call counters and circuit state.
func (c *Tier2FallbackClient) Metrics() Tier2FallbackMetrics {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()
	stateStr := "closed"
	switch state {
	case circuitOpen:
		stateStr = "open"
	case circuitHalfOpen:
		stateStr = "half_open"
	}
	return Tier2FallbackMetrics{
		PrimaryCalls:  c.primaryCalls.Load(),
		FallbackCalls: c.fallbackCalls.Load(),
		CircuitState:  stateStr,
	}
}

// errNew creates a plain error without importing "errors" directly.
func errNew(s string) error {
	return &plainError{s}
}

type plainError struct{ s string }

func (e *plainError) Error() string { return e.s }

// compile-time assertion
var _ Tier2Client = (*Tier2FallbackClient)(nil)
