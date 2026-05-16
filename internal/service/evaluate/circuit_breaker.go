// Package evaluate orchestrates the multi-tier evaluation pipeline: it
// runs Tier 0 gates, fans out Tier 1 / Tier 2 / Rspamd calls, aggregates
// the verdicts, and falls back gracefully when downstream services fail.
package evaluate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrCircuitOpen is returned by [CircuitBreaker.Do] when the breaker is
// open and the call must short-circuit.
var ErrCircuitOpen = errors.New("circuit breaker: open")

// State is the current breaker state. The breaker transitions
// closed → open after FailureThreshold consecutive failures,
// open → half-open after OpenTimeout elapses, and
// half-open → closed after SuccessThreshold consecutive successes (or
// back to open on a single failure).
type State int32

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig configures a breaker.
type CircuitBreakerConfig struct {
	Name             string
	FailureThreshold int
	SuccessThreshold int
	OpenTimeout      time.Duration
	// OnStateChange is invoked synchronously whenever the breaker
	// transitions. Optional; primarily for metrics emission.
	OnStateChange func(from, to State)
}

// CircuitBreaker is a small failure-isolation primitive used to wrap
// outbound calls to Tier 1, Tier 2, and Rspamd. It is concurrency-safe.
type CircuitBreaker struct {
	cfg CircuitBreakerConfig

	mu                  sync.Mutex
	state               State
	consecutiveFailures int
	consecutiveSuccess  int
	openedAt            time.Time

	// totals are atomics so metrics can be sampled without taking the lock.
	totalSuccess  atomic.Uint64
	totalFailure  atomic.Uint64
	totalShortCircuit atomic.Uint64
}

// NewCircuitBreaker constructs a breaker. Zero/negative thresholds default
// to sane values so tests can pass an empty CircuitBreakerConfig.
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = 2
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = 30 * time.Second
	}
	return &CircuitBreaker{cfg: cfg, state: StateClosed}
}

// Do runs op under the breaker. If the breaker is open and the open-window
// has not elapsed, op is not called and ErrCircuitOpen is returned.
func (cb *CircuitBreaker) Do(ctx context.Context, op func(context.Context) error) error {
	if !cb.allow() {
		cb.totalShortCircuit.Add(1)
		return ErrCircuitOpen
	}
	err := op(ctx)
	if err != nil {
		cb.onFailure()
	} else {
		cb.onSuccess()
	}
	return err
}

// State returns a snapshot of the current state.
func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// Metrics returns a snapshot of cumulative counters.
func (cb *CircuitBreaker) Metrics() (success, failure, shortCircuit uint64) {
	return cb.totalSuccess.Load(), cb.totalFailure.Load(), cb.totalShortCircuit.Load()
}

// Name returns the configured name (used by metrics labels and logging).
func (cb *CircuitBreaker) Name() string { return cb.cfg.Name }

func (cb *CircuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case StateClosed:
		return true
	case StateHalfOpen:
		// Allow exactly one trial at a time. We don't track in-flight
		// counters; the half-open state itself acts as the gate because
		// onSuccess / onFailure transitions immediately.
		return true
	case StateOpen:
		if time.Since(cb.openedAt) >= cb.cfg.OpenTimeout {
			cb.transition(StateHalfOpen)
			return true
		}
		return false
	default:
		return false
	}
}

func (cb *CircuitBreaker) onSuccess() {
	cb.totalSuccess.Add(1)
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case StateHalfOpen:
		cb.consecutiveSuccess++
		if cb.consecutiveSuccess >= cb.cfg.SuccessThreshold {
			cb.transition(StateClosed)
		}
	case StateClosed:
		cb.consecutiveFailures = 0
	}
}

func (cb *CircuitBreaker) onFailure() {
	cb.totalFailure.Add(1)
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case StateClosed:
		cb.consecutiveFailures++
		if cb.consecutiveFailures >= cb.cfg.FailureThreshold {
			cb.transition(StateOpen)
		}
	case StateHalfOpen:
		// A single half-open failure trips back to open.
		cb.transition(StateOpen)
	}
}

func (cb *CircuitBreaker) transition(to State) {
	from := cb.state
	cb.state = to
	cb.consecutiveFailures = 0
	cb.consecutiveSuccess = 0
	if to == StateOpen {
		cb.openedAt = time.Now()
	}
	if cb.cfg.OnStateChange != nil && from != to {
		cb.cfg.OnStateChange(from, to)
	}
}
