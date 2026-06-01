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
	//
	// IMPORTANT: this callback runs while the breaker's internal
	// mutex is held (it is called from transition, which is
	// reached from onSuccess / onFailure / allow — all of which
	// take cb.mu). Callbacks MUST NOT call back into the same
	// breaker (State(), Do(), etc.) or they will deadlock. Use
	// only thread-safe, non-blocking sinks such as Prometheus
	// observers and structured-log writers.
	OnStateChange func(from, to State)
	// OnShortCircuit is invoked synchronously every time Do skips
	// the wrapped op because allow() refused. Optional; primarily
	// for metrics emission (operators alert on a sustained
	// non-zero rate as the open-state signal).
	//
	// Two distinct call sites trigger this callback — the
	// counter conflates them by design:
	//
	//   (a) StateOpen and the open-window has not yet elapsed.
	//       This is the canonical "breaker is open" rejection.
	//   (b) StateHalfOpen, halfOpenProbe CAS lost (a concurrent
	//       caller already claimed the single probe slot for
	//       this open-cycle). The probe is in flight; this
	//       caller falls back to the open-state path.
	//
	// Dashboards that want to distinguish them should compare
	// against the CircuitBreakerState gauge (see
	// pkg/telemetry/metrics.go) — the gauge IS the
	// disambiguator. The counter alone is intentionally a
	// "fraction of calls the breaker rejected" signal, not a
	// state classifier.
	//
	// Unlike OnStateChange, this callback runs OUTSIDE cb.mu —
	// Do invokes it after allow() has released the lock and
	// returned false (see circuit_breaker.go::Do). It may
	// therefore be called concurrently from multiple goroutines,
	// and MUST use only thread-safe, non-blocking sinks such as
	// Prometheus counters and structured-log writers. The
	// callback IS allowed to call back into the breaker (State(),
	// Do(), etc.) because no lock is held — but doing so is still
	// poor taste and should be avoided.
	OnShortCircuit func()
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

	// halfOpenProbe gates the single trial request that the breaker
	// permits in StateHalfOpen. The first caller that wins the
	// compare-and-swap from false → true gets to call the
	// (presumably-recovered) downstream; every concurrent caller
	// receives ErrCircuitOpen instead of stampeding the dependency
	// that just came back from an outage. The slot is released by
	// onSuccess / onFailure (or by a transition that leaves
	// StateHalfOpen).
	//
	// All current accesses — the CAS in allow(), and the Store in
	// onSuccess and transition — happen while cb.mu is held, so a
	// plain bool would be functionally equivalent today. We keep
	// atomic.Bool deliberately as a future-proofing guarantee: if a
	// future refactor moves the half-open probe gate to a lock-free
	// fast path (e.g. an outer atomic check before the mutex
	// acquire), the CAS semantics already match what that path
	// would need. The cost is zero — atomic.Bool is a single word
	// with the same layout as a plain bool — and the contract
	// invariant ("at most one in-flight probe per half-open cycle")
	// is preserved either way.
	halfOpenProbe atomic.Bool

	// totals are atomics so metrics can be sampled without taking the lock.
	totalSuccess      atomic.Uint64
	totalFailure      atomic.Uint64
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
//
// Panic safety. If op panics — or terminates the goroutine via
// runtime.Goexit (e.g. t.Fatal in a test) — Do treats the abort as a
// failure for the purpose of breaker accounting. Without this, a panic
// inside the StateHalfOpen trial request would leave halfOpenProbe == true
// with no caller to release it and no onFailure to transition back to
// StateOpen, wedging the breaker permanently. The panic is NOT swallowed:
// the deferred handler records the failure (which itself releases the
// probe slot via transition(StateOpen)) and then lets the panic continue
// unwinding, so callers see the original stack.
func (cb *CircuitBreaker) Do(ctx context.Context, op func(context.Context) error) (err error) {
	if !cb.allow() {
		cb.totalShortCircuit.Add(1)
		if cb.cfg.OnShortCircuit != nil {
			cb.cfg.OnShortCircuit()
		}
		return ErrCircuitOpen
	}
	// Sentinel flag rather than recover()/re-panic so the original
	// panic value and stack trace propagate to the caller unchanged.
	// The flag stays true through any non-normal exit (panic, Goexit);
	// only the line right after op(ctx) returning clears it.
	aborted := true
	defer func() {
		if aborted {
			cb.onFailure()
		}
	}()
	err = op(ctx)
	aborted = false
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
		// Exactly one probe in flight at a time. Concurrent callers
		// race on a single-slot CAS — whoever wins flips the slot
		// from false→true and gets to call the downstream; everyone
		// else is short-circuited so a recovering service isn't
		// re-flooded the instant the open window expires.
		return cb.halfOpenProbe.CompareAndSwap(false, true)
	case StateOpen:
		if time.Since(cb.openedAt) >= cb.cfg.OpenTimeout {
			cb.transition(StateHalfOpen)
			// We're the first caller to discover the timer elapsed
			// and we hold the mutex — claim the probe slot before
			// any concurrent caller can. transition() has already
			// reset the slot to false, so this CAS is guaranteed
			// to succeed.
			return cb.halfOpenProbe.CompareAndSwap(false, true)
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
		} else {
			// Release the probe slot so the next half-open trial
			// can run while we wait for the success-threshold count
			// to be reached.
			cb.halfOpenProbe.Store(false)
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
		// A single half-open failure trips back to open; transition()
		// resets the probe slot for the next half-open window.
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
	// Reset the probe slot on every state change. Entering half-open
	// opens a fresh slot for the next trial; leaving half-open
	// (either back to open after a failure, or into closed after
	// enough successes) releases the slot so a future re-entry into
	// half-open starts clean.
	cb.halfOpenProbe.Store(false)
	if cb.cfg.OnStateChange != nil && from != to {
		cb.cfg.OnStateChange(from, to)
	}
}
