package evaluate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreaker_ClosedPassesCallThrough(t *testing.T) {
	t.Parallel()
	cb := NewCircuitBreaker(CircuitBreakerConfig{Name: "t"})
	called := false
	err := cb.Do(context.Background(), func(context.Context) error {
		called = true
		return nil
	})
	if err != nil || !called {
		t.Fatalf("expected closed breaker to invoke op once: called=%v err=%v", called, err)
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected state=closed, got %s", cb.State())
	}
}

func TestCircuitBreaker_TripsAfterFailureThreshold(t *testing.T) {
	t.Parallel()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		OpenTimeout:      time.Hour, // far in the future
	})
	boom := errors.New("boom")
	for i := 0; i < 3; i++ {
		if err := cb.Do(context.Background(), func(context.Context) error { return boom }); err != boom {
			t.Fatalf("call %d: want %v, got %v", i, boom, err)
		}
	}
	if cb.State() != StateOpen {
		t.Fatalf("expected state=open after 3 failures, got %s", cb.State())
	}
	// Next call must short-circuit without invoking op.
	calls := 0
	err := cb.Do(context.Background(), func(context.Context) error { calls++; return nil })
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("want ErrCircuitOpen, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("op should not have been invoked while open; got %d calls", calls)
	}
}

func TestCircuitBreaker_HalfOpenSinglePassThrough(t *testing.T) {
	t.Parallel()
	// Drive the breaker into half-open via the timer.
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 5, // many successes needed; we want to observe a sequence of probes
		OpenTimeout:      time.Millisecond,
	})
	_ = cb.Do(context.Background(), func(context.Context) error { return errors.New("trip") })
	if cb.State() != StateOpen {
		t.Fatalf("setup: expected open, got %s", cb.State())
	}
	time.Sleep(5 * time.Millisecond)
	// At this point allow() will transition to half-open on the first
	// caller. Fire 100 concurrent requests; exactly one should make
	// it through to the op.
	const concurrent = 100
	var (
		opCalls       atomic.Int64
		shortCircuits atomic.Int64
		started       sync.WaitGroup
		release       = make(chan struct{})
		wg            sync.WaitGroup
	)
	started.Add(concurrent)
	wg.Add(concurrent)
	for i := 0; i < concurrent; i++ {
		go func() {
			defer wg.Done()
			started.Done()
			<-release
			err := cb.Do(context.Background(), func(context.Context) error {
				opCalls.Add(1)
				// Hold the probe slot long enough for every other
				// goroutine to attempt allow() and observe the
				// claimed slot. Without this delay the probe could
				// finish and release the slot before its peers
				// race, making the test trivially pass.
				time.Sleep(10 * time.Millisecond)
				return nil
			})
			if errors.Is(err, ErrCircuitOpen) {
				shortCircuits.Add(1)
			}
		}()
	}
	started.Wait()
	close(release)
	wg.Wait()
	if got := opCalls.Load(); got != 1 {
		t.Fatalf("half-open should admit exactly 1 op, got %d", got)
	}
	if got := shortCircuits.Load(); got != concurrent-1 {
		t.Fatalf("expected %d short-circuits, got %d", concurrent-1, got)
	}
}

func TestCircuitBreaker_HalfOpenSuccessClosesWhenThresholdMet(t *testing.T) {
	t.Parallel()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 2,
		OpenTimeout:      time.Millisecond,
	})
	_ = cb.Do(context.Background(), func(context.Context) error { return errors.New("trip") })
	time.Sleep(5 * time.Millisecond)

	// First probe — succeeds, breaker stays half-open (need 2 successes).
	if err := cb.Do(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("first probe: want nil, got %v", err)
	}
	if cb.State() != StateHalfOpen {
		t.Fatalf("after 1 success want half_open, got %s", cb.State())
	}
	// Second probe — succeeds, breaker closes.
	if err := cb.Do(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("second probe: want nil, got %v", err)
	}
	if cb.State() != StateClosed {
		t.Fatalf("after 2 successes want closed, got %s", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	t.Parallel()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 2,
		OpenTimeout:      time.Millisecond,
	})
	_ = cb.Do(context.Background(), func(context.Context) error { return errors.New("trip") })
	time.Sleep(5 * time.Millisecond)
	// Half-open probe fails — should re-open the breaker.
	err := cb.Do(context.Background(), func(context.Context) error { return errors.New("still down") })
	if err == nil {
		t.Fatalf("expected op error to surface")
	}
	if cb.State() != StateOpen {
		t.Fatalf("after half-open failure want open, got %s", cb.State())
	}
	// And the probe slot is reset, so when the timer expires again a
	// new probe can be admitted.
	time.Sleep(5 * time.Millisecond)
	called := false
	if err := cb.Do(context.Background(), func(context.Context) error { called = true; return nil }); err != nil {
		t.Fatalf("second half-open probe: want nil, got %v", err)
	}
	if !called {
		t.Fatalf("expected op to be invoked after re-opening")
	}
}

func TestCircuitBreaker_OnStateChangeFiresOnTransitions(t *testing.T) {
	t.Parallel()
	var transitions []string
	var mu sync.Mutex
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      time.Millisecond,
		OnStateChange: func(from, to State) {
			mu.Lock()
			transitions = append(transitions, from.String()+"->"+to.String())
			mu.Unlock()
		},
	})
	_ = cb.Do(context.Background(), func(context.Context) error { return errors.New("trip") })
	time.Sleep(5 * time.Millisecond)
	_ = cb.Do(context.Background(), func(context.Context) error { return nil })
	mu.Lock()
	defer mu.Unlock()
	if len(transitions) < 3 {
		t.Fatalf("expected at least 3 transitions, got %v", transitions)
	}
	if transitions[0] != "closed->open" || transitions[1] != "open->half_open" || transitions[2] != "half_open->closed" {
		t.Fatalf("unexpected transition sequence: %v", transitions)
	}
}
