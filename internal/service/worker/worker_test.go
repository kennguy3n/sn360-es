package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeJob struct {
	name     string
	interval time.Duration
	runErr   error
	runs     int32
	onRun    func(ctx context.Context)
}

func (j *fakeJob) Name() string            { return j.name }
func (j *fakeJob) Interval() time.Duration { return j.interval }
func (j *fakeJob) Run(ctx context.Context) error {
	atomic.AddInt32(&j.runs, 1)
	if j.onRun != nil {
		j.onRun(ctx)
	}
	return j.runErr
}

type fakeLock struct {
	mu       sync.Mutex
	acquired int
	released int
	deny     bool
	acqErr   error
	relErr   error
	held     bool
}

func (l *fakeLock) Acquire(context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.acquired++
	if l.acqErr != nil {
		return false, l.acqErr
	}
	if l.deny {
		return false, nil
	}
	l.held = true
	return true, nil
}
func (l *fakeLock) Release(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.released++
	if l.relErr != nil {
		return l.relErr
	}
	l.held = false
	return nil
}

type fakeMetrics struct {
	mu     sync.Mutex
	cycles []recordedCycle
}

type recordedCycle struct {
	Name     string
	Duration time.Duration
	Err      error
}

func (m *fakeMetrics) ObserveCycle(name string, d time.Duration, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cycles = append(m.cycles, recordedCycle{Name: name, Duration: d, Err: err})
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestNewRunner_RejectsBadConfig(t *testing.T) {
	if _, err := NewRunner(RunnerConfig{}); err == nil {
		t.Fatal("expected error for missing job")
	}
	if _, err := NewRunner(RunnerConfig{Job: &fakeJob{}}); err == nil {
		t.Fatal("expected error for empty job name")
	}
	if _, err := NewRunner(RunnerConfig{Job: &fakeJob{name: "x"}}); err == nil {
		t.Fatal("expected error for zero interval")
	}
}

func TestRunner_RunOnce_ExecutesJobAndRecordsMetrics(t *testing.T) {
	job := &fakeJob{name: "j1", interval: time.Hour}
	lock := &fakeLock{}
	metrics := &fakeMetrics{}
	r, err := NewRunner(RunnerConfig{
		Job:     job,
		Logger:  discardLogger(),
		Locks:   func(string) DistributedLock { return lock },
		Metrics: metrics,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	r.runCycle(context.Background())
	if atomic.LoadInt32(&job.runs) != 1 {
		t.Errorf("job runs: %d", job.runs)
	}
	if lock.acquired != 1 || lock.released != 1 {
		t.Errorf("lock acq=%d rel=%d", lock.acquired, lock.released)
	}
	if len(metrics.cycles) != 1 || metrics.cycles[0].Name != "j1" {
		t.Errorf("metrics: %+v", metrics.cycles)
	}
}

func TestRunner_LockDenied_SkipsCycle(t *testing.T) {
	job := &fakeJob{name: "j1", interval: time.Hour}
	lock := &fakeLock{deny: true}
	metrics := &fakeMetrics{}
	r, _ := NewRunner(RunnerConfig{
		Job: job, Logger: discardLogger(),
		Locks: func(string) DistributedLock { return lock }, Metrics: metrics,
	})
	r.runCycle(context.Background())
	if atomic.LoadInt32(&job.runs) != 0 {
		t.Errorf("expected job to be skipped, got %d runs", job.runs)
	}
	if lock.released != 0 {
		t.Errorf("release should not run when lock denied; got %d", lock.released)
	}
	if len(metrics.cycles) != 0 {
		t.Errorf("metrics should not record skipped cycle, got %d", len(metrics.cycles))
	}
}

func TestRunner_LockAcquireError_SkipsCycle(t *testing.T) {
	job := &fakeJob{name: "j1", interval: time.Hour}
	lock := &fakeLock{acqErr: errors.New("redis down")}
	r, _ := NewRunner(RunnerConfig{
		Job: job, Logger: discardLogger(),
		Locks: func(string) DistributedLock { return lock },
	})
	r.runCycle(context.Background())
	if atomic.LoadInt32(&job.runs) != 0 {
		t.Errorf("expected job to be skipped on acquire error")
	}
}

func TestRunner_JobErrorIsLogged_DoesNotPanic(t *testing.T) {
	job := &fakeJob{name: "j1", interval: time.Hour, runErr: errors.New("fail")}
	metrics := &fakeMetrics{}
	r, _ := NewRunner(RunnerConfig{Job: job, Logger: discardLogger(), Metrics: metrics})
	r.runCycle(context.Background())
	if len(metrics.cycles) != 1 || metrics.cycles[0].Err == nil {
		t.Errorf("metrics should record error: %+v", metrics.cycles)
	}
}

func TestRunner_Run_StopsOnContextCancel(t *testing.T) {
	job := &fakeJob{name: "j1", interval: 5 * time.Millisecond}
	r, _ := NewRunner(RunnerConfig{Job: job, Logger: discardLogger()})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	time.Sleep(15 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after cancel")
	}
	if atomic.LoadInt32(&job.runs) == 0 {
		t.Error("job should have run at least once")
	}
}

func TestRunner_RunCycle_NilLocks(t *testing.T) {
	job := &fakeJob{name: "j1", interval: time.Hour}
	r, _ := NewRunner(RunnerConfig{Job: job, Logger: discardLogger()})
	r.runCycle(context.Background())
	if atomic.LoadInt32(&job.runs) != 1 {
		t.Errorf("job should run without locks: %d", job.runs)
	}
}
