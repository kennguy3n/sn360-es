package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recordingPruner struct {
	mu      sync.Mutex
	name    string
	removed int64
	err     error
	calls   []time.Time
}

func (p *recordingPruner) Name() string { return p.name }
func (p *recordingPruner) Prune(_ context.Context, before time.Time) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, before)
	if p.err != nil {
		return 0, p.err
	}
	return p.removed, nil
}

func TestNewCleanupJob_Validates(t *testing.T) {
	if _, err := NewCleanupJob(CleanupJobConfig{}); err == nil {
		t.Fatal("expected error for zero interval")
	}
	if _, err := NewCleanupJob(CleanupJobConfig{Interval: time.Second}); err == nil {
		t.Fatal("expected error for no pruners")
	}
}

func TestCleanupJob_Run_CallsAllPrunersWithCutoff(t *testing.T) {
	p1 := &recordingPruner{name: "a", removed: 5}
	p2 := &recordingPruner{name: "b", removed: 3}
	job, err := NewCleanupJob(CleanupJobConfig{
		Interval:      time.Hour,
		RetentionDays: 30,
		Pruners:       []Pruner{p1, p2},
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	before := time.Now()
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	after := time.Now()
	if len(p1.calls) != 1 || len(p2.calls) != 1 {
		t.Fatalf("each pruner should be called once; got %d, %d", len(p1.calls), len(p2.calls))
	}
	cutoff := p1.calls[0]
	wantMin := before.Add(-31 * 24 * time.Hour)
	wantMax := after.Add(-29 * 24 * time.Hour)
	if cutoff.Before(wantMin) || cutoff.After(wantMax) {
		t.Errorf("cutoff %s out of expected range [%s, %s]", cutoff, wantMin, wantMax)
	}
}

func TestCleanupJob_Run_ContinuesAfterPrunerFailure(t *testing.T) {
	p1 := &recordingPruner{name: "bad", err: errors.New("boom")}
	p2 := &recordingPruner{name: "good", removed: 7}
	job, _ := NewCleanupJob(CleanupJobConfig{
		Interval: time.Hour,
		Pruners:  []Pruner{p1, p2},
		Logger:   discardLogger(),
	})
	err := job.Run(context.Background())
	if err == nil || err.Error() != "boom" {
		t.Errorf("expected boom error, got %v", err)
	}
	if len(p2.calls) != 1 {
		t.Errorf("second pruner should still run after first failure: %d calls", len(p2.calls))
	}
}

func TestPrunerFunc_DelegatesToFn(t *testing.T) {
	p := NewPruner("x", func(_ context.Context, before time.Time) (int64, error) {
		if before.IsZero() {
			return 0, errors.New("zero")
		}
		return 42, nil
	})
	if p.Name() != "x" {
		t.Errorf("name: %q", p.Name())
	}
	if _, err := p.Prune(context.Background(), time.Time{}); err == nil {
		t.Error("expected error on zero before")
	}
	got, err := p.Prune(context.Background(), time.Now())
	if err != nil || got != 42 {
		t.Errorf("got %d, %v", got, err)
	}
}

func TestPrunerFunc_NilFnReturnsZero(t *testing.T) {
	p := &PrunerFunc{name: "n"}
	got, err := p.Prune(context.Background(), time.Now())
	if err != nil || got != 0 {
		t.Errorf("nil fn should return (0, nil); got (%d, %v)", got, err)
	}
}

func TestCleanupJob_NameAndInterval(t *testing.T) {
	job, _ := NewCleanupJob(CleanupJobConfig{
		Interval: 5 * time.Minute,
		Pruners:  []Pruner{&recordingPruner{name: "x"}},
	})
	if job.Name() != "cleanup" {
		t.Errorf("name: %q", job.Name())
	}
	if job.Interval() != 5*time.Minute {
		t.Errorf("interval: %s", job.Interval())
	}
}
