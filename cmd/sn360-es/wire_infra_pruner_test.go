package main

import (
	"context"
	"errors"
	"testing"
)

// TestRunBatchedPrune_LoopsUntilShortRead pins the batched-delete
// termination condition. The cleanup worker depends on this exact
// behaviour to drain backlog tables (evaluation_results,
// audit_logs, education_lesson_events, simulation_send_events) in
// fixed-size chunks rather than as a single unbounded DELETE.
//
// Scenario: a backlog of 11k rows older than the cutoff, batch
// size 5000 ⇒ runBatchedPrune must call the batch 3 times (5000 +
// 5000 + 1000) and return 11000 total.
func TestRunBatchedPrune_LoopsUntilShortRead(t *testing.T) {
	const batchSize = 5000
	const seed = int64(11_000)
	remaining := seed
	calls := 0
	batch := func(_ context.Context) (int64, bool, error) {
		calls++
		n := int64(batchSize)
		if remaining < n {
			n = remaining
		}
		remaining -= n
		return n, false, nil
	}
	total, err := runBatchedPrune(context.Background(), batchSize, batch)
	if err != nil {
		t.Fatalf("runBatchedPrune: %v", err)
	}
	if total != seed {
		t.Fatalf("total: got %d, want %d", total, seed)
	}
	if calls != 3 {
		t.Fatalf("calls: got %d, want 3", calls)
	}
}

// TestRunBatchedPrune_StopsOnFirstShortRead verifies the loop
// terminates after the FIRST short read — important because a
// "rows-affected = 0" terminal batch (a table that was already
// drained in a previous tick) must NOT be re-issued indefinitely.
func TestRunBatchedPrune_StopsOnFirstShortRead(t *testing.T) {
	calls := 0
	batch := func(_ context.Context) (int64, bool, error) {
		calls++
		// Single zero-row response on the first call.
		return 0, false, nil
	}
	total, err := runBatchedPrune(context.Background(), 5000, batch)
	if err != nil {
		t.Fatalf("runBatchedPrune: %v", err)
	}
	if total != 0 {
		t.Fatalf("total: got %d, want 0", total)
	}
	if calls != 1 {
		t.Fatalf("calls: got %d, want 1", calls)
	}
}

// TestRunBatchedPrune_RespectsContextCancellation pins the
// liveness guarantee: when the cleanup worker's parent context
// fires (binary shutdown, deadline), runBatchedPrune must return
// promptly with the cancellation error rather than continuing to
// hammer the DB.
//
// We pre-cancel the context before the first iteration so the
// guard at the top of the loop fires — that is the documented
// behaviour the cleanup worker relies on at shutdown.
func TestRunBatchedPrune_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	batch := func(_ context.Context) (int64, bool, error) {
		called = true
		return 5000, false, nil
	}
	total, err := runBatchedPrune(ctx, 5000, batch)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error: got %v, want context.Canceled", err)
	}
	if total != 0 {
		t.Fatalf("total: got %d, want 0", total)
	}
	if called {
		t.Fatal("batch should not have been invoked after cancellation")
	}
}

// TestRunBatchedPrune_PropagatesError verifies a DB-level batch
// error halts the loop and returns the rows successfully removed
// so far. The real-world version of this is a connection drop
// mid-prune: we want the cleanup metric to reflect the work that
// actually completed rather than rolling back to zero.
func TestRunBatchedPrune_PropagatesError(t *testing.T) {
	const batchSize = 100
	calls := 0
	wantErr := errors.New("simulated DB error")
	batch := func(_ context.Context) (int64, bool, error) {
		calls++
		switch calls {
		case 1:
			return int64(batchSize), false, nil
		case 2:
			return 0, false, wantErr
		default:
			t.Fatalf("unexpected call %d", calls)
			return 0, false, nil
		}
	}
	total, err := runBatchedPrune(context.Background(), batchSize, batch)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error: got %v, want %v", err, wantErr)
	}
	if total != int64(batchSize) {
		t.Fatalf("total: got %d, want %d", total, batchSize)
	}
	if calls != 2 {
		t.Fatalf("calls: got %d, want 2", calls)
	}
}

// TestRunBatchedPrune_BailsOnRowsAffectedUnknown verifies the
// driver-soft-fail escape hatch: when a hypothetical driver cannot
// report RowsAffected, runBatchedPrune returns the running total
// rather than spinning forever (the loop terminator depends on
// the affected count to detect "nothing left").
func TestRunBatchedPrune_BailsOnRowsAffectedUnknown(t *testing.T) {
	calls := 0
	batch := func(_ context.Context) (int64, bool, error) {
		calls++
		// Pretend the driver could not tell us how many rows
		// were deleted; runBatchedPrune must bail out.
		return 0, true, nil
	}
	total, err := runBatchedPrune(context.Background(), 5000, batch)
	if err != nil {
		t.Fatalf("runBatchedPrune: %v", err)
	}
	if total != 0 {
		t.Fatalf("total: got %d, want 0", total)
	}
	if calls != 1 {
		t.Fatalf("calls: got %d, want 1", calls)
	}
}
