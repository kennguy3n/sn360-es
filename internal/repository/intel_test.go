package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// fakeIndicatorExec records every ExecContext invocation issued by
// PgIntelStore.upsertIndicatorsBatch. We use it to assert the
// batched UpsertIndicators path:
//
//   - len(indicators) ≤ upsertBatchSize → exactly one ExecContext call
//     against the *postgres.DB directly (here we substitute the fake).
//   - len(indicators) >  upsertBatchSize → multiple ExecContext calls,
//     each carrying ≤ upsertBatchSize×upsertRowCols placeholders.
//
// The fake never speaks SQL; it just inspects the rendered statement
// and parameter slice so we can validate the chunking math without a
// running Postgres.
type fakeIndicatorExec struct {
	calls []fakeExecCall
	// rowsPerCall controls the RowsAffected returned per Exec.
	// Defaults to the row count derived from the placeholder span.
	rowsPerCall func(rows int) int64
	// failOnCall, when ≥ 0, makes the call at that index fail.
	failOnCall int
}

type fakeExecCall struct {
	query    string
	args     []any
	rowCount int
}

func newFakeExec() *fakeIndicatorExec {
	return &fakeIndicatorExec{failOnCall: -1}
}

func (f *fakeIndicatorExec) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	// Derive row count from arg length / upsertRowCols. Tests rely
	// on this to compute the aggregate "indicators landed" total.
	rows := len(args) / upsertRowCols
	idx := len(f.calls)
	f.calls = append(f.calls, fakeExecCall{
		query:    query,
		args:     append([]any(nil), args...),
		rowCount: rows,
	})
	if idx == f.failOnCall {
		return nil, errors.New("simulated postgres failure")
	}
	if f.rowsPerCall != nil {
		return fakeResult{rows: f.rowsPerCall(rows)}, nil
	}
	return fakeResult{rows: int64(rows)}, nil
}

// fakeResult implements sql.Result with a fixed RowsAffected. The
// LastInsertId path is not used by PgIntelStore.UpsertIndicators
// (Postgres doesn't surface autoincrement IDs via this interface)
// so it returns the conventional driver error.
type fakeResult struct {
	rows int64
}

func (f fakeResult) LastInsertId() (int64, error) { return 0, driver.ErrSkip }
func (f fakeResult) RowsAffected() (int64, error) { return f.rows, nil }

// mkIndicator produces a deterministic Indicator with a unique 32-
// byte hash so the upsert builder doesn't reject duplicates. The
// hash content is irrelevant to the chunking math; only its length
// must match the BYTEA shape Postgres expects.
func mkIndicator(seed int) intel.Indicator {
	hash := make([]byte, 32)
	hash[0] = byte(seed >> 8)
	hash[1] = byte(seed)
	return intel.Indicator{
		Hash:      hash,
		Indicator: fmt.Sprintf("evil-%d.example", seed),
		Type:      intel.IndicatorDomain,
		Severity:  50,
		Tags:      []string{"unit-test"},
	}
}

// TestUpsertIndicatorsBatch_SingleStatement verifies the small-feed
// fast path: any input with ≤ upsertBatchSize rows must hit
// ExecContext exactly once with len(args) == n × upsertRowCols.
func TestUpsertIndicatorsBatch_SingleStatement(t *testing.T) {
	t.Parallel()
	store := &PgIntelStore{now: func() time.Time { return time.Unix(1700000000, 0) }}
	exec := newFakeExec()

	indicators := make([]intel.Indicator, 10)
	for i := range indicators {
		indicators[i] = mkIndicator(i)
	}
	n, err := store.upsertIndicatorsBatch(context.Background(), exec, uuid.NewString(), indicators, store.now())
	if err != nil {
		t.Fatalf("upsertIndicatorsBatch: %v", err)
	}
	if n != 10 {
		t.Fatalf("rows returned = %d; want 10", n)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("calls = %d; want 1", len(exec.calls))
	}
	if got := len(exec.calls[0].args); got != 10*upsertRowCols {
		t.Errorf("args = %d; want %d", got, 10*upsertRowCols)
	}
	if !strings.Contains(exec.calls[0].query, "INSERT INTO intel_indicators") {
		t.Errorf("query missing INSERT prefix: %q", exec.calls[0].query)
	}
	if !strings.Contains(exec.calls[0].query, "ON CONFLICT (hash, feed_id)") {
		t.Errorf("query missing ON CONFLICT clause: %q", exec.calls[0].query)
	}
}

// TestUpsertIndicatorsBatch_PlaceholderCeiling makes the parameter-
// limit invariant explicit: at full upsertBatchSize the rendered
// statement carries exactly upsertBatchSize × upsertRowCols
// placeholders, which must stay strictly below Postgres' 65,535-
// parameter wire-protocol cap. If somebody widens the row schema
// without lowering upsertBatchSize, this test fails before the
// regression reaches production.
func TestUpsertIndicatorsBatch_PlaceholderCeiling(t *testing.T) {
	t.Parallel()
	const pgParamLimit = 65535
	if got := upsertBatchSize * upsertRowCols; got >= pgParamLimit {
		t.Fatalf("upsertBatchSize=%d × upsertRowCols=%d = %d placeholders "+
			"≥ Postgres limit %d — lower upsertBatchSize",
			upsertBatchSize, upsertRowCols, got, pgParamLimit)
	}
}

// TestUpsertIndicatorsBatch_EmptyChunk skips the round-trip entirely
// when handed an empty slice. The outer UpsertIndicators already
// short-circuits on len==0, but the inner helper is also called from
// the multi-batch loop where the last slice might (under future
// refactors) be empty — keep this an explicit no-op rather than a
// "INSERT … VALUES " syntax error.
func TestUpsertIndicatorsBatch_EmptyChunk(t *testing.T) {
	t.Parallel()
	store := &PgIntelStore{now: func() time.Time { return time.Unix(1700000000, 0) }}
	exec := newFakeExec()
	n, err := store.upsertIndicatorsBatch(context.Background(), exec, uuid.NewString(), nil, store.now())
	if err != nil {
		t.Fatalf("upsertIndicatorsBatch(nil): %v", err)
	}
	if n != 0 {
		t.Errorf("rows returned = %d; want 0", n)
	}
	if len(exec.calls) != 0 {
		t.Errorf("calls = %d; want 0", len(exec.calls))
	}
}

// TestUpsertIndicatorsBatch_RejectsInvalidFeedID guards the
// validUUID gate on UpsertIndicators (not the internal helper). A
// malformed feed id must short-circuit before any statement is
// built.
func TestUpsertIndicators_RejectsInvalidFeedID(t *testing.T) {
	t.Parallel()
	store := &PgIntelStore{now: func() time.Time { return time.Unix(1700000000, 0) }}
	indicators := []intel.Indicator{mkIndicator(0)}
	_, err := store.UpsertIndicators(context.Background(), "not-a-uuid", indicators)
	if err == nil {
		t.Fatal("UpsertIndicators with invalid feed id: want error; got nil")
	}
}
