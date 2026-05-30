package main

import (
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/worker"
)

// TestPartitionTemplates_UseSinglePercentSpecifiers is the structural
// guardrail against the `%%I` / `%%L` regression Devin Review caught
// on the first push of this file.
//
// Postgres' format() treats `%%` as a literal `%`, so a template
// containing `%%I` renders the literal text `%I` instead of
// identifier-quoting its argument; the resulting DDL is invalid SQL
// and ExecContext fails at runtime. Catching this at unit-test time
// is much cheaper than diagnosing it from a failed production
// reconcile cycle.
//
// The asserts pin the exact specifier shape we want:
//
//   - At least one `%I` and `%L` specifier present (so we know we
//     ARE using format() identifier / literal quoting at all).
//   - NO `%%I` or `%%L` substrings anywhere in any of the three
//     templates (the actual regression).
func TestPartitionTemplates_UseSinglePercentSpecifiers(t *testing.T) {
	cases := []struct {
		name     string
		tmpl     string
		wantSpec []string
	}{
		{"createPartitionTmpl", createPartitionTmpl, []string{"%I", "%L"}},
		{"detachPartitionTmpl", detachPartitionTmpl, []string{"%I"}},
		{"dropPartitionTmpl", dropPartitionTmpl, []string{"%I"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, spec := range tc.wantSpec {
				if !strings.Contains(tc.tmpl, spec) {
					t.Errorf("%s missing %q specifier; format() would not quote its arguments", tc.name, spec)
				}
			}
			for _, bad := range []string{"%%I", "%%L"} {
				if strings.Contains(tc.tmpl, bad) {
					t.Errorf("%s contains %q — Postgres format() would render it as literal text, breaking DDL execution", tc.name, bad)
				}
			}
		})
	}
}

// TestParsePartitionBound_Canonical pins the canonical
// `FOR VALUES FROM ('lo') TO ('hi')` shape the 0017 migration
// emits. Both bounds are real timestamps with explicit UTC
// offsets — RFC3339 parsing succeeds and neither unbounded
// flag is set. Locks in the parse contract so later changes to
// parsePartitionTimestamp can't silently break the production path.
func TestParsePartitionBound_Canonical(t *testing.T) {
	const expr = "FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00')"
	bound, err := parsePartitionBound(expr)
	if err != nil {
		t.Fatalf("parsePartitionBound: %v", err)
	}
	if bound.LowerUnbounded || bound.UpperUnbounded {
		t.Errorf("unbounded flags = (%v, %v), want (false, false)", bound.LowerUnbounded, bound.UpperUnbounded)
	}
	wantLower := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wantUpper := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if !bound.Lower.Equal(wantLower) {
		t.Errorf("lower = %s, want %s", bound.Lower, wantLower)
	}
	if !bound.Upper.Equal(wantUpper) {
		t.Errorf("upper = %s, want %s", bound.Upper, wantUpper)
	}
}

// TestParsePartitionBound_MinValue covers the historical legacy
// partition that catches "everything before the first managed
// month". The lower bound is MINVALUE, the upper is a real
// timestamp.
func TestParsePartitionBound_MinValue(t *testing.T) {
	const expr = "FOR VALUES FROM (MINVALUE) TO ('2026-01-01 00:00:00+00')"
	bound, err := parsePartitionBound(expr)
	if err != nil {
		t.Fatalf("parsePartitionBound: %v", err)
	}
	if !bound.LowerUnbounded {
		t.Error("LowerUnbounded = false, want true for MINVALUE")
	}
	if bound.UpperUnbounded {
		t.Error("UpperUnbounded = true, want false")
	}
	if !bound.Lower.IsZero() {
		t.Errorf("Lower = %s, want zero (timestamp is undefined for unbounded)", bound.Lower)
	}
	wantUpper := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !bound.Upper.Equal(wantUpper) {
		t.Errorf("Upper = %s, want %s", bound.Upper, wantUpper)
	}
}

// TestParsePartitionBound_MaxValue is the case Devin Review
// flagged: a manually-created partition catching "everything
// from time T onwards" must be flagged as unbounded so the
// retention sweep refuses to drop it (its Upper would otherwise
// be zero, which compares as before any plausible cutoff, which
// would mark it droppable — silent data loss).
func TestParsePartitionBound_MaxValue(t *testing.T) {
	const expr = "FOR VALUES FROM ('2026-12-01 00:00:00+00') TO (MAXVALUE)"
	bound, err := parsePartitionBound(expr)
	if err != nil {
		t.Fatalf("parsePartitionBound: %v", err)
	}
	if bound.LowerUnbounded {
		t.Error("LowerUnbounded = true, want false")
	}
	if !bound.UpperUnbounded {
		t.Error("UpperUnbounded = false, want true for MAXVALUE — partition extends to +∞ and must be treated as legacy")
	}
	if !bound.Upper.IsZero() {
		t.Errorf("Upper = %s, want zero (timestamp is undefined for unbounded)", bound.Upper)
	}
}

// TestParsePartitionBound_BothUnbounded — the (MINVALUE, MAXVALUE)
// shape doesn't appear in production, but a future manual
// partition could carry it. Both unbounded flags must be true.
func TestParsePartitionBound_BothUnbounded(t *testing.T) {
	const expr = "FOR VALUES FROM (MINVALUE) TO (MAXVALUE)"
	bound, err := parsePartitionBound(expr)
	if err != nil {
		t.Fatalf("parsePartitionBound: %v", err)
	}
	if !bound.LowerUnbounded || !bound.UpperUnbounded {
		t.Errorf("(LowerUnbounded, UpperUnbounded) = (%v, %v), want (true, true)", bound.LowerUnbounded, bound.UpperUnbounded)
	}
}

// TestParsePartitionBound_RejectsUnknownShape — LIST / HASH /
// DEFAULT partitions are not supported. The parser must return
// an error (which the ListPartitions caller maps to Legacy=true)
// rather than silently misinterpreting them as RANGE.
func TestParsePartitionBound_RejectsUnknownShape(t *testing.T) {
	cases := []string{
		"FOR VALUES IN ('foo', 'bar')",
		"FOR VALUES WITH (MODULUS 4, REMAINDER 0)",
		"DEFAULT",
		"",
	}
	for _, expr := range cases {
		if _, err := parsePartitionBound(expr); err == nil {
			t.Errorf("parsePartitionBound(%q) accepted unknown shape, want error", expr)
		}
	}
}

// TestPlanCleanupPruners covers the partition-worker / cleanup-worker
// mutex decision tree the cleanup runner uses to pick which parent
// tables to register row-level pruners for. The gate is the live
// partition-runner reference (NOT cfg.Worker.PartitionInterval > 0)
// so an init-failure on the partition runner falls back to row-level
// retention instead of silently dropping all retention for the
// partitioned tables. Devin Review flagged this on PR #46.
//
// Three states the function handles:
//  1. partitionRunner != nil  →  partitioned-table pruners SKIPPED
//     (partition worker is the live retention path). Only
//     communication_histories is registered. PartitionFallback=false.
//  2. partitionRunner == nil AND interval > 0 → init-failure path.
//     All partitioned-table pruners registered as fallback;
//     FallbackReason cites init failure.
//  3. partitionRunner == nil AND interval == 0 → explicit opt-out.
//     All partitioned-table pruners registered; FallbackReason
//     cites operator disable.
func TestPlanCleanupPruners(t *testing.T) {
	parents := partitionedAppendOnlyTables()
	if len(parents) == 0 {
		t.Fatalf("partitionedAppendOnlyTables() returned no parents; the test would be vacuous")
	}

	t.Run("partition runner active skips partitioned pruners", func(t *testing.T) {
		// Use a non-nil zero-value Runner — planCleanupPruners only
		// reads identity (nil vs non-nil), it never calls methods
		// on the runner. Constructing an empty struct is the
		// stable way to express "wired" without pulling NewRunner's
		// dependency chain into a unit test.
		stub := &worker.Runner{}
		plan := planCleanupPruners(stub, 24*time.Hour)
		if plan.PartitionFallback {
			t.Fatalf("PartitionFallback=true when runner is non-nil; want false")
		}
		if plan.FallbackReason != "" {
			t.Errorf("FallbackReason=%q when runner is non-nil; want empty", plan.FallbackReason)
		}
		want := []string{"communication_histories"}
		if !equalStringSlice(plan.Parents, want) {
			t.Errorf("Parents=%v; want %v", plan.Parents, want)
		}
	})

	t.Run("partition runner nil with interval>0 registers fallback pruners", func(t *testing.T) {
		plan := planCleanupPruners(nil, 24*time.Hour)
		if !plan.PartitionFallback {
			t.Fatalf("PartitionFallback=false when runner is nil; want true")
		}
		if !strings.Contains(plan.FallbackReason, "init failed") {
			t.Errorf("FallbackReason=%q; want one citing init failure", plan.FallbackReason)
		}
		// Every partitioned parent must be present in the plan,
		// followed by communication_histories.
		wantParents := make(map[string]struct{}, len(parents))
		for _, p := range parents {
			wantParents[p.Parent] = struct{}{}
		}
		gotPartitioned := plan.Parents[:len(plan.Parents)-1]
		for _, got := range gotPartitioned {
			if _, ok := wantParents[got]; !ok {
				t.Errorf("Parents includes unexpected %q", got)
			}
			delete(wantParents, got)
		}
		if len(wantParents) > 0 {
			t.Errorf("Parents missing partitioned parents: %v", wantParents)
		}
		if got := plan.Parents[len(plan.Parents)-1]; got != "communication_histories" {
			t.Errorf("last parent=%q; want %q", got, "communication_histories")
		}
	})

	t.Run("partition runner nil with interval==0 cites operator disable", func(t *testing.T) {
		plan := planCleanupPruners(nil, 0)
		if !plan.PartitionFallback {
			t.Fatalf("PartitionFallback=false when interval is 0; want true")
		}
		if !strings.Contains(plan.FallbackReason, "disabled") {
			t.Errorf("FallbackReason=%q; want one citing operator disable", plan.FallbackReason)
		}
		// Same parent set as the init-failure path.
		if len(plan.Parents) != len(parents)+1 {
			t.Errorf("Parents len=%d; want %d", len(plan.Parents), len(parents)+1)
		}
	})
}

// equalStringSlice is a tiny helper to keep the test body terse. We
// use slices.Equal where available, but the project pins Go 1.25.0
// and the helper makes the test resilient to a downgrade of the
// minimum supported version.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
