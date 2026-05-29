package main

import (
	"strings"
	"testing"
	"time"
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
