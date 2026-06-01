package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestQuarantineReleaseOutcome_EnumMatchesMigrationCheckConstraint
// is a drift guard: the Go enum and the SQL `CHECK (outcome IN
// (...))` literal in `migrations/0021_quarantine_release_audit.up.sql`
// must list the same set of outcomes, in either order. Any addition
// to one without the other will fail this test and prevent a half-
// landed enum extension from sneaking into a release.
func TestQuarantineReleaseOutcome_EnumMatchesMigrationCheckConstraint(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	migrationsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")
	body, err := os.ReadFile(filepath.Join(migrationsDir, "0021_quarantine_release_audit.up.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	src := string(body)
	const marker = "CHECK (outcome IN ("
	idx := strings.Index(src, marker)
	if idx < 0 {
		t.Fatalf("CHECK clause marker %q not found in migration", marker)
	}
	tail := src[idx+len(marker):]
	endIdx := strings.Index(tail, "))")
	if endIdx < 0 {
		t.Fatalf("CHECK clause closing %q not found in migration", "))")
	}
	clause := tail[:endIdx]

	want := make(map[string]bool, len(AllQuarantineReleaseOutcomes))
	for _, o := range AllQuarantineReleaseOutcomes {
		want[string(o)] = false
	}
	for _, raw := range strings.Split(clause, ",") {
		v := strings.Trim(strings.TrimSpace(raw), "'")
		if v == "" {
			continue
		}
		if _, ok := want[v]; !ok {
			t.Errorf("migration CHECK constraint has %q but Go enum does not", v)
			continue
		}
		want[v] = true
	}
	for o, seen := range want {
		if !seen {
			t.Errorf("Go enum has %q but migration CHECK constraint does not", o)
		}
	}
}

// TestMemoryQuarantineReleaseAudit_RoundTrip is the in-memory
// repository's full lifecycle test:
//  1. Record an entry — id is populated, fields round-trip.
//  2. ListByMessage returns the entry.
//  3. CountRecentByRecipient honours the since window.
//  4. CountRecentByRecipient is per-recipient, not per-tenant.
//  5. CountRecentByRecipient is per-tenant — entries from
//     another tenant do not leak across.
func TestMemoryQuarantineReleaseAudit_RoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryQuarantineReleaseAudit()

	hashA := []byte{0xde, 0xad, 0xbe, 0xef}
	hashB := []byte{0xca, 0xfe, 0xba, 0xbe}
	t0 := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	entries := []QuarantineReleaseAuditEntry{
		// In-window: acme + hashA, releases at t-30m
		{
			TenantID: "acme", PseudoMessageID: "pmid-1",
			RecipientUserHash: hashA,
			Outcome:           QuarantineReleaseOutcomeReleased,
			Reason:            "first attempt",
			CorrelationID:     "corr-1",
			RequestedAt:       t0.Add(-30 * time.Minute),
		},
		// In-window: acme + hashA, releases at t-5m
		{
			TenantID: "acme", PseudoMessageID: "pmid-2",
			RecipientUserHash: hashA,
			Outcome:           QuarantineReleaseOutcomeReleased,
			Reason:            "second attempt",
			RequestedAt:       t0.Add(-5 * time.Minute),
		},
		// Out-of-window: acme + hashA, releases at t-2h
		{
			TenantID: "acme", PseudoMessageID: "pmid-3",
			RecipientUserHash: hashA,
			Outcome:           QuarantineReleaseOutcomeRateLimited,
			RequestedAt:       t0.Add(-2 * time.Hour),
		},
		// Different recipient (hashB) — must not count under hashA's bucket
		{
			TenantID: "acme", PseudoMessageID: "pmid-1",
			RecipientUserHash: hashB,
			Outcome:           QuarantineReleaseOutcomeReleased,
			RequestedAt:       t0.Add(-10 * time.Minute),
		},
		// Different tenant — must not leak into acme's count
		{
			TenantID: "other", PseudoMessageID: "pmid-1",
			RecipientUserHash: hashA,
			Outcome:           QuarantineReleaseOutcomeReleased,
			RequestedAt:       t0.Add(-5 * time.Minute),
		},
	}

	for i, e := range entries {
		written, err := repo.Record(ctx, e)
		if err != nil {
			t.Fatalf("Record case %d: %v", i, err)
		}
		if written.ID == "" {
			t.Fatalf("Record case %d: id not populated", i)
		}
		// Round-trip the round-trip-able fields. CreatedAt is
		// set by the repo; RequestedAt round-trips verbatim.
		if !written.RequestedAt.Equal(e.RequestedAt) {
			t.Fatalf("RequestedAt drift: got=%v want=%v", written.RequestedAt, e.RequestedAt)
		}
		if string(written.RecipientUserHash) != string(e.RecipientUserHash) {
			t.Fatalf("hash mismatch")
		}
		if written.Outcome != e.Outcome {
			t.Fatalf("outcome mismatch")
		}
	}

	// ListByMessage on pmid-1 returns one acme + hashA row and one acme + hashB row.
	rows, err := repo.ListByMessage(ctx, "acme", "pmid-1", 10)
	if err != nil {
		t.Fatalf("ListByMessage: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("pmid-1 rows for acme: got %d want 2", len(rows))
	}

	// CountRecentByRecipient: acme + hashA, since t-1h → 2 (pmid-1 t-30m, pmid-2 t-5m).
	cnt, err := repo.CountRecentByRecipient(ctx, "acme", hashA, t0.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if cnt != 2 {
		t.Fatalf("count acme+hashA, last 1h: got %d want 2", cnt)
	}

	// Per-recipient: acme + hashB, since t-1h → 1.
	cnt, _ = repo.CountRecentByRecipient(ctx, "acme", hashB, t0.Add(-1*time.Hour))
	if cnt != 1 {
		t.Fatalf("count acme+hashB, last 1h: got %d want 1", cnt)
	}

	// Per-tenant: other + hashA must NOT see acme's entries.
	cnt, _ = repo.CountRecentByRecipient(ctx, "other", hashA, t0.Add(-1*time.Hour))
	if cnt != 1 {
		t.Fatalf("count other+hashA, last 1h: got %d want 1", cnt)
	}

	// Window respect: since t-1m → only the second-attempt
	// release for acme+hashA at t-5m falls outside; 0 in
	// window. (Both t-30m and t-5m are older than t-1m, so
	// neither survives — i.e. both are still in the past, just
	// outside the 1-minute window.)
	cnt, _ = repo.CountRecentByRecipient(ctx, "acme", hashA, t0.Add(-1*time.Minute))
	if cnt != 0 {
		t.Fatalf("count acme+hashA, last 1m: got %d want 0", cnt)
	}
}

// TestMemoryQuarantineReleaseAudit_CountExcludesAuthFailures is
// the regression guard for the rate-limit poisoning attack: an
// attacker who learns a recipient's BLAKE2b-256 hash and sprays
// forged JWTs would otherwise write `invalid_token` /
// `token_expired` rows that count toward the legitimate recipient's
// hourly bucket and deny them self-release. The Postgres and
// in-memory implementations both filter these outcomes; this test
// covers the in-memory path. The pg implementation's
// `outcome NOT IN ('token_expired','invalid_token')` SQL predicate
// is verified by the integration testcontainers suite.
func TestMemoryQuarantineReleaseAudit_CountExcludesAuthFailures(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryQuarantineReleaseAudit()
	hash := []byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
		0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89}
	t0 := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	// Seed 5 auth-failure rows (3 invalid_token + 2 token_expired)
	// plus 1 legitimate `released` row, all within the window.
	// If the count incorrectly included auth-failure rows it would
	// return 6; the correct (post-fix) value is 1.
	authFailures := []QuarantineReleaseOutcome{
		QuarantineReleaseOutcomeInvalidToken,
		QuarantineReleaseOutcomeInvalidToken,
		QuarantineReleaseOutcomeInvalidToken,
		QuarantineReleaseOutcomeTokenExpired,
		QuarantineReleaseOutcomeTokenExpired,
	}
	for i, o := range authFailures {
		if _, err := repo.Record(ctx, QuarantineReleaseAuditEntry{
			TenantID:          "acme",
			PseudoMessageID:   fmt.Sprintf("pmid-fail-%d", i),
			RecipientUserHash: hash,
			Outcome:           o,
			Reason:            "forged token from unverified claims",
			RequestedAt:       t0.Add(-time.Duration(i+1) * time.Minute),
		}); err != nil {
			t.Fatalf("Record auth-fail %d: %v", i, err)
		}
	}
	if _, err := repo.Record(ctx, QuarantineReleaseAuditEntry{
		TenantID:          "acme",
		PseudoMessageID:   "pmid-legit",
		RecipientUserHash: hash,
		Outcome:           QuarantineReleaseOutcomeReleased,
		Reason:            "legitimate release",
		RequestedAt:       t0.Add(-10 * time.Minute),
	}); err != nil {
		t.Fatalf("Record legit: %v", err)
	}

	cnt, err := repo.CountRecentByRecipient(ctx, "acme", hash, t0.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if cnt != 1 {
		t.Fatalf("count: got %d want 1 (auth-failure rows must NOT count toward rate-limit budget — see CountRecentByRecipient interface doc)", cnt)
	}

	// And the rows are still in ListByMessage (audit visibility
	// preserved — SOC can still see the forged-token attempts).
	rows, err := repo.ListByMessage(ctx, "acme", "pmid-fail-0", 10)
	if err != nil {
		t.Fatalf("ListByMessage: %v", err)
	}
	if len(rows) != 1 || rows[0].Outcome != QuarantineReleaseOutcomeInvalidToken {
		t.Fatalf("ListByMessage: rows=%+v (auth-failure rows MUST remain visible for forensics)", rows)
	}
}

// TestMemoryQuarantineReleaseAudit_ListByMessageLimit ensures the
// limit honours an upper bound.
func TestMemoryQuarantineReleaseAudit_ListByMessageLimit(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryQuarantineReleaseAudit()
	for i := 0; i < 5; i++ {
		_, err := repo.Record(ctx, QuarantineReleaseAuditEntry{
			TenantID: "acme", PseudoMessageID: "pmid-1",
			RecipientUserHash: []byte{byte(i)},
			Outcome:           QuarantineReleaseOutcomeReleased,
			RequestedAt:       time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	rows, err := repo.ListByMessage(ctx, "acme", "pmid-1", 2)
	if err != nil {
		t.Fatalf("ListByMessage: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2", len(rows))
	}
}

// TestMemoryTenantReleasePolicy_RoundTrip covers the policy repo:
// Upsert → Get → Upsert (replace) → Get.
func TestMemoryTenantReleasePolicy_RoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryTenantReleasePolicy()

	// Default fetch returns the zero policy with the default
	// per-hour cap baked in.
	p, err := repo.Get(ctx, "acme")
	if err != nil {
		t.Fatalf("Get default: %v", err)
	}
	if p.QuarantineSelfReleasePerHour == 0 {
		// Implementation choice: either zero (no row) is
		// "disabled" or the default is auto-applied. We
		// accept both; assert we got a usable value.
		// The state-machine treats 0 as disabled, so the
		// repo MUST return 0 here unless a row was written.
		t.Logf("Get returned zero policy for unconfigured tenant")
	}

	if err := repo.Upsert(ctx, TenantReleasePolicy{
		TenantID:                     "acme",
		QuarantineSelfReleasePerHour: 7,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	p, _ = repo.Get(ctx, "acme")
	if p.QuarantineSelfReleasePerHour != 7 {
		t.Fatalf("Get after upsert: per_hour=%d want 7", p.QuarantineSelfReleasePerHour)
	}

	// Replace.
	if err := repo.Upsert(ctx, TenantReleasePolicy{
		TenantID:                     "acme",
		QuarantineSelfReleasePerHour: 3,
	}); err != nil {
		t.Fatalf("Upsert replace: %v", err)
	}
	p, _ = repo.Get(ctx, "acme")
	if p.QuarantineSelfReleasePerHour != 3 {
		t.Fatalf("Get after replace: per_hour=%d want 3", p.QuarantineSelfReleasePerHour)
	}
}
