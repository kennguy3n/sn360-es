package corpus

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// TestGenerateProducesRequestedSize verifies that Generate produces at
// least Config.Size entries (it may produce slightly more so the
// MinPerCategory floor is honoured).
func TestGenerateProducesRequestedSize(t *testing.T) {
	emails := Generate(Config{Seed: 42, Size: 1000})
	if got := len(emails); got < 1000 {
		t.Fatalf("expected at least 1000 emails, got %d", got)
	}
}

// TestGenerateCoversAllCategories asserts every category in
// constant.AllCategories receives at least one labelled threat sample.
func TestGenerateCoversAllCategories(t *testing.T) {
	emails := Generate(Config{Seed: 42, Size: 1000})
	seen := map[constant.Category]int{}
	for _, e := range emails {
		if e.IsThreat {
			seen[e.ExpectedPrimary]++
		}
	}
	for _, c := range constant.AllCategories {
		if seen[c] == 0 {
			t.Errorf("category %s has zero threat samples", c)
		}
	}
}

// TestGenerateCoversAllTiers asserts that every tier value appears in
// the expected-tier distribution. A balanced corpus must exercise
// every tier so the accuracy report's per-tier rollup is meaningful.
func TestGenerateCoversAllTiers(t *testing.T) {
	emails := Generate(Config{Seed: 42, Size: 1000})
	seen := map[constant.Tier]int{}
	for _, e := range emails {
		seen[e.ExpectedTier]++
	}
	for _, want := range []constant.Tier{
		constant.TierBlocked,
		constant.TierHighRisk,
		constant.TierWarning,
		constant.TierCaution,
		constant.TierInformational,
		constant.TierTrusted,
	} {
		if seen[want] == 0 {
			t.Errorf("tier %s has zero samples", want)
		}
	}
}

// TestGenerateDeterministic asserts identical seeds produce identical
// corpora across two runs.
func TestGenerateDeterministic(t *testing.T) {
	a := Generate(Config{Seed: 1234, Size: 100})
	b := Generate(Config{Seed: 1234, Size: 100})
	if len(a) != len(b) {
		t.Fatalf("size mismatch: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Request.MessageID != b[i].Request.MessageID {
			t.Fatalf("message id mismatch at index %d", i)
		}
		if a[i].Request.Subject != b[i].Request.Subject {
			t.Fatalf("subject mismatch at index %d", i)
		}
		if a[i].ExpectedPrimary != b[i].ExpectedPrimary {
			t.Fatalf("expected primary mismatch at index %d", i)
		}
	}
}

// TestGenerateDifferentSeedsDiffer verifies the seed actually drives
// variation.
func TestGenerateDifferentSeedsDiffer(t *testing.T) {
	a := Generate(Config{Seed: 1, Size: 100})
	b := Generate(Config{Seed: 2, Size: 100})
	same := 0
	for i := range a {
		if a[i].Request.MessageID == b[i].Request.MessageID {
			same++
		}
	}
	if same == len(a) {
		t.Fatal("different seeds produced identical corpora")
	}
}

// TestGenerateNonEmptyFields asserts each generated email has the
// minimum set of fields populated.
func TestGenerateNonEmptyFields(t *testing.T) {
	emails := Generate(Config{Seed: 7, Size: 200})
	for i, e := range emails {
		if e.Request.Subject == "" {
			t.Errorf("entry %d has empty subject", i)
		}
		if e.Request.Body == "" {
			t.Errorf("entry %d has empty body", i)
		}
		if e.Request.Sender == "" {
			t.Errorf("entry %d has empty sender", i)
		}
		if e.Request.Recipient == "" {
			t.Errorf("entry %d has empty recipient", i)
		}
		if e.Locale == "" {
			t.Errorf("entry %d has empty locale", i)
		}
		if !strings.Contains(e.Request.Sender, "@") {
			t.Errorf("entry %d sender %q is not an address", i, e.Request.Sender)
		}
	}
}

// TestGenerateMinPerCategoryFloor verifies the min-per-category floor
// is honoured even when totalSize is very small.
func TestGenerateMinPerCategoryFloor(t *testing.T) {
	// With 10 emails total but 16 categories, the floor of 1 should
	// expand the output to at least 16.
	emails := Generate(Config{Seed: 1, Size: 10, MinPerCategory: 1})
	if got := len(emails); got < len(constant.AllCategories) {
		t.Fatalf("expected at least %d emails to satisfy floor, got %d",
			len(constant.AllCategories), got)
	}
}

// TestExportRoundTrip writes the corpus to JSON then loads it back and
// asserts the row count and a couple of fields survive the round
// trip. We don't unmarshal back to LabeledEmail because the export
// schema is intentionally flatter than the in-memory representation.
func TestExportRoundTrip(t *testing.T) {
	emails := Generate(Config{Seed: 11, Size: 50})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, emails); err != nil {
		t.Fatalf("write json: %v", err)
	}
	var rows []ExportRecord
	if err := json.Unmarshal(buf.Bytes(), &rows); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rows) != len(emails) {
		t.Fatalf("round-trip row count mismatch: %d vs %d", len(rows), len(emails))
	}
	if rows[0].MessageID != emails[0].Request.MessageID {
		t.Fatalf("message id mismatch on first row: %q vs %q",
			rows[0].MessageID, emails[0].Request.MessageID)
	}
}

// TestExportCSV smoke-tests the CSV exporter. We use csv.NewReader to
// count records because generated bodies legitimately contain embedded
// newlines (CSV quotes them); a raw split-by-'\n' would count those
// physical lines as separate rows.
func TestExportCSV(t *testing.T) {
	emails := Generate(Config{Seed: 5, Size: 30})
	var buf bytes.Buffer
	if err := WriteCSV(&buf, emails); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	r := csv.NewReader(&buf)
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if got := len(rows); got != len(emails)+1 {
		t.Fatalf("expected %d csv records (1 header + %d rows), got %d",
			len(emails)+1, len(emails), got)
	}
	if rows[0][0] != "test_id" {
		t.Fatalf("csv header missing leading column: %v", rows[0])
	}
}

// TestCategoryAndTierCounts smoke-tests the counting helpers.
func TestCategoryAndTierCounts(t *testing.T) {
	emails := Generate(Config{Seed: 9, Size: 200})
	cats := CategoryCounts(emails)
	if len(cats) == 0 {
		t.Fatal("CategoryCounts returned empty")
	}
	total := 0
	for _, c := range cats {
		total += c.Count
	}
	if total != len(emails) {
		t.Fatalf("category counts sum to %d, expected %d", total, len(emails))
	}
	tiers := TierCounts(emails)
	if len(tiers) == 0 {
		t.Fatal("TierCounts returned empty")
	}
}
