package webhook

import (
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// TestFormatCEF_BlockedVerdict_GoldenShape pins the wire shape of
// a CEF-formatted blocked verdict. The receiver-side parser is
// pipe-delimited so we assert the header structure exactly and the
// extension fields by key.
func TestFormatCEF_BlockedVerdict_GoldenShape(t *testing.T) {
	t.Parallel()
	occ := time.Date(2026, 5, 1, 12, 34, 56, 0, time.UTC)
	ev := &Event{
		EventID:          "evt-1",
		OccurredAt:       occ,
		TenantID:         "tenant-A",
		MessageID:        "msg-1",
		CorrelationID:    "corr-1",
		Score:            87,
		Tier:             constant.TierBlocked,
		Primary:          constant.CategoryLikelyPhishing,
		ReasonCodes:      []string{"phish_pattern", "lookalike_domain"},
		SenderHashHex:    "deadbeef",
		RecipientHashHex: "cafebabe",
	}
	body, err := formatCEF(ev)
	if err != nil {
		t.Fatalf("formatCEF: %v", err)
	}
	header, severity, exts, ok := splitCEFForTest(string(body))
	if !ok {
		t.Fatalf("CEF body not parseable as CEF:0 header + extensions; got %q", body)
	}
	if len(header) != 7 {
		t.Fatalf("CEF header should have 7 |-delimited fields; got %d (%q)", len(header), header)
	}
	if header[0] != "CEF:0" {
		t.Errorf("CEF[0] = %q; want CEF:0", header[0])
	}
	if header[1] != cefVendor {
		t.Errorf("CEF[1] = %q; want %s", header[1], cefVendor)
	}
	if header[2] != cefProduct {
		t.Errorf("CEF[2] = %q; want %s", header[2], cefProduct)
	}
	if header[3] != cefVersion {
		t.Errorf("CEF[3] = %q; want %s", header[3], cefVersion)
	}
	if !strings.HasPrefix(header[4], "email-evaluation.") {
		t.Errorf("CEF signature field should be email-evaluation.<verdict>; got %q", header[4])
	}
	if severity != "10" { // TierBlocked → severity 10 (per cefSeverityForTier)
		t.Errorf("CEF severity for Blocked = %q; want 10", severity)
	}
	// Spot-check the must-have extension keys.
	for _, k := range []string{"externalId=", "act=", "outcome=", "cn1Label=", "cs1Label="} {
		if !strings.Contains(exts, k) {
			t.Errorf("CEF extensions missing %q; got %q", k, exts)
		}
	}
}

// splitCEFForTest is a minimal CEF-v0 splitter that mirrors how a
// real CEF receiver parses the wire format: it walks the bytes
// counting UN-escaped pipes (`|` not preceded by `\`) until it has
// the 7 header fields, then splits the trailing field on its
// first space to separate the severity from the extension
// key=value tail. Returns (headerFields, severity, extensions, ok).
func splitCEFForTest(body string) ([]string, string, string, bool) {
	var fields []string
	var cur strings.Builder
	i := 0
	for i < len(body) && len(fields) < 6 {
		c := body[i]
		switch {
		case c == '\\' && i+1 < len(body) && (body[i+1] == '|' || body[i+1] == '\\'):
			cur.WriteByte(body[i+1])
			i += 2
		case c == '|':
			fields = append(fields, cur.String())
			cur.Reset()
			i++
		default:
			cur.WriteByte(c)
			i++
		}
	}
	if len(fields) != 6 {
		return nil, "", "", false
	}
	tail := body[i:]
	// tail = "<severity> <key=value> ..."
	sev, exts, ok := strings.Cut(tail, " ")
	if !ok {
		// Empty extensions are legal — receiver still accepts.
		fields = append(fields, sev)
		return fields, sev, "", true
	}
	fields = append(fields, sev)
	return fields, sev, exts, true
}

// TestFormatCEF_EscapesPipesInHeader checks the CEF escaping rule
// for header fields. A pipe inside a header field must be
// backslash-escaped; otherwise the receiver mis-parses the columns.
func TestFormatCEF_EscapesPipesInHeader(t *testing.T) {
	t.Parallel()
	// Inject a pipe via CorrelationID which lands in the name
	// only via signature/name — easier to trigger via a verdict
	// override on FinalVerdict.
	ev := &Event{
		EventID:      "evt-pipe",
		OccurredAt:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		TenantID:     "tenant-A",
		MessageID:    "msg-1",
		Tier:         constant.TierBlocked,
		Primary:      constant.CategoryLikelyPhishing,
		FinalVerdict: "x|y", // analyst-override pollution
	}
	body, err := formatCEF(ev)
	if err != nil {
		t.Fatalf("formatCEF: %v", err)
	}
	// The escape must appear in the raw bytes so a downstream
	// CEF receiver counts 7 header fields rather than mis-reading
	// the pipe as a column separator. Verify via the raw body
	// (splitCEFForTest, which models a real receiver, would
	// hide the escape because it un-escapes pipes in its
	// output).
	out := string(body)
	if !strings.Contains(out, `email-evaluation.x\|y`) {
		t.Errorf("Pipe in FinalVerdict not backslash-escaped on the wire; got %q", out)
	}
	// A spec-compliant receiver still parses 7 columns despite the
	// escaped pipe inside the signature field.
	header, _, _, ok := splitCEFForTest(out)
	if !ok || len(header) != 7 {
		t.Fatalf("escaped pipe broke header column count: got %d (%v) from %q", len(header), header, out)
	}
	if header[4] != "email-evaluation.x|y" {
		t.Errorf("post-unescape signature = %q; want email-evaluation.x|y", header[4])
	}
}

// TestFormatCEF_Deterministic guards the receiver's dedup story:
// the same logical event must produce identical bytes so a
// SHA-256 of the body is a stable dedup key.
func TestFormatCEF_Deterministic(t *testing.T) {
	t.Parallel()
	ev := &Event{
		EventID:     "evt-1",
		OccurredAt:  time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		TenantID:    "tenant-A",
		MessageID:   "msg-1",
		Tier:        constant.TierWarning,
		Primary:     constant.CategoryNewsletter,
		ReasonCodes: []string{"a", "b"},
	}
	first, err := formatCEF(ev)
	if err != nil {
		t.Fatalf("formatCEF: %v", err)
	}
	for i := 0; i < 10; i++ {
		next, err := formatCEF(ev)
		if err != nil {
			t.Fatalf("formatCEF: %v", err)
		}
		if string(first) != string(next) {
			t.Fatalf("non-deterministic CEF output:\n%s\nvs\n%s", first, next)
		}
	}
}
