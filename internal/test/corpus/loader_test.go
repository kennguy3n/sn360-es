package corpus

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestParse_AcceptsValidFixture(t *testing.T) {
	jsonl := `{"id":"a-001","label":"phish","rfc822":"` + base64.StdEncoding.EncodeToString([]byte("From: a@b\r\n\r\nhi")) + `"}` + "\n"
	got, err := Parse(strings.NewReader(jsonl), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 fixture, got %d", len(got))
	}
	if got[0].ID != "a-001" || got[0].Label != LabelPhish {
		t.Errorf("unexpected fixture: %+v", got[0])
	}
}

func TestParse_RejectsMalformedJSON(t *testing.T) {
	jsonl := `{not json}` + "\n"
	_, err := Parse(strings.NewReader(jsonl), "test")
	if err == nil {
		t.Fatal("expected error on malformed JSON, got nil")
	}
	var loaderErr *LoaderError
	if !errors.As(err, &loaderErr) {
		t.Fatalf("expected *LoaderError, got %T", err)
	}
	if loaderErr.Line != 1 {
		t.Errorf("expected line=1, got %d", loaderErr.Line)
	}
}

func TestParse_RejectsMissingID(t *testing.T) {
	jsonl := `{"label":"phish","rfc822":"` + base64.StdEncoding.EncodeToString([]byte("From: a\r\n\r\nx")) + `"}` + "\n"
	_, err := Parse(strings.NewReader(jsonl), "test")
	if err == nil {
		t.Fatal("expected error on missing id, got nil")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("expected 'id' in error, got %v", err)
	}
}

func TestParse_RejectsMissingLabel(t *testing.T) {
	jsonl := `{"id":"x","rfc822":"` + base64.StdEncoding.EncodeToString([]byte("From: a\r\n\r\nx")) + `"}` + "\n"
	_, err := Parse(strings.NewReader(jsonl), "test")
	if err == nil {
		t.Fatal("expected error on missing label, got nil")
	}
}

func TestParse_RejectsInvalidLabel(t *testing.T) {
	jsonl := `{"id":"x","label":"weird","rfc822":"abc"}` + "\n"
	_, err := Parse(strings.NewReader(jsonl), "test")
	if err == nil {
		t.Fatal("expected error on invalid label, got nil")
	}
	if !strings.Contains(err.Error(), "weird") {
		t.Errorf("expected label name in error: %v", err)
	}
}

func TestParse_RejectsMissingRFC822(t *testing.T) {
	jsonl := `{"id":"x","label":"phish"}` + "\n"
	_, err := Parse(strings.NewReader(jsonl), "test")
	if err == nil {
		t.Fatal("expected error on missing rfc822, got nil")
	}
}

func TestParse_RejectsInvalidExpectedTier(t *testing.T) {
	jsonl := `{"id":"x","label":"phish","expected_tier":"NotATier","rfc822":"abc"}` + "\n"
	_, err := Parse(strings.NewReader(jsonl), "test")
	if err == nil {
		t.Fatal("expected error on invalid tier, got nil")
	}
}

func TestParse_RejectsDuplicateIDs(t *testing.T) {
	body := `{"id":"a","label":"phish","rfc822":"` + base64.StdEncoding.EncodeToString([]byte("From: a@b\r\n\r\nhi")) + `"}` + "\n"
	jsonl := body + body
	_, err := Parse(strings.NewReader(jsonl), "test")
	if err == nil {
		t.Fatal("expected error on duplicate IDs, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected 'duplicate' in error, got %v", err)
	}
}

func TestParse_SkipsBlankAndCommentLines(t *testing.T) {
	jsonl := strings.Join([]string{
		"// header comment",
		"",
		`{"id":"a","label":"phish","rfc822":"` + base64.StdEncoding.EncodeToString([]byte("From: a\r\n\r\nx")) + `"}`,
		"",
		"// trailing comment",
	}, "\n")
	got, err := Parse(strings.NewReader(jsonl), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 fixture, got %d", len(got))
	}
}

func TestParse_EmptyFixtureSetIsAnError(t *testing.T) {
	_, err := Parse(strings.NewReader(""), "test")
	if err == nil {
		t.Fatal("expected error on empty input")
	}
}

func TestBuildRequest_ParsesHeadersAndBody(t *testing.T) {
	raw := "From: \"Alice\" <alice@sender.example>\r\nTo: bob@recipient.example\r\nSubject: Hello\r\n\r\nBody text\r\n"
	fx := Fixture{
		ID:     "test-001",
		Label:  LabelPhish,
		RFC822: base64.StdEncoding.EncodeToString([]byte(raw)),
	}
	req, err := BuildRequest(context.Background(), fx, BuildOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Sender != "alice@sender.example" {
		t.Errorf("Sender: got %q, want alice@sender.example", req.Sender)
	}
	if req.Subject != "Hello" {
		t.Errorf("Subject: got %q, want Hello", req.Subject)
	}
	if !strings.Contains(req.Body, "Body text") {
		t.Errorf("Body lost: %q", req.Body)
	}
	if req.Signals.SenderDomain != "sender.example" {
		t.Errorf("SenderDomain: got %q", req.Signals.SenderDomain)
	}
	if !req.Signals.IsExternal {
		t.Error("expected IsExternal=true when sender domain != recipient domain")
	}
}

func TestBuildRequest_HonoursSignalOverridesInMetadata(t *testing.T) {
	raw := "From: a@a.com\r\nTo: b@a.com\r\nSubject: x\r\n\r\nx\r\n"
	fx := Fixture{
		ID:     "test-002",
		Label:  LabelBenign,
		RFC822: base64.StdEncoding.EncodeToString([]byte(raw)),
		Metadata: map[string]string{
			"signals.is_internal":           "true",
			"signals.relationship_category": "Partner",
		},
	}
	req, err := BuildRequest(context.Background(), fx, BuildOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !req.Signals.IsInternal {
		t.Error("expected IsInternal=true from metadata override")
	}
	if req.Signals.RelationshipCategory.Valid() == false {
		t.Errorf("expected valid RelationshipCategory, got %q", req.Signals.RelationshipCategory)
	}
}

func TestBuildRequest_RejectsInvalidBase64(t *testing.T) {
	fx := Fixture{ID: "x", Label: LabelPhish, RFC822: "not-base64!!"}
	_, err := BuildRequest(context.Background(), fx, BuildOpts{})
	if err == nil {
		t.Fatal("expected error on invalid base64")
	}
}

func TestParse_ReadsFromActualFile(t *testing.T) {
	// Smoke test: ensure Parse handles a multi-line JSONL with
	// realistic content.
	rfcA := "From: a@a.com\r\nTo: b@b.com\r\nSubject: Phish\r\n\r\nVerify your account\r\n"
	rfcB := "From: c@c.com\r\nTo: d@d.com\r\nSubject: Benign\r\n\r\nHello team\r\n"
	jsonl := strings.Join([]string{
		`{"id":"phish-01","label":"phish","rfc822":"` + base64.StdEncoding.EncodeToString([]byte(rfcA)) + `"}`,
		`{"id":"benign-01","label":"benign","rfc822":"` + base64.StdEncoding.EncodeToString([]byte(rfcB)) + `"}`,
	}, "\n")
	got, err := Parse(bytes.NewBufferString(jsonl), "test")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 fixtures, got %d", len(got))
	}
}
