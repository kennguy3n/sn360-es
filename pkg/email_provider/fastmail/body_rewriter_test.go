package fastmail

import (
	"strings"
	"testing"
)

// TestFindFirstHTMLPart_LFOnlyMultipart guards against the previous
// regression where findFirstHTMLPart hard-coded "\r\n\r\n" for both
// the top-level header/body split and each sub-part's header/body
// split. LF-only blobs would silently return "", which then caused
// URLRewriteService to skip URL rewriting entirely — leaving
// potentially malicious URLs in place.
func TestFindFirstHTMLPart_LFOnlyMultipart(t *testing.T) {
	boundary := "BNDLF"
	raw := []byte("From: a@example.com\n" +
		"Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\n" +
		"\n" +
		"--" + boundary + "\n" +
		"Content-Type: text/plain\n" +
		"\n" +
		"plain body\n" +
		"--" + boundary + "\n" +
		"Content-Type: text/html; charset=utf-8\n" +
		"\n" +
		"<html><body><p>html body</p></body></html>\n" +
		"--" + boundary + "--\n")
	got, ok := findFirstHTMLPart(raw)
	if !ok {
		t.Fatalf("findFirstHTMLPart returned false for LF-only multipart input")
	}
	if !strings.Contains(got, "<p>html body</p>") {
		t.Errorf("expected HTML part body; got %q", got)
	}
}

// TestFindFirstHTMLPart_LFOnlySinglepart covers the simple text/html
// top-level case with LF endings.
func TestFindFirstHTMLPart_LFOnlySinglepart(t *testing.T) {
	raw := []byte("From: a@example.com\n" +
		"Content-Type: text/html\n" +
		"\n" +
		"<html><body>hi</body></html>")
	got, ok := findFirstHTMLPart(raw)
	if !ok {
		t.Fatalf("findFirstHTMLPart returned false for LF-only singlepart input")
	}
	if !strings.HasPrefix(got, "<html") {
		t.Errorf("expected HTML body; got %q", got)
	}
}

// TestReplaceHTMLBody_LFOnlyMultipart guards against the previous
// regression where replaceHTMLBody hard-coded CRLF for the top-level
// separator AND each sub-part's separator. Two failure modes were
// possible for LF-only blobs: (a) early error "missing header/body
// separator", or (b) returning a corrupted message where the
// reassembled top-level separator was CRLF even though the original
// was LF.
func TestReplaceHTMLBody_LFOnlyMultipart(t *testing.T) {
	boundary := "BNDLF2"
	raw := []byte("From: a@example.com\n" +
		"Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\n" +
		"\n" +
		"--" + boundary + "\n" +
		"Content-Type: text/plain\n" +
		"\n" +
		"plain body\n" +
		"--" + boundary + "\n" +
		"Content-Type: text/html; charset=utf-8\n" +
		"\n" +
		"<html><body><p>old</p></body></html>\n" +
		"--" + boundary + "--\n")
	out, err := replaceHTMLBody(raw, []byte("<html><body><p>new</p></body></html>"))
	if err != nil {
		t.Fatalf("replaceHTMLBody: %v", err)
	}
	if strings.Contains(string(out), "\r\n") {
		t.Errorf("LF-only input must not gain CRLF in output:\n%q", out)
	}
	if !strings.Contains(string(out), "<p>new</p>") {
		t.Errorf("new HTML body missing:\n%q", out)
	}
	if strings.Contains(string(out), "<p>old</p>") {
		t.Errorf("old HTML body should have been replaced:\n%q", out)
	}
	// The plain-text part and the boundary markers must survive
	// intact — a regression that fell through to "treat as text/plain"
	// would discard the multipart structure entirely.
	if !strings.Contains(string(out), "plain body") {
		t.Errorf("plain-text part lost during rewrite:\n%q", out)
	}
	if !strings.Contains(string(out), "--"+boundary+"--") {
		t.Errorf("closing boundary missing — multipart structure destroyed:\n%q", out)
	}
}

// TestReplaceHTMLBody_LFOnlySinglepart covers the simple text/html
// top-level case with LF endings.
func TestReplaceHTMLBody_LFOnlySinglepart(t *testing.T) {
	raw := []byte("From: a@example.com\n" +
		"Content-Type: text/html\n" +
		"\n" +
		"<html><body>old</body></html>")
	out, err := replaceHTMLBody(raw, []byte("<html><body>new</body></html>"))
	if err != nil {
		t.Fatalf("replaceHTMLBody: %v", err)
	}
	if strings.Contains(string(out), "\r\n") {
		t.Errorf("LF-only input must not gain CRLF in output:\n%q", out)
	}
	if !strings.Contains(string(out), "<body>new</body>") {
		t.Errorf("body not replaced:\n%q", out)
	}
}
