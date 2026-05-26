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

// TestFindFirstHTMLPart_FoldedContentType guards against the previous
// regression where the Content-Type value parse stopped at the first
// newline character, so a folded header per RFC 5322 §2.2.3 such as:
//
//	Content-Type: multipart/alternative;
//	 boundary="xx"
//
// would extract only "multipart/alternative;" and miss the boundary
// parameter on the continuation line. The downstream extractBoundary
// then returns "" and findFirstHTMLPart silently returns ("", false)
// — which causes URL-rewrite and body-rewrite paths to no-op against
// any well-formed multipart message that happens to use line folding.
//
// Folded headers are emitted in the wild by MUAs that wrap long
// Content-Type values for the 78-octet RFC 5322 §2.1.1 line-length
// recommendation; this is not an exotic edge case.
func TestFindFirstHTMLPart_FoldedContentType(t *testing.T) {
	boundary := "BNDFOLD"
	raw := []byte("From: a@example.com\r\n" +
		"Content-Type: multipart/alternative;\r\n" +
		" boundary=\"" + boundary + "\"\r\n" +
		"\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"plain body\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><p>folded</p></body></html>\r\n" +
		"--" + boundary + "--\r\n")
	got, ok := findFirstHTMLPart(raw)
	if !ok {
		t.Fatalf("findFirstHTMLPart returned false for folded Content-Type input — boundary lost")
	}
	if !strings.Contains(got, "<p>folded</p>") {
		t.Errorf("expected HTML part body; got %q", got)
	}
}

// TestReplaceHTMLBody_FoldedContentType is the WriteBody-side guard
// for the same folded-header bug as TestFindFirstHTMLPart_FoldedContentType.
// Pre-fix, replaceHTMLBody returned the error
// "missing boundary in multipart Content-Type" on this exact input;
// post-fix, the unfolded value "multipart/alternative; boundary=\"xx\""
// is parsed correctly and the HTML part is replaced in place.
func TestReplaceHTMLBody_FoldedContentType(t *testing.T) {
	boundary := "BNDFOLD2"
	raw := []byte("From: a@example.com\r\n" +
		"Content-Type: multipart/alternative;\r\n" +
		"\tboundary=\"" + boundary + "\"\r\n" + // continuation with TAB
		"\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"plain body\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><p>old</p></body></html>\r\n" +
		"--" + boundary + "--\r\n")
	out, err := replaceHTMLBody(raw, []byte("<html><body><p>new</p></body></html>"))
	if err != nil {
		t.Fatalf("replaceHTMLBody returned error for folded Content-Type: %v", err)
	}
	if !strings.Contains(string(out), "<p>new</p>") {
		t.Errorf("new HTML body missing:\n%q", out)
	}
	if strings.Contains(string(out), "<p>old</p>") {
		t.Errorf("old HTML body should have been replaced:\n%q", out)
	}
	if !strings.Contains(string(out), "plain body") {
		t.Errorf("plain-text part lost — multipart structure not preserved")
	}
	if !strings.Contains(string(out), "--"+boundary+"--") {
		t.Errorf("closing boundary missing — multipart structure destroyed")
	}
}

// TestExtractHeaderValue_Unfolding pins the folded-header unfolding
// helper's behaviour explicitly. The helper is the load-bearing piece
// of the folded-Content-Type fix above and is used outside the
// integration-level Find/Replace tests, so it deserves its own
// fixture-driven assertion.
func TestExtractHeaderValue_Unfolding(t *testing.T) {
	cases := []struct {
		name, header, want string
	}{
		{
			name:   "simple",
			header: "Content-Type: text/plain\r\n",
			want:   "text/plain",
		},
		{
			name:   "folded with space",
			header: "Content-Type: multipart/alternative;\r\n boundary=\"abc\"\r\n",
			want:   "multipart/alternative; boundary=\"abc\"",
		},
		{
			name:   "folded with tab",
			header: "Content-Type: multipart/alternative;\r\n\tboundary=\"abc\"\r\n",
			want:   "multipart/alternative; boundary=\"abc\"",
		},
		{
			name: "folded three lines",
			header: "Content-Type: multipart/alternative;\r\n" +
				" boundary=\"abc\";\r\n" +
				" charset=utf-8\r\n",
			want: "multipart/alternative; boundary=\"abc\"; charset=utf-8",
		},
		{
			name:   "missing header",
			header: "From: a@example.com\r\n",
			want:   "",
		},
		{
			name:   "case-insensitive name",
			header: "content-TYPE: text/html\r\n",
			want:   "text/html",
		},
		{
			name:   "LF-only folded",
			header: "Content-Type: multipart/alternative;\n boundary=\"abc\"\n",
			want:   "multipart/alternative; boundary=\"abc\"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractHeaderValue(tc.header, "Content-Type")
			if got != tc.want {
				t.Errorf("extractHeaderValue = %q, want %q", got, tc.want)
			}
		})
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
