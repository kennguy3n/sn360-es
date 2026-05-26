package fastmail

import (
	"bytes"
	"strings"
	"testing"
)

// TestSpliceBanner_PreservesHeaderOrder verifies that the rebuilt
// message keeps the exact header byte sequence from the input. The
// previous implementation reconstructed headers from the parsed
// mail.Header map, which is iterated in random order — a regression
// here would surface as a flaky failure under -count=N or -shuffle.
func TestSpliceBanner_PreservesHeaderOrder(t *testing.T) {
	// Hand-craft an RFC822 message with a header set that, if
	// reconstructed from a Go map, would almost certainly be reordered
	// across runs. We include three Received headers because their
	// order is semantically significant (RFC 5321 trace ordering).
	raw := []byte("Received: from mx-1.example.com\r\n" +
		"Received: from mx-2.example.com\r\n" +
		"Received: from mx-3.example.com\r\n" +
		"From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: hello\r\n" +
		"Date: Tue, 26 May 2026 10:00:00 +0000\r\n" +
		"Message-ID: <abc@example.com>\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body>hi</body></html>\r\n")
	banner := []byte("<div id=sn360>BANNER</div>")

	// Run the splice 64 times. If map iteration order ever leaks into
	// the output, at least one of these runs will produce a different
	// header section than the first.
	first, err := spliceBanner(raw, banner)
	if err != nil {
		t.Fatalf("spliceBanner: %v", err)
	}
	firstHeader := headerOf(t, first)
	for i := 0; i < 64; i++ {
		out, err := spliceBanner(raw, banner)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if !bytes.Equal(headerOf(t, out), firstHeader) {
			t.Fatalf("iteration %d: header bytes changed:\nfirst=%q\nlater=%q", i, firstHeader, headerOf(t, out))
		}
	}

	// Headers must appear in original order.
	hdrText := string(firstHeader)
	if !strings.Contains(hdrText, "Received: from mx-1") ||
		!strings.Contains(hdrText, "Received: from mx-2") ||
		!strings.Contains(hdrText, "Received: from mx-3") {
		t.Fatalf("missing Received headers:\n%s", hdrText)
	}
	idx1 := strings.Index(hdrText, "mx-1.example.com")
	idx2 := strings.Index(hdrText, "mx-2.example.com")
	idx3 := strings.Index(hdrText, "mx-3.example.com")
	if idx1 >= idx2 || idx2 >= idx3 {
		t.Fatalf("Received headers reordered: idx1=%d idx2=%d idx3=%d\n%s", idx1, idx2, idx3, hdrText)
	}

	// Body must contain the banner, spliced after <body>.
	body := bodyOf(t, first)
	if !bytes.Contains(body, banner) {
		t.Fatalf("banner missing from body: %q", body)
	}
}

// TestSpliceBanner_PromotesPlainTextToHTML ensures that when the
// input is plain text, we rewrite the Content-Type header line
// in-place (instead of appending or duplicating it) and the body is
// wrapped in HTML with the banner prepended.
func TestSpliceBanner_PromotesPlainTextToHTML(t *testing.T) {
	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: hello\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"X-After: keep-me\r\n" +
		"\r\n" +
		"line one\r\nline two\r\n")
	banner := []byte("<div>BANNER</div>")

	out, err := spliceBanner(raw, banner)
	if err != nil {
		t.Fatalf("spliceBanner: %v", err)
	}
	hdr := string(headerOf(t, out))
	// Content-Type should be the rewritten HTML one, exactly once.
	if got := strings.Count(strings.ToLower(hdr), "content-type:"); got != 1 {
		t.Errorf("Content-Type header count = %d, want 1; headers:\n%s", got, hdr)
	}
	if !strings.Contains(hdr, "Content-Type: text/html; charset=utf-8") {
		t.Errorf("Content-Type was not rewritten to text/html:\n%s", hdr)
	}
	// X-After must still be present — it followed Content-Type in the
	// original, so the rewrite must NOT have dropped it.
	if !strings.Contains(hdr, "X-After: keep-me") {
		t.Errorf("X-After header lost during rewrite:\n%s", hdr)
	}
	body := bodyOf(t, out)
	if !bytes.HasPrefix(body, banner) {
		t.Errorf("body should start with banner; got %q", body)
	}
	if !bytes.Contains(body, []byte("line one")) || !bytes.Contains(body, []byte("line two")) {
		t.Errorf("original plain-text content lost; got %q", body)
	}
}

// TestSpliceBanner_PreservesLFOnlyLineEndings ensures the function
// is robust against blobs that use LF-only line endings (real-world
// JMAP downloads sometimes do).
func TestSpliceBanner_PreservesLFOnlyLineEndings(t *testing.T) {
	raw := []byte("From: alice@example.com\n" +
		"Content-Type: text/html; charset=utf-8\n" +
		"\n" +
		"<html><body>hi</body></html>\n")
	banner := []byte("<div>B</div>")
	out, err := spliceBanner(raw, banner)
	if err != nil {
		t.Fatalf("spliceBanner: %v", err)
	}
	if bytes.Contains(out, []byte("\r\n")) {
		t.Errorf("LF-only input should not produce CRLF in output:\n%q", out)
	}
	if !bytes.Contains(out, banner) {
		t.Errorf("banner missing: %q", out)
	}
}

// TestSpliceBanner_LFOnlyMultipartFindsHTMLPart guards against the
// previous regression where injectIntoMultipart hard-coded "\r\n\r\n"
// for the per-part header/body separator. LF-only multipart blobs
// would silently miss the text/html part and the entire body would
// be wrapped as escaped plain text. The fix threads sepStyle through
// to the sub-part search so LF-only multipart messages are handled
// correctly.
func TestSpliceBanner_LFOnlyMultipartFindsHTMLPart(t *testing.T) {
	boundary := "B0UND"
	raw := []byte("From: a@example.com\n" +
		"Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\n" +
		"\n" +
		"--" + boundary + "\n" +
		"Content-Type: text/plain\n" +
		"\n" +
		"hello in plain text\n" +
		"--" + boundary + "\n" +
		"Content-Type: text/html; charset=utf-8\n" +
		"\n" +
		"<html><body><p>hello</p></body></html>\n" +
		"--" + boundary + "--\n")
	banner := []byte("<div id=sn360>BANNER</div>")
	out, err := spliceBanner(raw, banner)
	if err != nil {
		t.Fatalf("spliceBanner: %v", err)
	}
	if bytes.Contains(out, []byte("\r\n")) {
		t.Errorf("LF-only input should not produce CRLF in output:\n%q", out)
	}
	// The banner should appear inside the HTML part, not wrapped
	// around the entire raw multipart body.
	if !bytes.Contains(out, []byte("<div id=sn360>BANNER</div><p>hello</p>")) &&
		!bytes.Contains(out, banner) {
		t.Errorf("banner not injected into HTML part:\n%q", out)
	}
	// Critically: the boundary markers must survive, which is the
	// regression signal — when injectIntoMultipart's per-part search
	// failed it fell through to wrapping the whole body in <pre>,
	// which would HTML-escape the boundary markers as text.
	if !bytes.Contains(out, []byte("--"+boundary+"--")) {
		t.Errorf("multipart structure destroyed (closing boundary missing):\n%q", out)
	}
	if bytes.Contains(out, []byte("&lt;html")) {
		t.Errorf("HTML body should not be escaped — fallback path was incorrectly taken:\n%q", out)
	}
}

// headerOf returns the header bytes of a rebuilt message, stripping
// the trailing separator. It accepts both CRLF and LF.
func headerOf(t *testing.T, msg []byte) []byte {
	t.Helper()
	if i := bytes.Index(msg, []byte("\r\n\r\n")); i >= 0 {
		return msg[:i]
	}
	if i := bytes.Index(msg, []byte("\n\n")); i >= 0 {
		return msg[:i]
	}
	t.Fatalf("no header/body separator in:\n%q", msg)
	return nil
}

func bodyOf(t *testing.T, msg []byte) []byte {
	t.Helper()
	if i := bytes.Index(msg, []byte("\r\n\r\n")); i >= 0 {
		return msg[i+4:]
	}
	if i := bytes.Index(msg, []byte("\n\n")); i >= 0 {
		return msg[i+2:]
	}
	t.Fatalf("no header/body separator in:\n%q", msg)
	return nil
}
