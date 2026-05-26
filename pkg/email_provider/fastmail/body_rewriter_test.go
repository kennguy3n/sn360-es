package fastmail

import (
	"fmt"
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

// TestReplaceHTMLBody_PromotesContentTypeOnPlainTextToHTML pins
// the contract that when replaceHTMLBody is called on a text/plain
// (or no-Content-Type) source message, the rebuilt message's
// Content-Type is rewritten to text/html so receivers render the
// HTML rather than displaying it as literal tags. Without this
// promotion the quarantine stub and release receipt would arrive
// as `<html><body>...` literal text in the user's mailbox.
func TestReplaceHTMLBody_PromotesContentTypeOnPlainTextToHTML(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{
			name: "text/plain source",
			raw: []byte("From: a@example.com\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"\r\n" +
				"original plain body"),
		},
		{
			name: "no Content-Type header",
			raw: []byte("From: a@example.com\r\n" +
				"\r\n" +
				"original plain body"),
		},
		{
			name: "non-html non-multipart (text/markdown)",
			raw: []byte("From: a@example.com\r\n" +
				"Content-Type: text/markdown\r\n" +
				"\r\n" +
				"# markdown"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := replaceHTMLBody(tc.raw, []byte("<html><body>Quarantined by SN360</body></html>"))
			if err != nil {
				t.Fatalf("replaceHTMLBody: %v", err)
			}
			hdr, _, sepStyle, herr := splitHeaderBody(out)
			if herr != nil {
				t.Fatalf("splitHeaderBody on output: %v", herr)
			}
			if sepStyle != "\r\n" {
				t.Errorf("sep style changed unexpectedly: %q", sepStyle)
			}
			ct := extractHeaderValue(string(hdr), "Content-Type")
			if !strings.HasPrefix(strings.ToLower(ct), "text/html") {
				t.Fatalf("Content-Type was not promoted to text/html; got %q", ct)
			}
			if !strings.Contains(ct, "charset=utf-8") {
				t.Errorf("Content-Type should carry charset=utf-8; got %q", ct)
			}
			// And the body must still contain the HTML we asked for.
			if !strings.Contains(string(out), "<body>Quarantined by SN360</body>") {
				t.Errorf("body not replaced:\n%q", out)
			}
		})
	}
}

// TestReplaceHTMLBody_PreservesContentTypeOnHTMLSource asserts that
// when the source is already text/html we leave the Content-Type
// header alone (no double-rewrite, no charset surprises).
func TestReplaceHTMLBody_PreservesContentTypeOnHTMLSource(t *testing.T) {
	raw := []byte("From: a@example.com\r\n" +
		"Content-Type: text/html; charset=iso-8859-1\r\n" +
		"\r\n" +
		"<p>old</p>")
	out, err := replaceHTMLBody(raw, []byte("<p>new</p>"))
	if err != nil {
		t.Fatalf("replaceHTMLBody: %v", err)
	}
	hdr, _, _, _ := splitHeaderBody(out)
	ct := extractHeaderValue(string(hdr), "Content-Type")
	if !strings.Contains(strings.ToLower(ct), "iso-8859-1") {
		t.Errorf("original charset must be preserved on HTML source; got %q", ct)
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

// newRewriterForCacheTests returns a BodyRewriter with a dummy
// BannerInjector. The injector's HTTP client is never invoked by the
// cache tests; we exercise cacheInsert / cacheLookup / EvictCache
// directly.
func newRewriterForCacheTests(t *testing.T, maxEntries int) *BodyRewriter {
	t.Helper()
	c, err := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     "http://127.0.0.1:0",
		AccountID:   "acct-test",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	inj, err := NewBannerInjector(BannerInjectorConfig{Client: c})
	if err != nil {
		t.Fatalf("NewBannerInjector: %v", err)
	}
	r, err := NewBodyRewriterWithCacheBound(inj, maxEntries)
	if err != nil {
		t.Fatalf("NewBodyRewriterWithCacheBound: %v", err)
	}
	return r
}

// TestBodyRewriterCache_EnforcesUpperBound pins the LRU bound: once
// the cache is full, every additional insertion evicts the
// least-recently-used entry, so the cache never exceeds maxEntries
// even under sustained FetchBody-without-EvictCache calls. This is
// the defence against the unbounded-growth concern flagged by Devin
// Review: callers that forget to call EvictCache cannot leak memory.
func TestBodyRewriterCache_EnforcesUpperBound(t *testing.T) {
	const maxEntries = 4
	r := newRewriterForCacheTests(t, maxEntries)

	for i := 0; i < maxEntries*3; i++ {
		key := fmt.Sprintf("user@example.com|msg-%d", i)
		r.cacheInsert(key, []byte("raw"), map[string]bool{"inbox": true}, nil)
	}
	if got := r.cacheLen(); got != maxEntries {
		t.Fatalf("cache exceeded its bound: got %d entries, want %d", got, maxEntries)
	}

	// The first maxEntries-1 insertions should have been evicted by
	// now; only the most-recent maxEntries entries remain.
	for i := maxEntries * 2; i < maxEntries*3; i++ {
		key := fmt.Sprintf("user@example.com|msg-%d", i)
		if _, ok := r.cacheLookup(key); !ok {
			t.Errorf("expected most-recent entry %s to still be cached", key)
		}
	}
	if _, ok := r.cacheLookup("user@example.com|msg-0"); ok {
		t.Error("oldest entry should have been evicted")
	}
}

// TestBodyRewriterCache_LRUOrderingPromotesOnLookup verifies that
// cacheLookup moves the entry to most-recently-used position, so a
// hot key survives even when many cold keys cycle through.
func TestBodyRewriterCache_LRUOrderingPromotesOnLookup(t *testing.T) {
	const maxEntries = 3
	r := newRewriterForCacheTests(t, maxEntries)

	r.cacheInsert("k|hot", []byte("hot"), nil, nil)
	r.cacheInsert("k|cold-1", []byte("c1"), nil, nil)
	r.cacheInsert("k|cold-2", []byte("c2"), nil, nil)

	// Promote "hot" by looking it up.
	if _, ok := r.cacheLookup("k|hot"); !ok {
		t.Fatal("hot lookup should hit")
	}

	// Insert a new entry that triggers eviction; the oldest at this
	// point is cold-1 (cold-2 is newer, hot was just promoted).
	r.cacheInsert("k|new", []byte("n"), nil, nil)

	if _, ok := r.cacheLookup("k|hot"); !ok {
		t.Error("hot entry should have survived; LRU promotion broken")
	}
	if _, ok := r.cacheLookup("k|cold-1"); ok {
		t.Error("cold-1 should have been evicted as the LRU entry")
	}
}

// TestBodyRewriterCache_EvictCacheRemovesEntry verifies EvictCache
// removes the entry from both the map and the LRU list (so a later
// insert does not double-count this slot against the bound).
//
// EvictCache derives its key via cacheKey(email,messageID), so the
// test inserts through the same derived key to make the eviction
// path realistic. After eviction the cache slot is freed and a
// follow-up insert reuses it rather than evicting an unrelated
// entry.
func TestBodyRewriterCache_EvictCacheRemovesEntry(t *testing.T) {
	r := newRewriterForCacheTests(t, 2)
	r.cacheInsert(cacheKey("user@example.com", "msg-x"), []byte("x"), nil, nil)
	r.cacheInsert(cacheKey("user@example.com", "msg-y"), []byte("y"), nil, nil)
	if got := r.cacheLen(); got != 2 {
		t.Fatalf("expected 2 entries pre-evict, got %d", got)
	}

	r.EvictCache("user@example.com", "msg-x")

	if got := r.cacheLen(); got != 1 {
		t.Fatalf("EvictCache did not remove entry: got %d, want 1", got)
	}
	if _, ok := r.cacheLookup(cacheKey("user@example.com", "msg-x")); ok {
		t.Error("evicted entry still reachable")
	}
	// Freed slot must be reusable without evicting msg-y.
	r.cacheInsert(cacheKey("user@example.com", "msg-z"), []byte("z"), nil, nil)
	if _, ok := r.cacheLookup(cacheKey("user@example.com", "msg-y")); !ok {
		t.Error("EvictCache should have freed a slot without disturbing msg-y")
	}
}
