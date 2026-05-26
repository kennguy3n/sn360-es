package fastmail

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// rewrittenHTMLContentType is the Content-Type header value the
// rewriter applies when it has just replaced a non-HTML body with
// HTML. Without this, JMAP receivers re-import the message keeping
// the source Content-Type (e.g. text/plain), and mail clients then
// render the HTML as literal tags. Matches the value spliceBanner
// already uses for the analogous "escape plain-text into HTML" path
// in banner_injector.go.
const rewrittenHTMLContentType = "text/html; charset=utf-8"

// defaultBodyCacheMaxEntries bounds the per-process Fastmail body
// cache to prevent unbounded growth when callers invoke FetchBody
// without a paired WriteBody / EvictCache. The URLRewriteService
// path always calls EvictCache after FetchBody, so this bound is
// defensive against future callers (or buggy ones) that don't.
// Each entry holds the raw RFC822 bytes + two small bool maps; at
// 256 entries the worst-case memory footprint is roughly
// 256 × average_message_size + tracker overhead, which keeps the
// cache as scratch-space rather than a long-lived structure.
const defaultBodyCacheMaxEntries = 256

// BodyRewriter implements action.BodyRewriter for Fastmail.
//
// JMAP Email bodies are immutable, so WriteBody re-uses the same
// upload/import/destroy dance the BannerInjector relies on, except
// the modifier operates on the full HTML body string instead of an
// inserted banner snippet.
//
// FetchBody is straightforward: Email/get with fetchHTMLBodyValues
// returns the assembled HTML.
//
// The internal cache is a bounded LRU: at most maxEntries entries
// are retained, and on overflow the least-recently-used entry is
// evicted. This makes the rewriter safe to use from callers that
// invoke FetchBody without always pairing it with WriteBody or
// EvictCache — the cache cannot grow without bound regardless of
// caller discipline.
type BodyRewriter struct {
	inj *BannerInjector

	mu sync.Mutex
	// cached maps cacheKey → list element holding the cachedBody.
	// The list orders entries from front (most-recently-used) to
	// back (least-recently-used). LookupReference / insertion both
	// move the entry to the front.
	cached map[string]*list.Element
	order  *list.List
	// maxEntries is the hard upper bound on cache size. Set via
	// NewBodyRewriter / NewBodyRewriterWithCacheBound.
	maxEntries int
}

type cachedBody struct {
	key        string
	raw        []byte
	mailboxIDs map[string]bool
	keywords   map[string]bool
}

// NewBodyRewriter constructs a Fastmail BodyRewriter from an
// existing BannerInjector. The injector provides the shared client +
// upload/import plumbing. The internal cache is bounded to
// defaultBodyCacheMaxEntries entries with LRU eviction.
func NewBodyRewriter(inj *BannerInjector) (*BodyRewriter, error) {
	return NewBodyRewriterWithCacheBound(inj, defaultBodyCacheMaxEntries)
}

// NewBodyRewriterWithCacheBound constructs a BodyRewriter with an
// explicit upper bound on the internal cache. maxEntries <= 0 falls
// back to defaultBodyCacheMaxEntries. Exposed for tests and for
// operators that want to tune the bound for unusually large or
// small deployments.
func NewBodyRewriterWithCacheBound(inj *BannerInjector, maxEntries int) (*BodyRewriter, error) {
	if inj == nil {
		return nil, errors.New("fastmail: body rewriter requires a non-nil banner injector")
	}
	if maxEntries <= 0 {
		maxEntries = defaultBodyCacheMaxEntries
	}
	return &BodyRewriter{
		inj:        inj,
		cached:     make(map[string]*list.Element, maxEntries),
		order:      list.New(),
		maxEntries: maxEntries,
	}, nil
}

// FetchBody returns the HTML body of the given message. Plain-text
// bodies are returned as-is when no HTML part exists.
func (r *BodyRewriter) FetchBody(ctx context.Context, email, messageID string) (string, error) {
	if messageID == "" {
		return "", errors.New("fastmail: message_id required")
	}
	raw, mailboxIDs, keywords, err := r.inj.fetchRaw(ctx, messageID)
	if err != nil {
		return "", fmt.Errorf("fastmail body_rewriter: %w", err)
	}
	r.cacheInsert(cacheKey(email, messageID), raw, mailboxIDs, keywords)

	html, _ := extractHTMLBody(raw)
	return html, nil
}

// cacheInsert promotes / inserts the entry while enforcing the
// LRU bound.
func (r *BodyRewriter) cacheInsert(key string, raw []byte, mailboxIDs, keywords map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if el, ok := r.cached[key]; ok {
		el.Value = &cachedBody{key: key, raw: raw, mailboxIDs: mailboxIDs, keywords: keywords}
		r.order.MoveToFront(el)
		return
	}
	for r.order.Len() >= r.maxEntries {
		oldest := r.order.Back()
		if oldest == nil {
			break
		}
		if cb, ok := oldest.Value.(*cachedBody); ok {
			delete(r.cached, cb.key)
		}
		r.order.Remove(oldest)
	}
	el := r.order.PushFront(&cachedBody{key: key, raw: raw, mailboxIDs: mailboxIDs, keywords: keywords})
	r.cached[key] = el
}

// cacheLookup returns the cachedBody for key when present and marks
// it as most-recently-used.
func (r *BodyRewriter) cacheLookup(key string) (cachedBody, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	el, ok := r.cached[key]
	if !ok {
		return cachedBody{}, false
	}
	r.order.MoveToFront(el)
	cb, _ := el.Value.(*cachedBody)
	return *cb, true
}

// cacheLen reports the current cache size. Used by tests; safe for
// concurrent callers.
func (r *BodyRewriter) cacheLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.order.Len()
}

// WriteBody swaps the HTML payload using the same upload/import/destroy
// dance the BannerInjector uses. The new message has a new JMAP id;
// SN360-ES does not depend on id stability across mutations.
func (r *BodyRewriter) WriteBody(ctx context.Context, email, messageID, htmlBody string) error {
	if messageID == "" {
		return errors.New("fastmail: message_id required")
	}
	cached, ok := r.cacheLookup(cacheKey(email, messageID))
	if !ok {
		// Cold path: fetch the raw body. This handles WriteBody
		// invocations that were not preceded by FetchBody (e.g.
		// the quarantine restore flow that knows the new body
		// upfront).
		raw, mailboxIDs, keywords, err := r.inj.fetchRaw(ctx, messageID)
		if err != nil {
			return fmt.Errorf("fastmail body_rewriter: cold fetch: %w", err)
		}
		cached = cachedBody{raw: raw, mailboxIDs: mailboxIDs, keywords: keywords}
	}
	mutated, err := replaceHTMLBody(cached.raw, []byte(htmlBody))
	if err != nil {
		return fmt.Errorf("fastmail body_rewriter: replace: %w", err)
	}
	blobID, err := r.inj.upload(ctx, mutated)
	if err != nil {
		return fmt.Errorf("fastmail body_rewriter: upload: %w", err)
	}
	newID, err := r.inj.importBlob(ctx, blobID, cached.mailboxIDs, cached.keywords)
	if err != nil {
		return fmt.Errorf("fastmail body_rewriter: import: %w", err)
	}
	if newID == "" {
		return errors.New("fastmail body_rewriter: import returned no id")
	}
	if err := r.inj.destroy(ctx, messageID); err != nil {
		return fmt.Errorf("fastmail body_rewriter: destroy: %w", err)
	}
	r.EvictCache(email, messageID)
	return nil
}

// EvictCache implements action.BodyRewriterCacheCleaner. Release the
// cached raw RFC822 bytes when WriteBody will not be called.
func (r *BodyRewriter) EvictCache(email, messageID string) {
	key := cacheKey(email, messageID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if el, ok := r.cached[key]; ok {
		r.order.Remove(el)
		delete(r.cached, key)
	}
}

func cacheKey(email, messageID string) string {
	return strings.ToLower(email) + "|" + messageID
}

// extractHTMLBody pulls the first text/html part out of an RFC822
// message. Returns the empty string when no HTML part exists.
func extractHTMLBody(raw []byte) (string, error) {
	// Re-use the multipart walk from spliceBanner by passing an
	// empty banner — the returned bytes contain the HTML part body
	// unchanged. For simplicity we duplicate a small helper rather
	// than thread a "noop banner" through the splicer.
	html, ok := findFirstHTMLPart(raw)
	if !ok {
		return "", nil
	}
	return html, nil
}

// findFirstHTMLPart returns the text/html body of the first matching
// MIME part. The function auto-detects the message's line-ending
// style (CRLF per RFC 5322, or LF-only which JMAP blobs sometimes
// ship) and uses the same separator for both the top-level header/
// body split and each sub-part's header/body split. Content-Transfer-
// Encoding is currently pass-through (Fastmail messages are typically
// 7bit or quoted-printable which render as UTF-8).
func findFirstHTMLPart(raw []byte) (string, bool) {
	header, body, sepStyle, err := splitHeaderBody(raw)
	if err != nil || len(body) == 0 {
		return "", false
	}
	contentType := extractHeaderValue(string(header), "Content-Type")
	if contentType == "" {
		return "", false
	}
	if strings.HasPrefix(strings.ToLower(contentType), "text/html") {
		return string(body), true
	}
	if !strings.HasPrefix(strings.ToLower(contentType), "multipart/") {
		return "", false
	}
	boundary := extractBoundary(contentType)
	if boundary == "" {
		return "", false
	}
	partSep := []byte(sepStyle + sepStyle)
	sep := []byte("--" + boundary)
	parts := bytes.Split(body, sep)
	for _, p := range parts {
		i := bytes.Index(p, partSep)
		if i < 0 {
			continue
		}
		hdr := string(p[:i])
		if !strings.Contains(strings.ToLower(hdr), "text/html") {
			continue
		}
		return string(p[i+len(partSep):]), true
	}
	return "", false
}

// replaceHTMLBody returns a new RFC822 with the first text/html part
// replaced by newHTML. The function auto-detects the message's line-
// ending style (CRLF or LF-only) via splitHeaderBody and re-uses that
// style for both the top-level header/body separator and each sub-
// part's header/body separator. The rebuilt message preserves the
// original line-ending style so LF-only inputs round-trip without
// CRLF contamination.
//
// When the source message is NOT already HTML (no Content-Type,
// text/plain, or any other non-multipart, non-HTML type) the top-
// level Content-Type header is rewritten to text/html so receivers
// render the body rather than displaying raw HTML tags as literal
// text. For multipart messages we only touch the matching text/html
// part's body and leave the outer Content-Type alone, because the
// other parts (text/plain, attachments) remain valid.
func replaceHTMLBody(raw, newHTML []byte) ([]byte, error) {
	header, body, sepStyle, err := splitHeaderBody(raw)
	if err != nil {
		return nil, fmt.Errorf("fastmail: %w", err)
	}
	if len(header) == 0 && len(body) == 0 {
		return nil, errors.New("fastmail: missing header/body separator")
	}
	blank := []byte(sepStyle + sepStyle)
	contentType := extractHeaderValue(string(header), "Content-Type")
	lower := strings.ToLower(contentType)

	switch {
	case contentType == "",
		!strings.HasPrefix(lower, "text/html") && !strings.HasPrefix(lower, "multipart/"):
		// Source body is text/plain (or has no declared type, or
		// some other singlepart type). Replacing the body with
		// HTML requires promoting Content-Type to text/html;
		// without this the JMAP receiver keeps the source type
		// and clients render the HTML as literal text. Mirrors
		// spliceBanner's escape-into-HTML path.
		rewrittenHeader := rewriteHeaderLine(header, "Content-Type", rewrittenHTMLContentType, sepStyle)
		out := make([]byte, 0, len(rewrittenHeader)+len(blank)+len(newHTML))
		out = append(out, rewrittenHeader...)
		out = append(out, blank...)
		out = append(out, newHTML...)
		return out, nil
	case strings.HasPrefix(lower, "text/html"):
		// Already HTML — just swap the body in place.
		out := make([]byte, 0, len(header)+len(blank)+len(newHTML))
		out = append(out, header...)
		out = append(out, blank...)
		out = append(out, newHTML...)
		return out, nil
	}

	// Multipart: walk parts, rebuild the first text/html part.
	boundary := extractBoundary(contentType)
	if boundary == "" {
		return nil, errors.New("fastmail: missing boundary in multipart Content-Type")
	}
	sep := []byte("--" + boundary)
	parts := bytes.Split(body, sep)
	replaced := false
	for i, p := range parts {
		j := bytes.Index(p, blank)
		if j < 0 {
			continue
		}
		hdr := string(p[:j])
		if !strings.Contains(strings.ToLower(hdr), "text/html") {
			continue
		}
		hdrEnd := j + len(blank)
		rebuilt := make([]byte, 0, hdrEnd+len(newHTML))
		rebuilt = append(rebuilt, p[:hdrEnd]...)
		rebuilt = append(rebuilt, newHTML...)
		parts[i] = rebuilt
		replaced = true
		break
	}
	if !replaced {
		return nil, errors.New("fastmail: no text/html part to replace")
	}
	out := make([]byte, 0, len(header)+len(blank)+len(body))
	out = append(out, header...)
	out = append(out, blank...)
	out = append(out, bytes.Join(parts, sep)...)
	return out, nil
}

// extractHeaderValue returns the value of the named header (case-
// insensitive) from a raw RFC 5322 header block, performing header
// unfolding per §2.2.3: lines that begin with whitespace are
// treated as continuations of the preceding header and joined into
// a single logical value with a single-space separator. Returns the
// empty string if the header is not present.
//
// This is the critical correctness layer for Content-Type parsing,
// where the boundary= parameter is commonly placed on a continuation
// line:
//
//	Content-Type: multipart/alternative;
//	 boundary="xx"
//
// A naive "stop at first newline" parse would miss the boundary
// parameter entirely; the unfolded value sees both halves joined.
func extractHeaderValue(headerStr, name string) string {
	nameLower := strings.ToLower(strings.TrimSpace(name))
	lines := splitHeaderLines(headerStr)
	for i, line := range lines {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:colon])) != nameLower {
			continue
		}
		value := strings.TrimSpace(line[colon+1:])
		for j := i + 1; j < len(lines); j++ {
			next := lines[j]
			if next == "" {
				break
			}
			if next[0] != ' ' && next[0] != '\t' {
				break
			}
			value += " " + strings.TrimSpace(next)
		}
		return value
	}
	return ""
}

// splitHeaderLines splits a header block on \n, stripping a trailing
// \r from each line so the returned slice is line-ending-agnostic
// (CRLF or LF). Empty trailing line is preserved as "" so callers can
// terminate folded-header look-ahead at the header/body boundary.
func splitHeaderLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			end := i
			if end > start && s[end-1] == '\r' {
				end--
			}
			out = append(out, s[start:end])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// Compile-time interface checks.
var (
	_ action.BodyRewriter             = (*BodyRewriter)(nil)
	_ action.BodyRewriterCacheCleaner = (*BodyRewriter)(nil)
)
