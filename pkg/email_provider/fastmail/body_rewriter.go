package fastmail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BodyRewriter implements action.BodyRewriter for Fastmail.
//
// JMAP Email bodies are immutable, so WriteBody re-uses the same
// upload/import/destroy dance the BannerInjector relies on, except
// the modifier operates on the full HTML body string instead of an
// inserted banner snippet.
//
// FetchBody is straightforward: Email/get with fetchHTMLBodyValues
// returns the assembled HTML.
type BodyRewriter struct {
	inj *BannerInjector

	mu sync.Mutex
	// cached holds the raw RFC822 fetched in FetchBody so WriteBody
	// can swap only the HTML payload without re-downloading the
	// blob. Keyed by (email,messageID).
	cached map[string]cachedBody
}

type cachedBody struct {
	raw        []byte
	mailboxIDs map[string]bool
	keywords   map[string]bool
}

// NewBodyRewriter constructs a Fastmail BodyRewriter from an
// existing BannerInjector. The injector provides the shared client +
// upload/import plumbing.
func NewBodyRewriter(inj *BannerInjector) (*BodyRewriter, error) {
	if inj == nil {
		return nil, errors.New("fastmail: body rewriter requires a non-nil banner injector")
	}
	return &BodyRewriter{inj: inj, cached: make(map[string]cachedBody)}, nil
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
	r.mu.Lock()
	r.cached[cacheKey(email, messageID)] = cachedBody{raw: raw, mailboxIDs: mailboxIDs, keywords: keywords}
	r.mu.Unlock()

	html, _ := extractHTMLBody(raw)
	return html, nil
}

// WriteBody swaps the HTML payload using the same upload/import/destroy
// dance the BannerInjector uses. The new message has a new JMAP id;
// SN360-ES does not depend on id stability across mutations.
func (r *BodyRewriter) WriteBody(ctx context.Context, email, messageID, htmlBody string) error {
	if messageID == "" {
		return errors.New("fastmail: message_id required")
	}
	r.mu.Lock()
	cached, ok := r.cached[cacheKey(email, messageID)]
	r.mu.Unlock()
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
	r.mu.Lock()
	delete(r.cached, cacheKey(email, messageID))
	r.mu.Unlock()
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
// MIME part, with the part's Content-Transfer-Encoding header
// inspected only to decide whether to decode (currently we
// pass-through; Fastmail typically uses 7bit or quoted-printable
// which are renderable as UTF-8).
func findFirstHTMLPart(raw []byte) (string, bool) {
	idx := bytesIndex(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return "", false
	}
	header := string(raw[:idx])
	body := raw[idx+4:]
	ctIdx := indexCI(header, "Content-Type:")
	if ctIdx < 0 {
		return "", false
	}
	rest := header[ctIdx+len("Content-Type:"):]
	newline := indexAnyOf(rest, "\r\n")
	if newline < 0 {
		newline = len(rest)
	}
	contentType := strings.TrimSpace(rest[:newline])
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
	sep := []byte("--" + boundary)
	parts := bytesSplit(body, sep)
	for _, p := range parts {
		i := bytesIndex(p, []byte("\r\n\r\n"))
		if i < 0 {
			continue
		}
		hdr := string(p[:i])
		if !strings.Contains(strings.ToLower(hdr), "text/html") {
			continue
		}
		return string(p[i+4:]), true
	}
	return "", false
}

// replaceHTMLBody returns a new RFC822 with the first text/html part
// replaced by newHTML.
func replaceHTMLBody(raw, newHTML []byte) ([]byte, error) {
	idx := bytesIndex(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, errors.New("fastmail: missing header/body separator")
	}
	header := raw[:idx]
	body := raw[idx+4:]
	headerStr := string(header)
	ctIdx := indexCI(headerStr, "Content-Type:")
	if ctIdx < 0 {
		// Treat as text/plain and replace whole body.
		var out []byte
		out = append(out, header...)
		out = append(out, []byte("\r\n\r\n")...)
		out = append(out, newHTML...)
		return out, nil
	}
	rest := headerStr[ctIdx+len("Content-Type:"):]
	newline := indexAnyOf(rest, "\r\n")
	if newline < 0 {
		newline = len(rest)
	}
	contentType := strings.TrimSpace(rest[:newline])
	if strings.HasPrefix(strings.ToLower(contentType), "text/html") {
		var out []byte
		out = append(out, header...)
		out = append(out, []byte("\r\n\r\n")...)
		out = append(out, newHTML...)
		return out, nil
	}
	if !strings.HasPrefix(strings.ToLower(contentType), "multipart/") {
		var out []byte
		out = append(out, header...)
		out = append(out, []byte("\r\n\r\n")...)
		out = append(out, newHTML...)
		return out, nil
	}
	boundary := extractBoundary(contentType)
	if boundary == "" {
		return nil, errors.New("fastmail: missing boundary in multipart Content-Type")
	}
	sep := []byte("--" + boundary)
	parts := bytesSplit(body, sep)
	replaced := false
	for i, p := range parts {
		j := bytesIndex(p, []byte("\r\n\r\n"))
		if j < 0 {
			continue
		}
		hdr := string(p[:j])
		if !strings.Contains(strings.ToLower(hdr), "text/html") {
			continue
		}
		var rebuilt []byte
		rebuilt = append(rebuilt, p[:j+4]...)
		rebuilt = append(rebuilt, newHTML...)
		parts[i] = rebuilt
		replaced = true
		break
	}
	if !replaced {
		return nil, errors.New("fastmail: no text/html part to replace")
	}
	var out []byte
	out = append(out, header...)
	out = append(out, []byte("\r\n\r\n")...)
	out = append(out, joinParts(parts, sep)...)
	return out, nil
}

// joinParts re-renders the multipart body. Mirrors bytes.Join while
// keeping the package free of external imports.
func joinParts(parts [][]byte, sep []byte) []byte {
	if len(parts) == 0 {
		return nil
	}
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	total += len(sep) * (len(parts) - 1)
	out := make([]byte, 0, total)
	for i, p := range parts {
		if i > 0 {
			out = append(out, sep...)
		}
		out = append(out, p...)
	}
	return out
}

// bytesIndex / bytesSplit / indexCI / indexAnyOf are small helpers
// kept package-local so the package's standard-library footprint
// stays minimal.

func bytesIndex(haystack, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func bytesSplit(s, sep []byte) [][]byte {
	var out [][]byte
	for {
		idx := bytesIndex(s, sep)
		if idx < 0 {
			out = append(out, s)
			return out
		}
		out = append(out, s[:idx])
		s = s[idx+len(sep):]
	}
}

func indexCI(s, sub string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sub))
}

func indexAnyOf(s string, chars string) int {
	return strings.IndexAny(s, chars)
}

// Compile-time interface checks.
var (
	_ action.BodyRewriter             = (*BodyRewriter)(nil)
	_ action.BodyRewriterCacheCleaner = (*BodyRewriter)(nil)
)
