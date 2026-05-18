package gmail

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// Ensure GmailBodyRewriter satisfies the interfaces at compile time.
var _ action.BodyRewriter = (*BodyRewriter)(nil)
var _ action.BodyRewriterCacheCleaner = (*BodyRewriter)(nil)

// BodyRewriter implements action.BodyRewriter for Gmail using the
// shadow-copy approach: fetch the raw RFC-2822, extract the HTML
// body, and on write-back re-import with the modified body and trash
// the original.
type BodyRewriter struct {
	inj   *BannerInjector
	cache sync.Map // key: "email\x00messageID" → *fetchState
}

// NewBodyRewriter constructs a Gmail BodyRewriter from an existing
// BannerInjector (reuses its HTTP client and token source).
func NewBodyRewriter(inj *BannerInjector) *BodyRewriter {
	return &BodyRewriter{inj: inj}
}

// fetchState holds the intermediate state between FetchBody and
// WriteBody for a single message. We stash the raw RFC-2822 and
// thread ID so WriteBody can re-import without a second API call.
type fetchState struct {
	raw      []byte
	threadID string
	storedAt time.Time
}

func cacheKey(email, messageID string) string {
	return email + "\x00" + messageID
}

// FetchBody retrieves the message's HTML body by fetching the raw
// RFC-2822 and extracting the text/html MIME part. The raw bytes and
// thread ID are cached so WriteBody can reuse them.
func (g *BodyRewriter) FetchBody(ctx context.Context, email, messageID string) (string, error) {
	raw, threadID, err := g.inj.fetchRaw(ctx, email, messageID)
	if err != nil {
		return "", fmt.Errorf("gmail body_rewriter: fetch raw: %w", err)
	}
	g.cache.Store(cacheKey(email, messageID), &fetchState{
		raw:      raw,
		threadID: threadID,
		storedAt: time.Now(),
	})
	g.evictStale()
	html := extractHTMLFromRFC822(raw)
	return html, nil
}

// EvictCache removes the cached fetch state for a message. Callers
// should call this when WriteBody will not be called (e.g., no URLs
// to rewrite) to prevent cache leaks.
func (g *BodyRewriter) EvictCache(email, messageID string) {
	g.cache.Delete(cacheKey(email, messageID))
}

// evictStale removes cache entries older than 5 minutes. This handles
// the case where FetchBody is called but WriteBody never follows.
func (g *BodyRewriter) evictStale() {
	cutoff := time.Now().Add(-5 * time.Minute)
	g.cache.Range(func(key, value any) bool {
		st := value.(*fetchState)
		if st.storedAt.Before(cutoff) {
			g.cache.Delete(key)
		}
		return true
	})
}

// WriteBody re-imports the message with the modified HTML body using
// Gmail's shadow-copy approach. If FetchBody was called first, the
// cached raw bytes are reused to avoid a second API call.
func (g *BodyRewriter) WriteBody(ctx context.Context, email, messageID, htmlBody string) error {
	key := cacheKey(email, messageID)
	var raw []byte
	var threadID string

	if v, ok := g.cache.LoadAndDelete(key); ok {
		st := v.(*fetchState)
		raw = st.raw
		threadID = st.threadID
	} else {
		var err error
		raw, threadID, err = g.inj.fetchRaw(ctx, email, messageID)
		if err != nil {
			return fmt.Errorf("gmail body_rewriter: fetch raw for write: %w", err)
		}
	}

	modified, mutated := replaceHTMLInRFC822(raw, htmlBody)
	if !mutated {
		// No HTML part found or replacement unchanged — skip the
		// import+trash cycle to avoid wasting API quota and
		// changing the message's internal Gmail ID.
		return nil
	}

	if err := g.inj.importMessage(ctx, email, modified, threadID); err != nil {
		return fmt.Errorf("gmail body_rewriter: import: %w", err)
	}
	if err := g.inj.trashMessage(ctx, email, messageID); err != nil {
		return fmt.Errorf("gmail body_rewriter: trash original: %w", err)
	}
	return nil
}

// extractHTMLFromRFC822 is a lightweight extraction of the first
// text/html part from an RFC-2822 message. It handles base64 and
// quoted-printable Content-Transfer-Encoding. For messages with no
// HTML part it returns "".
func extractHTMLFromRFC822(raw []byte) string {
	s := string(raw)
	// Find the boundary between headers and body.
	idx := strings.Index(s, "\r\n\r\n")
	if idx < 0 {
		idx = strings.Index(s, "\n\n")
	}
	if idx < 0 {
		return ""
	}
	body := s[idx:]

	// Look for an HTML content type marker.
	htmlStart := strings.Index(strings.ToLower(body), "content-type: text/html")
	if htmlStart < 0 {
		// Single-part HTML — check headers.
		headerBlock := s[:idx]
		if strings.Contains(strings.ToLower(headerBlock), "content-type: text/html") {
			bodyStart := idx + 4
			if strings.HasPrefix(s[idx:], "\n\n") {
				bodyStart = idx + 2
			}
			cte := detectCTE(headerBlock)
			return decodeCTE(s[bodyStart:], cte)
		}
		return ""
	}

	// Skip past the part headers to the body.
	partHeaders := body[htmlStart:]
	bodyIdx := strings.Index(partHeaders, "\r\n\r\n")
	if bodyIdx < 0 {
		bodyIdx = strings.Index(partHeaders, "\n\n")
	}
	if bodyIdx < 0 {
		return ""
	}

	headerSection := partHeaders[:bodyIdx]
	content := partHeaders[bodyIdx+4:]
	if strings.HasPrefix(partHeaders[bodyIdx:], "\n\n") {
		content = partHeaders[bodyIdx+2:]
	}

	// Truncate at the next MIME boundary.
	if bIdx := strings.Index(content, "\r\n--"); bIdx >= 0 {
		content = content[:bIdx]
	} else if bIdx := strings.Index(content, "\n--"); bIdx >= 0 {
		content = content[:bIdx]
	}

	cte := detectCTE(headerSection)
	return decodeCTE(strings.TrimSpace(content), cte)
}

// detectCTE extracts the Content-Transfer-Encoding from a header block.
func detectCTE(headers string) string {
	lower := strings.ToLower(headers)
	idx := strings.Index(lower, "content-transfer-encoding:")
	if idx < 0 {
		return "7bit"
	}
	rest := headers[idx+len("content-transfer-encoding:"):]
	end := strings.IndexAny(rest, "\r\n")
	if end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(strings.ToLower(rest))
}

// decodeCTE decodes content based on Content-Transfer-Encoding.
func decodeCTE(content, cte string) string {
	switch cte {
	case "base64":
		cleaned := strings.ReplaceAll(content, "\r\n", "")
		cleaned = strings.ReplaceAll(cleaned, "\n", "")
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cleaned))
		if err != nil {
			return content
		}
		return string(decoded)
	case "quoted-printable":
		r := quotedprintable.NewReader(strings.NewReader(content))
		decoded, err := io.ReadAll(r)
		if err != nil {
			return content
		}
		return string(decoded)
	default:
		return content
	}
}

// replaceHTMLInRFC822 replaces the first text/html part body in the
// raw RFC-2822 with newHTML. Returns the modified raw and true if a
// replacement happened.
func replaceHTMLInRFC822(raw []byte, newHTML string) ([]byte, bool) {
	s := string(raw)

	idx := strings.Index(s, "\r\n\r\n")
	sep := "\r\n\r\n"
	if idx < 0 {
		idx = strings.Index(s, "\n\n")
		sep = "\n\n"
	}
	if idx < 0 {
		return raw, false
	}
	body := s[idx:]

	htmlStart := strings.Index(strings.ToLower(body), "content-type: text/html")
	if htmlStart < 0 {
		// Single-part HTML message.
		headerBlock := s[:idx]
		if strings.Contains(strings.ToLower(headerBlock), "content-type: text/html") {
			bodyStart := idx + len(sep)
			return []byte(s[:bodyStart] + newHTML), true
		}
		return raw, false
	}

	// Multi-part: find the part body boundaries.
	absStart := idx + htmlStart
	partBody := s[absStart:]
	bodyIdx := strings.Index(partBody, "\r\n\r\n")
	bodySep := "\r\n\r\n"
	if bodyIdx < 0 {
		bodyIdx = strings.Index(partBody, "\n\n")
		bodySep = "\n\n"
	}
	if bodyIdx < 0 {
		return raw, false
	}
	contentStart := absStart + bodyIdx + len(bodySep)
	content := s[contentStart:]

	contentEnd := contentStart + len(content)
	if bIdx := strings.Index(content, "\r\n--"); bIdx >= 0 {
		contentEnd = contentStart + bIdx
	} else if bIdx := strings.Index(content, "\n--"); bIdx >= 0 {
		contentEnd = contentStart + bIdx
	}

	result := s[:contentStart] + newHTML + s[contentEnd:]
	return []byte(result), true
}
