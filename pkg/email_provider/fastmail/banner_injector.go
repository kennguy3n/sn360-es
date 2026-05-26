package fastmail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BannerInjector implements action.BannerInjector for Fastmail.
//
// JMAP Email objects (RFC 8621 §4) are immutable on every property
// except `keywords` and `mailboxIds`; the body cannot be edited via
// Email/set. To inject a banner we follow the JMAP-canonical
// "rewrite" pattern:
//
//  1. Fetch the original Email's raw RFC822 blob via the download URL.
//  2. Splice the banner HTML into the appropriate MIME part.
//  3. Upload the new MIME via the JMAP upload URL → returns a blobId.
//  4. Email/import the blob with the same mailboxIds and keywords.
//  5. Email/set destroy the original.
//
// The new message has a different JMAP id; SN360-ES does not rely on
// id stability across mutations (the next poll cycle will pick up
// the new message and re-evaluate; the banner is idempotent because
// the URL rewrite + tier label classification produces the same
// hash). The provider returns nil on success.
type BannerInjector struct {
	client *Client
}

// BannerInjectorConfig wires BannerInjector.
type BannerInjectorConfig struct {
	Client *Client
}

// NewBannerInjector validates the config and returns a usable
// injector.
func NewBannerInjector(cfg BannerInjectorConfig) (*BannerInjector, error) {
	if cfg.Client == nil {
		return nil, errors.New("fastmail: banner injector requires a Client")
	}
	return &BannerInjector{client: cfg.Client}, nil
}

// InjectBanner performs the upload + import + destroy dance.
func (b *BannerInjector) InjectBanner(ctx context.Context, req action.BannerInjectRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	raw, mailboxIDs, keywords, err := b.fetchRaw(ctx, req.MessageID)
	if err != nil {
		return fmt.Errorf("fastmail: banner fetch raw: %w", err)
	}
	mutated, err := spliceBanner(raw, req.HTML)
	if err != nil {
		return fmt.Errorf("fastmail: splice banner: %w", err)
	}
	blobID, err := b.upload(ctx, mutated)
	if err != nil {
		return fmt.Errorf("fastmail: upload: %w", err)
	}
	newID, err := b.importBlob(ctx, blobID, mailboxIDs, keywords)
	if err != nil {
		return fmt.Errorf("fastmail: import: %w", err)
	}
	if newID == "" {
		return errors.New("fastmail: import returned no new id")
	}
	if err := b.destroy(ctx, req.MessageID); err != nil {
		return fmt.Errorf("fastmail: destroy original: %w", err)
	}
	return nil
}

// fetchRaw reads the message's raw RFC822 blob along with the
// mailbox/keyword set we need to preserve on import.
func (b *BannerInjector) fetchRaw(ctx context.Context, messageID string) ([]byte, map[string]bool, map[string]bool, error) {
	getArgs := map[string]any{
		"accountId":  b.client.accountID,
		"ids":        []string{messageID},
		"properties": []string{"id", "blobId", "mailboxIds", "keywords"},
	}
	resp, err := b.client.Invoke(ctx, "Email/get", getArgs)
	if err != nil {
		return nil, nil, nil, err
	}
	var decoded struct {
		List []struct {
			ID         string          `json:"id"`
			BlobID     string          `json:"blobId"`
			MailboxIDs map[string]bool `json:"mailboxIds"`
			Keywords   map[string]bool `json:"keywords"`
		} `json:"list"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return nil, nil, nil, fmt.Errorf("decode email/get: %w", err)
	}
	if len(decoded.List) == 0 {
		return nil, nil, nil, fmt.Errorf("message %s not found", messageID)
	}
	email := decoded.List[0]
	sess, err := b.client.Session(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	rawURL := buildBlobURL(sess.DownloadURL, b.client.accountID, email.BlobID, "raw.eml")
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	tok, err := b.client.tokens.Token(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+tok)
	httpResp, err := b.client.http.Do(httpReq)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("download: %w", err)
	}
	defer httpResp.Body.Close()
	raw, rerr := io.ReadAll(io.LimitReader(httpResp.Body, 32<<20))
	if rerr != nil {
		return nil, nil, nil, fmt.Errorf("read download: %w", rerr)
	}
	if httpResp.StatusCode/100 != 2 {
		return nil, nil, nil, fmt.Errorf("download %d: %s", httpResp.StatusCode, truncate(string(raw), 200))
	}
	return raw, email.MailboxIDs, email.Keywords, nil
}

// upload posts the modified RFC822 to the JMAP upload URL and
// returns the resulting blobId.
func (b *BannerInjector) upload(ctx context.Context, data []byte) (string, error) {
	sess, err := b.client.Session(ctx)
	if err != nil {
		return "", err
	}
	url := strings.ReplaceAll(sess.UploadURL, "{accountId}", b.client.accountID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	tok, err := b.client.tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "message/rfc822")
	resp, err := b.client.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return "", fmt.Errorf("read upload: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("upload %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var decoded struct {
		BlobID string `json:"blobId"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", fmt.Errorf("decode upload: %w", err)
	}
	if decoded.BlobID == "" {
		return "", errors.New("upload response missing blobId")
	}
	return decoded.BlobID, nil
}

// importBlob calls Email/import on the uploaded blob with the
// original mailboxIds + keywords preserved.
func (b *BannerInjector) importBlob(ctx context.Context, blobID string, mailboxIDs, keywords map[string]bool) (string, error) {
	args := map[string]any{
		"accountId": b.client.accountID,
		"emails": map[string]any{
			"new": map[string]any{
				"blobId":     blobID,
				"mailboxIds": mailboxIDs,
				"keywords":   keywords,
			},
		},
	}
	resp, err := b.client.Invoke(ctx, "Email/import", args)
	if err != nil {
		return "", err
	}
	var decoded struct {
		Created map[string]struct {
			ID string `json:"id"`
		} `json:"created"`
		NotCreated map[string]json.RawMessage `json:"notCreated"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return "", fmt.Errorf("decode email/import: %w", err)
	}
	for k, raw := range decoded.NotCreated {
		return "", fmt.Errorf("import %s failed: %s", k, string(raw))
	}
	created, ok := decoded.Created["new"]
	if !ok {
		return "", errors.New("import response missing created")
	}
	return created.ID, nil
}

// destroy removes the original message via Email/set destroy.
func (b *BannerInjector) destroy(ctx context.Context, id string) error {
	args := map[string]any{
		"accountId": b.client.accountID,
		"destroy":   []string{id},
	}
	resp, err := b.client.Invoke(ctx, "Email/set", args)
	if err != nil {
		return err
	}
	var decoded struct {
		Destroyed    []string                   `json:"destroyed"`
		NotDestroyed map[string]json.RawMessage `json:"notDestroyed"`
	}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return fmt.Errorf("decode email/set destroy: %w", err)
	}
	if len(decoded.NotDestroyed) > 0 {
		for k, raw := range decoded.NotDestroyed {
			return fmt.Errorf("destroy %s failed: %s", k, string(raw))
		}
	}
	return nil
}

// buildBlobURL renders the JMAP download URL template (RFC 8620
// §1.6.1). The template has {accountId}, {blobId}, {type}, {name}
// placeholders.
func buildBlobURL(template, accountID, blobID, name string) string {
	r := strings.NewReplacer(
		"{accountId}", accountID,
		"{blobId}", blobID,
		"{type}", "message/rfc822",
		"{name}", name,
	)
	return r.Replace(template)
}

// spliceBanner inserts the banner HTML into the appropriate MIME part
// of an RFC822 message. The implementation parses the MIME structure
// using net/mail and re-renders the body with the banner prepended.
func spliceBanner(raw, banner []byte) ([]byte, error) {
	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse rfc822: %w", err)
	}
	ct := parsed.Header.Get("Content-Type")
	body, err := io.ReadAll(parsed.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	var mutated []byte
	switch {
	case strings.HasPrefix(strings.ToLower(ct), "multipart/"):
		mutated, err = injectIntoMultipart(parsed.Header, ct, body, banner)
		if err != nil {
			return nil, err
		}
	case strings.Contains(strings.ToLower(ct), "text/html"):
		mutated = []byte(spliceHTMLBanner(string(body), string(banner)))
	default:
		// Plain text or unspecified → wrap in HTML.
		text := htmlEscape(string(body))
		mutated = []byte(string(banner) + "<hr/><pre>" + text + "</pre>")
		parsed.Header["Content-Type"] = []string{"text/html; charset=utf-8"}
	}
	// Re-assemble header + body. We preserve the original headers
	// verbatim (banner injection should not change envelope info).
	var out bytes.Buffer
	for k, vs := range parsed.Header {
		for _, v := range vs {
			fmt.Fprintf(&out, "%s: %s\r\n", k, v)
		}
	}
	out.WriteString("\r\n")
	out.Write(mutated)
	return out.Bytes(), nil
}

// injectIntoMultipart finds the first text/html (or text/plain) sub
// part and inlines the banner. The boundary is extracted from the
// Content-Type header.
func injectIntoMultipart(headers mail.Header, contentType string, body, banner []byte) ([]byte, error) {
	boundary := extractBoundary(contentType)
	if boundary == "" {
		// Fall back: pretend it's plain text.
		text := htmlEscape(string(body))
		return []byte(string(banner) + "<hr/><pre>" + text + "</pre>"), nil
	}
	sep := []byte("--" + boundary)
	parts := bytes.Split(body, sep)
	mutated := false
	for i, part := range parts {
		// Find the first text/html part.
		idx := bytes.Index(part, []byte("\r\n\r\n"))
		if idx < 0 {
			continue
		}
		hdr := string(part[:idx])
		if !strings.Contains(strings.ToLower(hdr), "text/html") {
			continue
		}
		partBody := part[idx+4:]
		spliced := spliceHTMLBanner(string(partBody), string(banner))
		parts[i] = append(part[:idx+4], []byte(spliced)...)
		mutated = true
		break
	}
	if !mutated {
		// No HTML part — fall back to plain wrap above the multipart.
		text := htmlEscape(string(body))
		return []byte(string(banner) + "<hr/><pre>" + text + "</pre>"), nil
	}
	return bytes.Join(parts, sep), nil
}

// extractBoundary parses the boundary parameter out of a multipart
// Content-Type header value.
func extractBoundary(contentType string) string {
	lower := strings.ToLower(contentType)
	idx := strings.Index(lower, "boundary=")
	if idx < 0 {
		return ""
	}
	rest := contentType[idx+len("boundary="):]
	rest = strings.TrimSpace(rest)
	rest = strings.TrimPrefix(rest, "\"")
	end := strings.IndexAny(rest, "\";")
	if end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// spliceHTMLBanner inserts banner after the opening <body> tag (or
// the top of the document if no <body> exists). Case-insensitive.
func spliceHTMLBanner(doc, banner string) string {
	if doc == "" {
		return banner
	}
	lower := strings.ToLower(doc)
	idx := strings.Index(lower, "<body")
	if idx < 0 {
		return banner + doc
	}
	end := strings.Index(doc[idx:], ">")
	if end < 0 {
		return banner + doc
	}
	insertAt := idx + end + 1
	return doc[:insertAt] + banner + doc[insertAt:]
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}

// Compile-time interface check.
var _ action.BannerInjector = (*BannerInjector)(nil)
