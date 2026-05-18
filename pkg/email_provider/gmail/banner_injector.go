package gmail

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BannerInjector implements action.BannerInjector against the Gmail
// REST API.
//
// Gmail's `users.messages.modify` endpoint only mutates labels and
// flags — the message body itself is immutable. To inject an inline
// security banner we therefore follow the well-documented
// "import + trash" shadow-copy pattern used by Google's own add-on
// SDK and by the nges-ingestion-svc:
//
//  1. GET /users/{email}/messages/{id}?format=raw — pulls the original
//     RFC-2822 message base64url-encoded.
//  2. Decode and parse the MIME tree; locate the text/html body
//     (or text/plain if no HTML part exists) and prepend the banner
//     HTML before <body> (or at the top of the part when no body tag
//     is present).
//  3. POST /users/{email}/messages/import with the modified raw,
//     threadId set to the original thread so the message stays in
//     the same conversation, and internalDateSource=dateHeader so
//     Gmail preserves the receive timestamp.
//  4. POST /users/{email}/messages/{id}/trash to remove the original.
//
// The result is a shadow copy of the original message with the banner
// already embedded — the user sees the security warning the next time
// they open the conversation. The trash step is deliberately the last
// operation so a transient failure mid-flow leaves the original
// reachable rather than orphaned.
type BannerInjector struct {
	baseURL string
	http    *http.Client
	tokens  TokenSource
}

// BannerInjectorConfig wires BannerInjector.
type BannerInjectorConfig struct {
	BaseURL     string
	HTTPClient  *http.Client
	TokenSource TokenSource
}

// NewBannerInjector constructs a Gmail BannerInjector. TokenSource is
// required; BaseURL and HTTPClient default to the public endpoint and
// a 30s timeout client respectively.
func NewBannerInjector(cfg BannerInjectorConfig) (*BannerInjector, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("gmail: banner injector token source is required")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://gmail.googleapis.com"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &BannerInjector{baseURL: base, http: client, tokens: cfg.TokenSource}, nil
}

// InjectBanner shadow-copies the message with the supplied HTML
// banner spliced into the rendered body. Validates the request,
// fetches the raw RFC-2822, mutates the MIME tree, imports the
// modified copy under the same thread, then trashes the original.
func (b *BannerInjector) InjectBanner(ctx context.Context, req action.BannerInjectRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if req.Email == "" {
		return errors.New("gmail: banner injector requires email")
	}

	raw, threadID, err := b.fetchRaw(ctx, req.Email, req.MessageID)
	if err != nil {
		return fmt.Errorf("gmail: fetch raw: %w", err)
	}

	modified, mutated, err := injectBannerIntoRFC822(raw, req.HTML)
	if err != nil {
		return fmt.Errorf("gmail: inject banner into rfc822: %w", err)
	}
	if !mutated {
		// No HTML / text part found — fall through with the
		// original raw. The caller still gets a successful import
		// + trash, so the audit chain remains consistent, but the
		// user sees no banner. Logging this is the caller's job.
		modified = raw
	}

	if err := b.importMessage(ctx, req.Email, modified, threadID); err != nil {
		return fmt.Errorf("gmail: import shadow copy: %w", err)
	}
	if err := b.trashMessage(ctx, req.Email, req.MessageID); err != nil {
		// The shadow copy is already in the inbox. A trash failure
		// is best-effort: log + return so the caller can retry, but
		// the user already sees the banner. The label applier will
		// catch a stale original via its own monotonicity logic.
		return fmt.Errorf("gmail: trash original: %w", err)
	}
	return nil
}

// gmailGetMessageResponse covers the `?format=raw` reply, which
// returns the base64url-encoded RFC2822 in the `raw` field along
// with the threadId we want to preserve on import.
type gmailGetMessageResponse struct {
	ID       string `json:"id"`
	ThreadID string `json:"threadId"`
	Raw      string `json:"raw"`
}

// fetchRaw issues the GET /messages/{id}?format=raw call and
// base64url-decodes the body. The returned []byte is the raw RFC2822.
func (b *BannerInjector) fetchRaw(ctx context.Context, email, messageID string) ([]byte, string, error) {
	endpoint := fmt.Sprintf("%s/gmail/v1/users/%s/messages/%s?format=raw",
		b.baseURL, url.PathEscape(email), url.PathEscape(messageID))
	var resp gmailGetMessageResponse
	if err := b.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, "", err
	}
	if resp.Raw == "" {
		return nil, resp.ThreadID, errors.New("empty raw payload")
	}
	raw, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(resp.Raw)
	if err != nil {
		// Gmail accepts both padded and unpadded base64url; try the
		// padded variant before giving up.
		raw, err = base64.URLEncoding.DecodeString(resp.Raw)
		if err != nil {
			return nil, resp.ThreadID, fmt.Errorf("decode raw: %w", err)
		}
	}
	return raw, resp.ThreadID, nil
}

// importMessage POSTs the modified RFC2822 to
// users.messages.import. internalDateSource=dateHeader preserves the
// original receive timestamp; threadId keeps the message in the same
// conversation.
func (b *BannerInjector) importMessage(ctx context.Context, email string, raw []byte, threadID string) error {
	endpoint := fmt.Sprintf("%s/gmail/v1/users/%s/messages/import?internalDateSource=dateHeader",
		b.baseURL, url.PathEscape(email))
	body := struct {
		Raw      string `json:"raw"`
		ThreadID string `json:"threadId,omitempty"`
	}{
		Raw:      base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(raw),
		ThreadID: threadID,
	}
	return b.do(ctx, http.MethodPost, endpoint, body, nil)
}

// trashMessage POSTs to users.messages.{id}.trash to remove the
// original. The shadow copy already exists by this point, so a
// failure here is recoverable but worth surfacing.
func (b *BannerInjector) trashMessage(ctx context.Context, email, messageID string) error {
	endpoint := fmt.Sprintf("%s/gmail/v1/users/%s/messages/%s/trash",
		b.baseURL, url.PathEscape(email), url.PathEscape(messageID))
	return b.do(ctx, http.MethodPost, endpoint, struct{}{}, nil)
}

// do is a verbatim copy of LabelProvider.do scoped to this file so
// the banner injector remains independent of label provider state.
// Keeping them separate prevents accidental coupling — for instance,
// the label provider may eventually grow per-tenant headers we don't
// want to send on import calls.
func (b *BannerInjector) do(ctx context.Context, method, endpoint string, in, out any) error {
	var bodyReader io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	tok, err := b.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("acquire token: %w", err)
	}
	if tok == "" {
		return errors.New("gmail: empty bearer token")
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := b.http.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8 MiB cap
	if rerr != nil {
		return fmt.Errorf("read body: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return &APIError{StatusCode: resp.StatusCode, Body: string(body), Endpoint: endpoint}
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// injectBannerIntoRFC822 parses raw RFC2822 bytes, splices banner
// HTML into the first text/html part (or text/plain if there's no
// HTML), and returns the re-serialised message. The boolean is true
// when a mutation happened so the caller can decide whether to
// re-import or skip.
//
// The implementation only handles the message shapes we encounter in
// production: simple single-part text/html or text/plain bodies, and
// multipart/alternative or multipart/mixed bodies. Anything more
// exotic (encrypted parts, nested multiparts deeper than two levels)
// is left untouched — the safe outcome there is "user sees no banner"
// rather than "we damage the message".
func injectBannerIntoRFC822(raw, banner []byte) ([]byte, bool, error) {
	// Split header from body at the first blank line. RFC2822
	// allows either CRLF CRLF or LF LF; normalise to CRLF for our
	// re-emit so downstream MIME parsers stay happy.
	sep := bytes.Index(raw, []byte("\r\n\r\n"))
	useCRLF := true
	if sep < 0 {
		sep = bytes.Index(raw, []byte("\n\n"))
		useCRLF = false
		if sep < 0 {
			return nil, false, errors.New("missing header/body separator")
		}
	}
	headerBytes := raw[:sep]
	var bodyStart int
	if useCRLF {
		bodyStart = sep + 4
	} else {
		bodyStart = sep + 2
	}
	body := raw[bodyStart:]

	header, err := parseHeader(headerBytes)
	if err != nil {
		return nil, false, fmt.Errorf("parse header: %w", err)
	}

	contentType := header.Get("Content-Type")
	mediaType, params, _ := mime.ParseMediaType(contentType)
	if mediaType == "" {
		mediaType = "text/plain"
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return raw, false, nil
		}
		newBody, mutated, err := mutateMultipartBody(body, boundary, banner)
		if err != nil {
			return nil, false, err
		}
		if !mutated {
			return raw, false, nil
		}
		return reassembleMessage(headerBytes, newBody, useCRLF), true, nil
	}

	// Single-part bodies. Honour Content-Transfer-Encoding so we
	// decode → mutate → re-encode without corrupting the payload.
	cte := strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding")))
	plain, encErr := decodeBody(body, cte)
	if encErr != nil {
		return raw, false, nil
	}

	mutated, ok := injectIntoTextPart(plain, banner, mediaType)
	if !ok {
		return raw, false, nil
	}
	reEncoded, err := encodeBody(mutated, cte)
	if err != nil {
		return nil, false, fmt.Errorf("re-encode body: %w", err)
	}
	return reassembleMessage(headerBytes, reEncoded, useCRLF), true, nil
}

// mutateMultipartBody walks a multipart body, prepending banner HTML
// to the first text/html part it finds (or text/plain if no HTML
// part). It returns the re-serialised body and a boolean indicating
// whether anything was changed.
func mutateMultipartBody(body []byte, boundary string, banner []byte) ([]byte, bool, error) {
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	type rawPart struct {
		header textproto.MIMEHeader
		body   []byte
	}
	var parts []rawPart
	for {
		p, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("multipart: %w", err)
		}
		data, rerr := io.ReadAll(p)
		if rerr != nil {
			return nil, false, fmt.Errorf("multipart read: %w", rerr)
		}
		parts = append(parts, rawPart{header: cloneHeader(p.Header), body: data})
	}
	if len(parts) == 0 {
		return body, false, nil
	}

	// Prefer the first text/html part; fall back to the first
	// text/plain. We never inject into application/* or image/*.
	htmlIdx, textIdx := -1, -1
	for i, p := range parts {
		mt, _, _ := mime.ParseMediaType(p.header.Get("Content-Type"))
		if mt == "text/html" && htmlIdx == -1 {
			htmlIdx = i
		} else if mt == "text/plain" && textIdx == -1 {
			textIdx = i
		}
	}
	target := htmlIdx
	if target == -1 {
		target = textIdx
	}
	if target == -1 {
		return body, false, nil
	}

	tgt := &parts[target]
	tgtMediaType, _, _ := mime.ParseMediaType(tgt.header.Get("Content-Type"))
	cte := strings.ToLower(strings.TrimSpace(tgt.header.Get("Content-Transfer-Encoding")))
	decoded, err := decodeBody(tgt.body, cte)
	if err != nil {
		return body, false, nil
	}
	mutated, ok := injectIntoTextPart(decoded, banner, tgtMediaType)
	if !ok {
		return body, false, nil
	}
	reEncoded, err := encodeBody(mutated, cte)
	if err != nil {
		return nil, false, fmt.Errorf("re-encode part: %w", err)
	}
	tgt.body = reEncoded

	// Rebuild the multipart body. We use Go's mime/multipart writer
	// so the boundary handling matches what Gmail expects.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, false, fmt.Errorf("set boundary: %w", err)
	}
	for _, p := range parts {
		pw, err := w.CreatePart(p.header)
		if err != nil {
			return nil, false, fmt.Errorf("create part: %w", err)
		}
		if _, err := pw.Write(p.body); err != nil {
			return nil, false, fmt.Errorf("write part: %w", err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, false, fmt.Errorf("close writer: %w", err)
	}
	return buf.Bytes(), true, nil
}

// injectIntoTextPart prepends banner HTML to decoded. For text/html
// parts the banner is placed immediately after the opening <body>
// tag (case-insensitive). When no <body> tag exists the banner is
// prepended to the whole content. For text/plain parts a plain-text
// note is appended so the recipient on a text-only client still sees
// something. Returns the mutated bytes and a boolean indicating
// whether content actually changed.
func injectIntoTextPart(decoded, banner []byte, mediaType string) ([]byte, bool) {
	switch mediaType {
	case "text/html":
		lower := bytes.ToLower(decoded)
		if idx := bytes.Index(lower, []byte("<body")); idx >= 0 {
			// Find the end of the <body> opening tag.
			end := bytes.Index(decoded[idx:], []byte(">"))
			if end < 0 {
				return append(append([]byte{}, banner...), decoded...), true
			}
			insertAt := idx + end + 1
			out := make([]byte, 0, len(decoded)+len(banner))
			out = append(out, decoded[:insertAt]...)
			out = append(out, banner...)
			out = append(out, decoded[insertAt:]...)
			return out, true
		}
		out := make([]byte, 0, len(decoded)+len(banner))
		out = append(out, banner...)
		out = append(out, decoded...)
		return out, true
	case "text/plain":
		// Strip HTML tags for the plain variant so the user does
		// not see raw markup. We treat the banner as opaque HTML
		// and emit a short notice instead. Callers that want full
		// fidelity should ensure the message has a text/html part.
		notice := []byte("[SN360 SECURITY NOTICE]\n\n")
		out := make([]byte, 0, len(notice)+len(decoded))
		out = append(out, notice...)
		out = append(out, decoded...)
		return out, true
	default:
		return decoded, false
	}
}

// reassembleMessage stitches the (untouched) header and (possibly
// modified) body back together using the line-ending style of the
// original input.
func reassembleMessage(header, body []byte, useCRLF bool) []byte {
	sep := []byte("\r\n\r\n")
	if !useCRLF {
		sep = []byte("\n\n")
	}
	out := make([]byte, 0, len(header)+len(sep)+len(body))
	out = append(out, header...)
	out = append(out, sep...)
	out = append(out, body...)
	return out
}

// parseHeader parses RFC822 header bytes into a textproto.MIMEHeader.
// textproto's ReadMIMEHeader expects a trailing blank line, so we
// append CRLF CRLF before parsing.
func parseHeader(b []byte) (textproto.MIMEHeader, error) {
	buf := make([]byte, 0, len(b)+4)
	buf = append(buf, b...)
	if !bytes.HasSuffix(buf, []byte("\n")) {
		buf = append(buf, '\r', '\n')
	}
	buf = append(buf, '\r', '\n')
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(buf)))
	return r.ReadMIMEHeader()
}

// decodeBody reverses the Content-Transfer-Encoding so we can splice
// the banner. Unknown encodings are returned unchanged (and treated
// as 7bit / 8bit).
func decodeBody(b []byte, cte string) ([]byte, error) {
	switch cte {
	case "", "7bit", "8bit", "binary":
		return b, nil
	case "base64":
		raw := bytes.TrimSpace(b)
		dst := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
		n, err := base64.StdEncoding.Decode(dst, raw)
		if err != nil {
			// Some mailers emit base64 without padding; try URL
			// variant as a fallback.
			n, err = base64.RawStdEncoding.Decode(dst, raw)
			if err != nil {
				return nil, fmt.Errorf("base64 decode: %w", err)
			}
		}
		return dst[:n], nil
	case "quoted-printable":
		r := quotedprintable.NewReader(bytes.NewReader(b))
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("quoted-printable decode: %w", err)
		}
		return out, nil
	default:
		return b, nil
	}
}

// cloneHeader returns a deep copy of h.
func cloneHeader(h textproto.MIMEHeader) textproto.MIMEHeader {
	out := make(textproto.MIMEHeader, len(h))
	for k, v := range h {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// encodeBody re-applies the Content-Transfer-Encoding after we
// mutated the body. For unknown encodings we emit the raw bytes,
// matching decodeBody's pass-through behaviour.
func encodeBody(b []byte, cte string) ([]byte, error) {
	switch cte {
	case "", "7bit", "8bit", "binary":
		return b, nil
	case "base64":
		dst := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
		base64.StdEncoding.Encode(dst, b)
		return dst, nil
	case "quoted-printable":
		var buf bytes.Buffer
		w := quotedprintable.NewWriter(&buf)
		if _, err := w.Write(b); err != nil {
			return nil, fmt.Errorf("quoted-printable write: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("quoted-printable close: %w", err)
		}
		return buf.Bytes(), nil
	default:
		return b, nil
	}
}
