package outlook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BannerInjector implements action.BannerInjector against Microsoft
// Graph.
//
// Unlike Gmail, Graph supports direct body mutation. The flow is a
// straightforward GET → splice → PATCH:
//
//  1. GET /v1.0/users/{email}/messages/{id}?$select=id,body
//     returns the current body.contentType and body.content.
//  2. Splice the banner HTML into the body. When the body is "html"
//     we insert immediately after the opening <body> tag (or at the
//     top if there is no <body> tag). When the body is "text" we
//     promote the message to "html" so the banner renders properly.
//  3. PATCH /v1.0/users/{email}/messages/{id} with the updated body.
//
// Compared to the Gmail shadow-copy approach this preserves the
// original message ID and conversation index, so any downstream
// systems that key off `internetMessageId` keep working without
// remapping.
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

// NewBannerInjector constructs an Outlook BannerInjector. TokenSource
// is required.
func NewBannerInjector(cfg BannerInjectorConfig) (*BannerInjector, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("outlook: banner injector token source is required")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://graph.microsoft.com"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &BannerInjector{baseURL: base, http: client, tokens: cfg.TokenSource}, nil
}

// outlookMessageBody is the wire shape of the `body` complex type on
// /messages.
type outlookMessageBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

// outlookMessageBodyEnvelope wraps body for $select / PATCH.
type outlookMessageBodyEnvelope struct {
	ID   string             `json:"id,omitempty"`
	Body outlookMessageBody `json:"body"`
}

// InjectBanner reads the current body via Graph, splices the banner
// in, and PATCHes the message back. The HTML field on the request is
// always rendered as HTML — Outlook's mobile + desktop clients all
// support it, and we deliberately promote text-only bodies to HTML so
// the banner renders correctly.
func (b *BannerInjector) InjectBanner(ctx context.Context, req action.BannerInjectRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if req.Email == "" {
		return errors.New("outlook: banner injector requires email")
	}

	current, err := b.getBody(ctx, req.Email, req.MessageID)
	if err != nil {
		return fmt.Errorf("outlook: get body: %w", err)
	}

	updated := injectBannerIntoBody(current, string(req.HTML))
	if err := b.patchBody(ctx, req.Email, req.MessageID, updated); err != nil {
		return fmt.Errorf("outlook: patch body: %w", err)
	}
	return nil
}

// getBody fetches the message body via Graph. The $select filter
// keeps the payload small.
func (b *BannerInjector) getBody(ctx context.Context, email, messageID string) (outlookMessageBody, error) {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s?$select=body",
		b.baseURL, url.PathEscape(email), url.PathEscape(messageID))
	var env outlookMessageBodyEnvelope
	if err := b.do(ctx, http.MethodGet, endpoint, nil, &env); err != nil {
		return outlookMessageBody{}, err
	}
	return env.Body, nil
}

// patchBody writes body via Graph PATCH /messages/{id}.
func (b *BannerInjector) patchBody(ctx context.Context, email, messageID string, body outlookMessageBody) error {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s",
		b.baseURL, url.PathEscape(email), url.PathEscape(messageID))
	return b.do(ctx, http.MethodPatch, endpoint, outlookMessageBodyEnvelope{Body: body}, nil)
}

// injectBannerIntoBody returns a new outlookMessageBody with the
// banner spliced in. Text bodies are promoted to HTML so the banner
// markup renders; HTML bodies are mutated in-place.
func injectBannerIntoBody(current outlookMessageBody, banner string) outlookMessageBody {
	ct := strings.ToLower(strings.TrimSpace(current.ContentType))
	switch ct {
	case "html":
		return outlookMessageBody{
			ContentType: "html",
			Content:     spliceHTMLBanner(current.Content, banner),
		}
	case "", "text":
		// Promote to HTML so the banner renders. Escape the
		// existing plain-text body inside a <pre> block to
		// preserve whitespace.
		escaped := htmlEscape(current.Content)
		merged := banner + "<hr/><pre>" + escaped + "</pre>"
		return outlookMessageBody{
			ContentType: "html",
			Content:     merged,
		}
	default:
		// Unknown content types (e.g. "RTF" via legacy clients);
		// preserve the original and prepend the banner as HTML.
		return outlookMessageBody{
			ContentType: "html",
			Content:     banner + current.Content,
		}
	}
}

// spliceHTMLBanner inserts banner after the opening <body> tag (or
// the top of the document if no <body> exists). Lower-cases the
// search needle so we tolerate <BODY>, <Body>, etc.
func spliceHTMLBanner(doc, banner string) string {
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

// htmlEscape returns a minimal HTML-escaped form of s that is safe
// to embed inside <pre>. We escape & first, then <, >, ", '.
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

// do executes an authenticated request and decodes the JSON response
// into out when out != nil. Non-2xx responses are turned into a typed
// APIError containing the response body.
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
		return errors.New("outlook: empty bearer token")
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := b.http.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if rerr != nil {
		return fmt.Errorf("read body: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return &APIError{StatusCode: resp.StatusCode, Body: string(respBody), Endpoint: endpoint}
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
