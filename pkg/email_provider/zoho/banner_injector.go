package zoho

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BannerInjector implements action.BannerInjector against the Zoho
// Mail message-content endpoint.
//
// Zoho exposes a "draft replace" semantics: PUT /accounts/{acct}/messages/{id}
// with a `content` body atomically rewrites the message. The flow is
// the same GET → splice → PUT used by Outlook; the body MIME type is
// preserved when "html", otherwise we promote text bodies to HTML so
// the banner markup renders correctly.
type BannerInjector struct {
	client *Client
}

// BannerInjectorConfig wires BannerInjector.
type BannerInjectorConfig struct {
	Client *Client
}

// NewBannerInjector validates the config and returns a BannerInjector.
func NewBannerInjector(cfg BannerInjectorConfig) (*BannerInjector, error) {
	if cfg.Client == nil {
		return nil, errors.New("zoho: banner injector requires a Client")
	}
	return &BannerInjector{client: cfg.Client}, nil
}

// InjectBanner reads the current body via Zoho, splices the banner in,
// and writes the message back.
func (b *BannerInjector) InjectBanner(ctx context.Context, req action.BannerInjectRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if req.Email == "" {
		return errors.New("zoho: banner injector requires email")
	}
	accountID, err := b.accountIDForEmail(ctx, req.Email)
	if err != nil {
		return err
	}
	body, err := b.fetchBody(ctx, accountID, req.MessageID)
	if err != nil {
		return fmt.Errorf("zoho: fetch body: %w", err)
	}
	updated := injectZohoBanner(body, string(req.HTML))
	if err := b.writeBody(ctx, accountID, req.MessageID, updated); err != nil {
		return fmt.Errorf("zoho: write body: %w", err)
	}
	return nil
}

// zohoBody is the lightweight representation of a message body that
// the injector and body rewriter share.
type zohoBody struct {
	HTML    string
	Text    string
	IsHTML  bool
	Headers map[string]string
}

// fetchBody retrieves the rendered body of a Zoho message via the
// per-message content endpoint.
func (b *BannerInjector) fetchBody(ctx context.Context, accountID, messageID string) (zohoBody, error) {
	endpoint := fmt.Sprintf("%s/accounts/%s/messages/%s/content?mode=full",
		b.client.baseURL, url.PathEscape(accountID), url.PathEscape(messageID))
	var resp struct {
		Data struct {
			HTMLContent string            `json:"htmlContent"`
			Content     string            `json:"content"`
			Headers     map[string]string `json:"headers"`
		} `json:"data"`
	}
	if err := b.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return zohoBody{}, err
	}
	body := zohoBody{
		HTML:    resp.Data.HTMLContent,
		Text:    resp.Data.Content,
		Headers: resp.Data.Headers,
	}
	body.IsHTML = strings.TrimSpace(body.HTML) != ""
	return body, nil
}

// writeBody writes the modified body back via the message-edit
// endpoint. Zoho expects `content`, `contentType` and `mode=edit`.
func (b *BannerInjector) writeBody(ctx context.Context, accountID, messageID string, body zohoBody) error {
	endpoint := fmt.Sprintf("%s/accounts/%s/messages/%s",
		b.client.baseURL, url.PathEscape(accountID), url.PathEscape(messageID))
	payload := map[string]any{
		"mode":        "edit",
		"contentType": "text/html",
		"content":     body.HTML,
	}
	if !body.IsHTML && body.Text != "" {
		payload["contentType"] = "text/plain"
		payload["content"] = body.Text
	}
	return b.client.do(ctx, http.MethodPut, endpoint, payload, nil)
}

// accountIDForEmail mirrors the helper on LabelProvider — delegates
// to the per-Client cache so we avoid re-enumerating /api/users on
// every banner injection.
func (b *BannerInjector) accountIDForEmail(ctx context.Context, email string) (string, error) {
	return b.client.ResolveAccountID(ctx, email)
}

// injectZohoBanner returns a new zohoBody with the banner spliced in.
// Plain-text bodies are promoted to HTML so the banner renders.
func injectZohoBanner(current zohoBody, banner string) zohoBody {
	if current.IsHTML || strings.TrimSpace(current.HTML) != "" {
		return zohoBody{
			HTML:    spliceHTMLBanner(current.HTML, banner),
			Headers: current.Headers,
			IsHTML:  true,
		}
	}
	escaped := htmlEscape(current.Text)
	merged := banner + "<hr/><pre>" + escaped + "</pre>"
	return zohoBody{
		HTML:    merged,
		Headers: current.Headers,
		IsHTML:  true,
	}
}

// spliceHTMLBanner inserts banner after the opening <body> tag (or
// the top of the document if no <body> exists). The search is case
// insensitive so <BODY>, <Body>, etc. all match.
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
