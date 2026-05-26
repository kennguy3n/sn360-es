package workmail

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BannerInjector implements action.BannerInjector for WorkMail via
// EWS UpdateItem on the item:Body property. The body is fetched as
// HTML, the banner is spliced after <body>, and the merged HTML is
// written back. Mirrors the Outlook implementation conceptually.
type BannerInjector struct {
	ews *EWSClient
}

// BannerInjectorConfig wires BannerInjector.
type BannerInjectorConfig struct {
	EWS *EWSClient
}

// NewBannerInjector validates the config and returns the injector.
func NewBannerInjector(cfg BannerInjectorConfig) (*BannerInjector, error) {
	if cfg.EWS == nil {
		return nil, errors.New("workmail: banner injector requires an EWSClient")
	}
	return &BannerInjector{ews: cfg.EWS}, nil
}

// InjectBanner reads the message body, splices the banner, and writes
// it back.
func (b *BannerInjector) InjectBanner(ctx context.Context, req action.BannerInjectRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if req.Email == "" {
		return errors.New("workmail: banner injector requires email")
	}
	body, err := b.ews.GetItem(ctx, req.Email, req.MessageID)
	if err != nil {
		return fmt.Errorf("workmail: get body: %w", err)
	}
	updated := injectWorkmailBanner(body, string(req.HTML))
	if err := b.ews.UpdateBody(ctx, req.Email, req.MessageID, updated); err != nil {
		return fmt.Errorf("workmail: update body: %w", err)
	}
	return nil
}

// injectWorkmailBanner returns a new EWSMessageBody with the banner
// spliced in. Plain-text bodies are promoted to HTML so the banner
// renders.
func injectWorkmailBanner(current EWSMessageBody, banner string) EWSMessageBody {
	if strings.EqualFold(current.BodyType, "HTML") {
		return EWSMessageBody{
			BodyType: "HTML",
			Content:  spliceHTMLBanner(current.Content, banner),
		}
	}
	escaped := htmlEscape(current.Content)
	return EWSMessageBody{
		BodyType: "HTML",
		Content:  banner + "<hr/><pre>" + escaped + "</pre>",
	}
}

// spliceHTMLBanner inserts banner after the opening <body> tag.
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
