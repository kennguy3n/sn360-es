package zoho

import (
	"context"
	"errors"
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BodyRewriter implements action.BodyRewriter for Zoho Mail. The
// implementation delegates to the existing BannerInjector's
// fetch/write helpers so we only maintain one HTTP plumbing path.
type BodyRewriter struct {
	inj *BannerInjector
}

// NewBodyRewriter constructs a Zoho BodyRewriter from an existing
// BannerInjector. The injector must be non-nil.
func NewBodyRewriter(inj *BannerInjector) (*BodyRewriter, error) {
	if inj == nil {
		return nil, errors.New("zoho: body rewriter requires a non-nil banner injector")
	}
	return &BodyRewriter{inj: inj}, nil
}

// FetchBody returns the HTML body of the given message. Plain-text
// bodies are returned as-is (callers can detect via empty HTML).
func (r *BodyRewriter) FetchBody(ctx context.Context, email, messageID string) (string, error) {
	accountID, err := r.inj.accountIDForEmail(ctx, email)
	if err != nil {
		return "", err
	}
	body, err := r.inj.fetchBody(ctx, accountID, messageID)
	if err != nil {
		return "", fmt.Errorf("zoho body_rewriter: fetch: %w", err)
	}
	if body.IsHTML {
		return body.HTML, nil
	}
	return body.Text, nil
}

// WriteBody PUTs the new HTML body via the Zoho message-edit
// endpoint.
func (r *BodyRewriter) WriteBody(ctx context.Context, email, messageID, htmlBody string) error {
	accountID, err := r.inj.accountIDForEmail(ctx, email)
	if err != nil {
		return err
	}
	body := zohoBody{HTML: htmlBody, IsHTML: true}
	if err := r.inj.writeBody(ctx, accountID, messageID, body); err != nil {
		return fmt.Errorf("zoho body_rewriter: write: %w", err)
	}
	return nil
}

// Compile-time interface check.
var _ action.BodyRewriter = (*BodyRewriter)(nil)
