package outlook

import (
	"context"
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// Ensure OutlookBodyRewriter satisfies the interface at compile time.
var _ action.BodyRewriter = (*BodyRewriter)(nil)

// BodyRewriter implements action.BodyRewriter for Outlook using
// Microsoft Graph's GET/PATCH approach on /messages/{id}/body.
type BodyRewriter struct {
	inj *BannerInjector
}

// NewBodyRewriter constructs an Outlook BodyRewriter from an existing
// BannerInjector (reuses its HTTP client, token source, and base URL).
func NewBodyRewriter(inj *BannerInjector) *BodyRewriter {
	return &BodyRewriter{inj: inj}
}

// FetchBody retrieves the message's HTML body via Microsoft Graph.
func (o *BodyRewriter) FetchBody(ctx context.Context, email, messageID string) (string, error) {
	body, err := o.inj.getBody(ctx, email, messageID)
	if err != nil {
		return "", fmt.Errorf("outlook body_rewriter: get body: %w", err)
	}
	return body.Content, nil
}

// WriteBody PATCHes the message body back via Microsoft Graph.
func (o *BodyRewriter) WriteBody(ctx context.Context, email, messageID, htmlBody string) error {
	if err := o.inj.patchBody(ctx, email, messageID, outlookMessageBody{
		ContentType: "html",
		Content:     htmlBody,
	}); err != nil {
		return fmt.Errorf("outlook body_rewriter: patch body: %w", err)
	}
	return nil
}
