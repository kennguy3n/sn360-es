package workmail

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// BodyRewriter implements action.BodyRewriter for WorkMail. It is a
// thin wrapper over EWSClient.GetItem / UpdateBody.
type BodyRewriter struct {
	ews *EWSClient
}

// NewBodyRewriter constructs a WorkMail BodyRewriter from an existing
// EWSClient. The client must be non-nil.
func NewBodyRewriter(ews *EWSClient) (*BodyRewriter, error) {
	if ews == nil {
		return nil, errors.New("workmail: body rewriter requires a non-nil EWSClient")
	}
	return &BodyRewriter{ews: ews}, nil
}

// FetchBody returns the HTML body of the given message.
func (r *BodyRewriter) FetchBody(ctx context.Context, email, messageID string) (string, error) {
	body, err := r.ews.GetItem(ctx, email, messageID)
	if err != nil {
		return "", fmt.Errorf("workmail body_rewriter: fetch: %w", err)
	}
	if strings.EqualFold(body.BodyType, "HTML") {
		return body.Content, nil
	}
	return body.Content, nil
}

// WriteBody PATCHes the message body via EWS UpdateItem.
func (r *BodyRewriter) WriteBody(ctx context.Context, email, messageID, htmlBody string) error {
	if err := r.ews.UpdateBody(ctx, email, messageID, EWSMessageBody{BodyType: "HTML", Content: htmlBody}); err != nil {
		return fmt.Errorf("workmail body_rewriter: write: %w", err)
	}
	return nil
}

// Compile-time interface check.
var _ action.BodyRewriter = (*BodyRewriter)(nil)
