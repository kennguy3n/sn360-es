// Package fastmail implements the SN360-ES provider integration
// against Fastmail's JMAP API (RFC 8620 + RFC 8621). Fastmail does
// not implement OAuth2 for personal/SMB API access; authentication is
// done with an app-specific API token that the operator generates in
// the Fastmail settings UI. The token is sent as a Bearer header on
// every JMAP request.
//
// The package mirrors the dependency-free style of the other
// providers — only the Go standard library is used.
package fastmail

import (
	"context"
	"errors"
)

// TokenSource yields a fresh JMAP bearer token on each call. The
// surface is intentionally tiny so consumers can plug in a static
// token (StaticTokenSource), a future OAuth2 flow, or a custom
// function in tests.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts an ordinary function to TokenSource.
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token implements TokenSource.
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// StaticTokenSource returns the same bearer token on every call. This
// is the production token source for Fastmail today: the API token is
// long-lived and does not need to be refreshed.
type StaticTokenSource struct{ APIToken string }

// Token implements TokenSource.
func (s StaticTokenSource) Token(context.Context) (string, error) {
	if s.APIToken == "" {
		return "", errors.New("fastmail: static token source has empty API token")
	}
	return s.APIToken, nil
}
