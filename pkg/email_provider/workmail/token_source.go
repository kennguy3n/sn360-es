package workmail

import (
	"context"
	"errors"
	"os"
)

// EnvCredentials reads credentials from the canonical AWS environment
// variables. When AWS_ACCESS_KEY_ID is unset it returns an error so
// the caller can fall back to a different provider rather than
// silently signing with empty credentials.
type EnvCredentials struct{}

// Retrieve implements CredentialsProvider.
func (EnvCredentials) Retrieve(context.Context) (Credentials, error) {
	id := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	token := os.Getenv("AWS_SESSION_TOKEN")
	if id == "" || secret == "" {
		return Credentials{}, errors.New("workmail: env credentials missing")
	}
	return Credentials{AccessKeyID: id, SecretAccessKey: secret, SessionToken: token}, nil
}

// ChainedCredentials tries each underlying provider in order and
// returns the first one that succeeds. It mirrors the spirit of the
// AWS SDK's default credential chain without the IMDS / SSO layers
// (operators wanting those can plug them in as a custom provider).
type ChainedCredentials struct {
	Providers []CredentialsProvider
}

// Retrieve walks the chain.
func (c ChainedCredentials) Retrieve(ctx context.Context) (Credentials, error) {
	var lastErr error
	for _, p := range c.Providers {
		creds, err := p.Retrieve(ctx)
		if err == nil {
			return creds, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("workmail: no credentials providers configured")
	}
	return Credentials{}, lastErr
}
