package workmail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the shared plumbing for the WorkMail JSON API
// (AWSWorkMail_20171001 service). Per AWS convention the API is
// invoked via HTTP POST to https://workmail.<region>.amazonaws.com/
// with a JSON body and an X-Amz-Target header identifying the
// operation.
type Client struct {
	http      *http.Client
	signer    *Signer
	endpoint  string
	orgID     string
	region    string
}

// ClientConfig wires Client.
type ClientConfig struct {
	HTTPClient *http.Client
	Signer     *Signer
	// Endpoint overrides the WorkMail base URL. Defaults to
	// https://workmail.<region>.amazonaws.com when empty.
	Endpoint string
	Region   string
	OrgID    string
}

// NewClient validates the config and returns a usable Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Signer == nil {
		return nil, errors.New("workmail: client requires a Signer")
	}
	if cfg.Region == "" {
		return nil, errors.New("workmail: client requires a region")
	}
	if strings.TrimSpace(cfg.OrgID) == "" {
		return nil, errors.New("workmail: client requires an organization id")
	}
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://workmail.%s.amazonaws.com", cfg.Region)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		http:     client,
		signer:   cfg.Signer,
		endpoint: endpoint,
		orgID:    cfg.OrgID,
		region:   cfg.Region,
	}, nil
}

// OrgID returns the configured organization id.
func (c *Client) OrgID() string { return c.orgID }

// Region returns the configured AWS region.
func (c *Client) Region() string { return c.region }

// APIError captures a non-2xx response from the WorkMail API.
type APIError struct {
	Operation  string
	StatusCode int
	Type       string `json:"__type"`
	Message    string `json:"message"`
	Body       string
}

// Error renders a compact form for logs.
func (e *APIError) Error() string {
	if e.Type != "" || e.Message != "" {
		return fmt.Sprintf("workmail: %s %d %s: %s", e.Operation, e.StatusCode, e.Type, e.Message)
	}
	return fmt.Sprintf("workmail: %s %d: %s", e.Operation, e.StatusCode, e.Body)
}

// Invoke runs a WorkMail JSON API operation. operation is the
// X-Amz-Target value minus the service prefix (e.g. "ListUsers").
func (c *Client) Invoke(ctx context.Context, operation string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("workmail: marshal %s: %w", operation, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("workmail: build %s: %w", operation, err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AWSWorkMail_20171001."+operation)
	if err := c.signer.Sign(ctx, req, body); err != nil {
		return fmt.Errorf("workmail: sign %s: %w", operation, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("workmail: http %s: %w", operation, err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if rerr != nil {
		return fmt.Errorf("workmail: read %s: %w", operation, rerr)
	}
	if resp.StatusCode/100 != 2 {
		apiErr := &APIError{Operation: operation, StatusCode: resp.StatusCode, Body: string(respBody)}
		_ = json.Unmarshal(respBody, apiErr)
		return apiErr
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("workmail: decode %s: %w", operation, err)
	}
	return nil
}
