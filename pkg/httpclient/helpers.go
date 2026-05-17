package httpclient

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
)

// JSON sends a JSON-encoded payload and decodes the JSON response into out.
//
// payload may be nil (no body). out may be nil (no decode). Non-2xx
// responses produce an [*Error] with the body captured (truncated to
// 4 KiB) so callers can surface upstream diagnostics safely.
//
// JSON does NOT set req.GetBody when method is POST, so POST calls are
// treated as non-idempotent by [Client.Do] and never retried on 5xx —
// retrying a non-idempotent POST can produce duplicate side effects
// (duplicate escalation tickets, duplicate banner releases). Callers
// whose POST endpoint is genuinely idempotent should call
// [Client.PostJSONIdempotent] instead.
func (c *Client) JSON(ctx context.Context, method, path string, payload, out any) error {
	return c.jsonRequest(ctx, method, path, payload, out, methodAllowsAutoRetry(method))
}

// GetJSON is a thin shortcut over JSON for GET requests.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	return c.JSON(ctx, http.MethodGet, path, nil, out)
}

// PostJSON is a thin shortcut over JSON for POST requests. The request is
// treated as NON-idempotent and is never retried by [Client.Do]. Use
// [Client.PostJSONIdempotent] only for endpoints whose semantics make a
// duplicate POST safe (e.g. PUT-style upserts that the server has
// chosen to expose under POST).
func (c *Client) PostJSON(ctx context.Context, path string, payload, out any) error {
	return c.JSON(ctx, http.MethodPost, path, payload, out)
}

// PostJSONIdempotent is identical to [Client.PostJSON] but marks the
// request as idempotent by populating req.GetBody, which permits
// [Client.Do] to retry it on 5xx or network failures.
//
// ONLY use this for endpoints whose contract guarantees that a
// duplicate POST is safe (e.g. server-side dedup keyed off a stable
// request ID, or PUT-style upserts exposed as POST). For ticket
// creation, banner release, simulation send, or anything else that
// produces user-visible side effects, use [Client.PostJSON].
func (c *Client) PostJSONIdempotent(ctx context.Context, path string, payload, out any) error {
	return c.jsonRequest(ctx, http.MethodPost, path, payload, out, true)
}

// PutJSON is a thin shortcut over JSON for PUT requests.
func (c *Client) PutJSON(ctx context.Context, path string, payload, out any) error {
	return c.JSON(ctx, http.MethodPut, path, payload, out)
}

// methodAllowsAutoRetry reports whether the helper should populate
// req.GetBody (and therefore consent to retries) for the given verb.
// PUT/DELETE/OPTIONS are semantically idempotent; bodyless verbs do
// not need GetBody at all but it's harmless to skip them since Do
// only rewinds when GetBody is set.
func methodAllowsAutoRetry(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions,
		http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

// jsonRequest is the concrete implementation behind JSON / GetJSON /
// PostJSON / PutJSON / PostJSONIdempotent. retryable controls whether
// req.GetBody is populated, which in turn governs Do's retry decision.
func (c *Client) jsonRequest(ctx context.Context, method, path string, payload, out any, retryable bool) error {
	body, err := encodeJSON(payload)
	if err != nil {
		return err
	}
	u, err := c.resolveURL(path)
	if err != nil {
		return err
	}
	var reqBody io.Reader
	if body != nil {
		reqBody = body
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return &Error{Op: method, URL: u, Cause: err}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		if retryable {
			raw := body.Bytes()
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(raw)), nil
			}
		} else {
			// http.NewRequestWithContext auto-populates GetBody for
			// *bytes.Buffer / *bytes.Reader / *strings.Reader inputs.
			// Drop it explicitly for non-retryable verbs (POST) so
			// Client.Do treats the request as non-idempotent and the
			// caller cannot accidentally double-submit on 5xx.
			req.GetBody = nil
		}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return errorFromResponse(method, u, resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return &Error{Op: method, URL: u, Status: resp.StatusCode, Cause: err}
	}
	return nil
}

func (c *Client) resolveURL(path string) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	if c.cfg.BaseURL == "" {
		return "", errors.New("httpclient: relative path requires BaseURL")
	}
	base, err := url.Parse(c.cfg.BaseURL)
	if err != nil {
		return "", fmt.Errorf("httpclient: base url: %w", err)
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("httpclient: rel url: %w", err)
	}
	return base.ResolveReference(rel).String(), nil
}

func encodeJSON(payload any) (*bytes.Buffer, error) {
	if payload == nil {
		return nil, nil
	}
	buf := bytes.NewBuffer(make([]byte, 0, 256))
	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return nil, &Error{Op: "encode", Cause: err}
	}
	return buf, nil
}

func errorFromResponse(op, u string, resp *http.Response) *Error {
	limited := io.LimitReader(resp.Body, 4*1024)
	body, _ := io.ReadAll(limited)
	cause := fmt.Errorf("upstream returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	return &Error{Op: op, URL: u, Status: resp.StatusCode, Cause: cause}
}
