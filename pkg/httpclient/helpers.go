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
func (c *Client) JSON(ctx context.Context, method, path string, payload, out any) error {
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
		raw := body.Bytes()
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(raw)), nil
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

// GetJSON is a thin shortcut over JSON for GET requests.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	return c.JSON(ctx, http.MethodGet, path, nil, out)
}

// PostJSON is a thin shortcut over JSON for POST requests.
func (c *Client) PostJSON(ctx context.Context, path string, payload, out any) error {
	return c.JSON(ctx, http.MethodPost, path, payload, out)
}

// PutJSON is a thin shortcut over JSON for PUT requests.
func (c *Client) PutJSON(ctx context.Context, path string, payload, out any) error {
	return c.JSON(ctx, http.MethodPut, path, payload, out)
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
