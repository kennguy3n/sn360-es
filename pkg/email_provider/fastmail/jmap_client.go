package fastmail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Client is the shared JMAP HTTP plumbing reused by every Fastmail
// provider in this package. It performs session discovery (RFC 8620
// §2) lazily on first use and caches the resulting apiUrl.
type Client struct {
	http       *http.Client
	tokens     TokenSource
	baseURL    string
	accountID  string
	sessionURL string

	mu      sync.Mutex
	session *Session
}

// ClientConfig wires Client. APIToken or TokenSource is required;
// AccountID is the JMAP account identifier used as the registry key.
type ClientConfig struct {
	HTTPClient  *http.Client
	TokenSource TokenSource
	// BaseURL overrides the JMAP base URL ("https://api.fastmail.com")
	// at which /.well-known/jmap lives. Useful for tests + alt hosts.
	BaseURL string
	// AccountID is the JMAP accountId for every method call. When
	// empty the client picks the primaryAccount declared by the
	// JMAP session response (RFC 8620 §2 primaryAccounts mapping).
	AccountID string
	// SessionURL overrides the .well-known/jmap endpoint for tests.
	SessionURL string
}

// Session represents the JMAP session object returned by the
// well-known endpoint. Only the fields we use are decoded.
type Session struct {
	APIURL          string                       `json:"apiUrl"`
	DownloadURL     string                       `json:"downloadUrl"`
	UploadURL       string                       `json:"uploadUrl"`
	EventSourceURL  string                       `json:"eventSourceUrl"`
	PrimaryAccounts map[string]string            `json:"primaryAccounts"`
	Accounts        map[string]json.RawMessage   `json:"accounts"`
	Capabilities    map[string]json.RawMessage   `json:"capabilities"`
}

// NewClient validates the config and returns a usable Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("fastmail: token source is required")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://api.fastmail.com"
	}
	sessionURL := strings.TrimSpace(cfg.SessionURL)
	if sessionURL == "" {
		sessionURL = base + "/.well-known/jmap"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		http:       client,
		tokens:     cfg.TokenSource,
		baseURL:    base,
		accountID:  strings.TrimSpace(cfg.AccountID),
		sessionURL: sessionURL,
	}, nil
}

// AccountID returns the resolved JMAP account ID. When empty, the
// caller should call Session(ctx) first to populate it.
func (c *Client) AccountID() string { return c.accountID }

// Session returns the cached JMAP session, performing discovery on
// the first call.
func (c *Client) Session(ctx context.Context) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return c.session, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.sessionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fastmail: build session request: %w", err)
	}
	tok, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("fastmail: acquire token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fastmail: session: %w", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return nil, fmt.Errorf("fastmail: read session: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("fastmail: session %d: %s", resp.StatusCode, truncate(string(body), 256))
	}
	var sess Session
	if err := json.Unmarshal(body, &sess); err != nil {
		return nil, fmt.Errorf("fastmail: decode session: %w", err)
	}
	if sess.APIURL == "" {
		return nil, errors.New("fastmail: session response missing apiUrl")
	}
	if c.accountID == "" {
		// Pick the primary mail account when the operator didn't
		// supply one explicitly. The JMAP primaryAccounts mapping
		// keys the per-capability account id.
		c.accountID = sess.PrimaryAccounts["urn:ietf:params:jmap:mail"]
	}
	c.session = &sess
	return c.session, nil
}

// MethodCall is one JMAP invocation: [name, args, call-id].
type MethodCall struct {
	Name   string
	Args   any
	CallID string
}

// MethodResponse is one decoded JMAP response.
type MethodResponse struct {
	Name   string
	Args   json.RawMessage
	CallID string
}

// jmapRequest is the wire-format request body.
type jmapRequest struct {
	Using       []string `json:"using"`
	MethodCalls [][]any  `json:"methodCalls"`
}

// jmapResponse is the wire-format response body.
type jmapResponse struct {
	MethodResponses [][]json.RawMessage `json:"methodResponses"`
	SessionState    string              `json:"sessionState"`
}

// JMAPError captures a non-2xx HTTP response from the JMAP endpoint.
type JMAPError struct {
	StatusCode int
	Body       string
}

// Error renders a compact form for logs.
func (e *JMAPError) Error() string {
	return fmt.Sprintf("fastmail: jmap %d: %s", e.StatusCode, truncate(e.Body, 256))
}

// Invoke issues a single JMAP method call against the configured
// account id and returns the decoded response args.
func (c *Client) Invoke(ctx context.Context, method string, args any) (json.RawMessage, error) {
	resps, err := c.InvokeBatch(ctx, []MethodCall{{Name: method, Args: args, CallID: "0"}})
	if err != nil {
		return nil, err
	}
	if len(resps) == 0 {
		return nil, fmt.Errorf("fastmail: no response for %s", method)
	}
	r := resps[0]
	if r.Name == "error" {
		return nil, fmt.Errorf("fastmail: %s returned error: %s", method, string(r.Args))
	}
	return r.Args, nil
}

// InvokeBatch issues multiple method calls in a single round trip
// and returns the decoded responses in the original order.
func (c *Client) InvokeBatch(ctx context.Context, calls []MethodCall) ([]MethodResponse, error) {
	if len(calls) == 0 {
		return nil, errors.New("fastmail: at least one method call required")
	}
	sess, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	using := []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"}
	wire := make([][]any, len(calls))
	for i, m := range calls {
		callID := m.CallID
		if callID == "" {
			callID = fmt.Sprintf("c%d", i)
		}
		wire[i] = []any{m.Name, m.Args, callID}
	}
	reqBody, err := json.Marshal(jmapRequest{Using: using, MethodCalls: wire})
	if err != nil {
		return nil, fmt.Errorf("fastmail: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sess.APIURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("fastmail: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	tok, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("fastmail: acquire token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fastmail: http: %w", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if rerr != nil {
		return nil, fmt.Errorf("fastmail: read body: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return nil, &JMAPError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	var decoded jmapResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("fastmail: decode: %w", err)
	}
	out := make([]MethodResponse, 0, len(decoded.MethodResponses))
	for _, r := range decoded.MethodResponses {
		if len(r) < 3 {
			return nil, fmt.Errorf("fastmail: malformed method response: %s", string(body))
		}
		var name, callID string
		if err := json.Unmarshal(r[0], &name); err != nil {
			return nil, fmt.Errorf("fastmail: decode method name: %w", err)
		}
		if err := json.Unmarshal(r[2], &callID); err != nil {
			return nil, fmt.Errorf("fastmail: decode call id: %w", err)
		}
		out = append(out, MethodResponse{Name: name, Args: r[1], CallID: callID})
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
