// Package gmail provides a minimal Gmail REST API client that
// implements action.LabelProvider. It uses the documented
// `users.labels` and `users.messages.modify` endpoints
// (https://developers.google.com/gmail/api/reference/rest) directly
// over HTTP, avoiding the heavy `google.golang.org/api/gmail/v1`
// surface. Authentication is delegated to a TokenSource the caller
// supplies — typically a `golang.org/x/oauth2.TokenSource` produced
// from domain-wide-delegation credentials.
package gmail

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
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// TokenSource yields a fresh OAuth2 bearer token on each call. The
// minimal surface keeps the provider compatible with both
// `golang.org/x/oauth2.TokenSource` and any custom impersonation
// helper without pulling the oauth2 module into this package.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts a function to the TokenSource interface.
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token implements TokenSource.
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// Config wires LabelProvider.
type Config struct {
	// BaseURL overrides the Gmail REST base. Default is the public
	// endpoint at https://gmail.googleapis.com.
	BaseURL string
	// HTTPClient is the transport. Default is http.DefaultClient with
	// a 30s timeout.
	HTTPClient *http.Client
	// TokenSource issues bearer tokens. Required.
	TokenSource TokenSource
	// LabelVisibility controls the listVisibility / labelListVisibility
	// applied to labels we ensure. Defaults to "labelShow" and
	// "labelShow" so the labels are visible in the Gmail sidebar.
	LabelVisibility   string
	MsgListVisibility string
}

// LabelProvider is the HTTP-backed implementation of
// action.LabelProvider for Gmail.
type LabelProvider struct {
	baseURL string
	http    *http.Client
	tokens  TokenSource

	labelVis    string
	msgLabelVis string
}

// New constructs a Gmail LabelProvider. TokenSource is required; the
// other fields fall back to sensible defaults.
func New(cfg Config) (*LabelProvider, error) {
	if cfg.TokenSource == nil {
		return nil, errors.New("gmail: token source is required")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://gmail.googleapis.com"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	labelVis := cfg.LabelVisibility
	if labelVis == "" {
		labelVis = "labelShow"
	}
	msgVis := cfg.MsgListVisibility
	if msgVis == "" {
		msgVis = "show"
	}
	return &LabelProvider{
		baseURL:     base,
		http:        client,
		tokens:      cfg.TokenSource,
		labelVis:    labelVis,
		msgLabelVis: msgVis,
	}, nil
}

// Kind reports the provider identity used by action.LabelApplier.
func (p *LabelProvider) Kind() action.LabelProviderKind { return action.LabelProviderGmail }

// gmailLabel is the wire shape for users.labels.{list,create,get}.
type gmailLabel struct {
	ID                    string           `json:"id,omitempty"`
	Name                  string           `json:"name"`
	LabelListVisibility   string           `json:"labelListVisibility,omitempty"`
	MessageListVisibility string           `json:"messageListVisibility,omitempty"`
	Color                 *gmailLabelColor `json:"color,omitempty"`
}

type gmailLabelColor struct {
	BackgroundColor string `json:"backgroundColor,omitempty"`
	TextColor       string `json:"textColor,omitempty"`
}

type gmailLabelList struct {
	Labels []gmailLabel `json:"labels"`
}

// EnsureLabel creates the label in the user's mailbox if it does not
// already exist. The lookup is by exact name; Gmail's `labels.list`
// endpoint is global per mailbox so a single round-trip suffices in
// the cache-miss path.
func (p *LabelProvider) EnsureLabel(ctx context.Context, email, name string, color action.LabelColor) (string, error) {
	if email == "" || name == "" {
		return "", errors.New("gmail: email and label name are required")
	}
	if id, err := p.findLabelID(ctx, email, name); err != nil {
		return "", err
	} else if id != "" {
		return id, nil
	}

	body := gmailLabel{
		Name:                  name,
		LabelListVisibility:   p.labelVis,
		MessageListVisibility: p.msgLabelVis,
	}
	if c := mapColor(color); c != nil {
		body.Color = c
	}

	endpoint := fmt.Sprintf("%s/gmail/v1/users/%s/labels", p.baseURL, url.PathEscape(email))
	var out gmailLabel
	if err := p.do(ctx, http.MethodPost, endpoint, body, &out); err != nil {
		return "", fmt.Errorf("gmail: create label %q: %w", name, err)
	}
	if out.ID == "" {
		return "", fmt.Errorf("gmail: create label %q returned empty id", name)
	}
	return out.ID, nil
}

// findLabelID resolves an existing label by name. It returns ("", nil)
// when no match exists so the caller can fall through to create.
func (p *LabelProvider) findLabelID(ctx context.Context, email, name string) (string, error) {
	endpoint := fmt.Sprintf("%s/gmail/v1/users/%s/labels", p.baseURL, url.PathEscape(email))
	var list gmailLabelList
	if err := p.do(ctx, http.MethodGet, endpoint, nil, &list); err != nil {
		return "", fmt.Errorf("gmail: list labels: %w", err)
	}
	for _, l := range list.Labels {
		if l.Name == name {
			return l.ID, nil
		}
	}
	return "", nil
}

type gmailModifyRequest struct {
	AddLabelIDs    []string `json:"addLabelIds,omitempty"`
	RemoveLabelIDs []string `json:"removeLabelIds,omitempty"`
}

// ApplyLabel attaches labelID to messageID via
// users.messages.modify.
func (p *LabelProvider) ApplyLabel(ctx context.Context, email, messageID, labelID string) error {
	return p.modify(ctx, email, messageID, gmailModifyRequest{AddLabelIDs: []string{labelID}})
}

// RemoveLabel detaches labelID from messageID via
// users.messages.modify.
func (p *LabelProvider) RemoveLabel(ctx context.Context, email, messageID, labelID string) error {
	return p.modify(ctx, email, messageID, gmailModifyRequest{RemoveLabelIDs: []string{labelID}})
}

func (p *LabelProvider) modify(ctx context.Context, email, messageID string, body gmailModifyRequest) error {
	if email == "" || messageID == "" {
		return errors.New("gmail: email and message_id are required")
	}
	endpoint := fmt.Sprintf("%s/gmail/v1/users/%s/messages/%s/modify",
		p.baseURL, url.PathEscape(email), url.PathEscape(messageID))
	return p.do(ctx, http.MethodPost, endpoint, body, nil)
}

// do executes an authenticated request and decodes the JSON response
// into out when out != nil. Non-2xx responses are turned into a typed
// error containing the response body so callers can log the Google
// error envelope intact.
func (p *LabelProvider) do(ctx context.Context, method, endpoint string, in, out any) error {
	var bodyReader io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	tok, err := p.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("acquire token: %w", err)
	}
	if tok == "" {
		return errors.New("gmail: empty bearer token")
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return fmt.Errorf("read body: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
			Endpoint:   endpoint,
		}
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// mapColor translates the abstract LabelColor into Gmail's
// labels.color object. Gmail only accepts six-digit hex codes from a
// documented palette; we snap the supplied Background/Foreground to
// the nearest allowed value. Empty Background returns nil so the
// label is created with the default (Gmail-assigned) color.
func mapColor(c action.LabelColor) *gmailLabelColor {
	if c.Background == "" {
		return nil
	}
	bg := snapToGmailPalette(c.Background, gmailBackgroundPalette)
	fg := c.Foreground
	if fg == "" {
		fg = "#ffffff"
	}
	fg = snapToGmailPalette(fg, gmailTextPalette)
	return &gmailLabelColor{BackgroundColor: bg, TextColor: fg}
}

// gmailBackgroundPalette is a subset of the Gmail-permitted label
// background colours that covers the SN360 tier palette. The list is
// intentionally short — Gmail rejects values outside this set with a
// 400.
var gmailBackgroundPalette = []string{
	"#000000", "#434343", "#666666", "#999999", "#cccccc", "#efefef", "#f3f3f3", "#ffffff",
	"#fb4c2f", "#ffad47", "#fad165", "#16a766", "#43d692", "#4a86e8", "#a479e2", "#f691b3",
	"#f6c5be", "#ffe6c7", "#fef1d1", "#b9e4d0", "#c6f3de", "#c9daf8", "#e4d7f5", "#fcdee8",
	"#efa093", "#ffd6a2", "#fce8b3", "#89d3b2", "#a0eac9", "#a4c2f4", "#d0bcf1", "#fbc8d9",
	"#e66550", "#ffbc6b", "#fcda83", "#44b984", "#68dfa9", "#6d9eeb", "#b694e8", "#f7a7c0",
	"#cc3a21", "#eaa041", "#f2c960", "#149e60", "#3dc789", "#3c78d8", "#8e63ce", "#e07798",
	"#ac2b16", "#cf8933", "#d5ae49", "#0b804b", "#2a9c68", "#285bac", "#653e9b", "#b65775",
	"#822111", "#a46a21", "#aa8831", "#076239", "#1a764d", "#1c4587", "#41236d", "#83334c",
}

// gmailTextPalette is the matching foreground palette. Gmail accepts
// the same colour codes for text but only when paired with a
// permitted background.
var gmailTextPalette = gmailBackgroundPalette

// snapToGmailPalette returns the palette entry that exactly matches
// (case-insensitive) the requested colour, or the first palette entry
// when no match is found. This lets the caller use any of the
// permitted Gmail hex codes directly without forcing an
// approximate-match algorithm we cannot test for stability.
func snapToGmailPalette(want string, palette []string) string {
	w := strings.ToLower(want)
	for _, p := range palette {
		if strings.EqualFold(p, w) {
			return p
		}
	}
	// Fall back to a safe neutral so the create call succeeds.
	return "#666666"
}

// APIError captures a non-2xx response. It is exported so callers
// can branch on the status code (e.g. retry on 503).
type APIError struct {
	StatusCode int
	Body       string
	Endpoint   string
}

// Error renders a compact form including the endpoint for fast
// triage.
func (e *APIError) Error() string {
	return fmt.Sprintf("gmail: %d %s: %s", e.StatusCode, e.Endpoint, truncate(e.Body, 256))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
