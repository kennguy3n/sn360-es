package evaluate

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

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// RspamdHTTPConfig configures the Rspamd HTTP client. URL must point at
// the Rspamd controller's HTTP interface (typically port 11334) — e.g.
// "http://rspamd.svc.cluster.local:11334". Password authenticates the
// request via the standard Rspamd "Password" header.
type RspamdHTTPConfig struct {
	// URL is the Rspamd HTTP endpoint base (without trailing slash).
	// Required.
	URL string
	// Password is sent as the "Password" header. Optional but
	// strongly recommended.
	Password string
	// CheckPath is the API path; defaults to "/checkv2".
	CheckPath string
	// Timeout caps the per-call duration. Defaults to 5s.
	Timeout time.Duration
	// HTTPClient lets tests inject a custom transport. Defaults to a
	// freshly constructed http.Client with Timeout.
	HTTPClient *http.Client
}

// RspamdHTTPClient implements evaluate.RspamdClient. It serialises the
// SN360 EvaluateRequest into an RFC-5322-ish raw message and POSTs it
// to Rspamd's /checkv2 endpoint, then projects the JSON response into
// dto.RspamdOutcome.
type RspamdHTTPClient struct {
	url      string
	password string
	path     string
	timeout  time.Duration
	http     *http.Client
}

// NewRspamdHTTPClient validates cfg and returns a ready-to-use client.
func NewRspamdHTTPClient(cfg RspamdHTTPConfig) (*RspamdHTTPClient, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("rspamd: URL is required")
	}
	if cfg.CheckPath == "" {
		cfg.CheckPath = "/checkv2"
	}
	if !strings.HasPrefix(cfg.CheckPath, "/") {
		cfg.CheckPath = "/" + cfg.CheckPath
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	return &RspamdHTTPClient{
		url:      strings.TrimRight(cfg.URL, "/"),
		password: cfg.Password,
		path:     cfg.CheckPath,
		timeout:  cfg.Timeout,
		http:     cfg.HTTPClient,
	}, nil
}

// rspamdResponse mirrors the JSON shape returned by /checkv2. We only
// pull the fields the orchestrator and banner renderer consume; the
// full Rspamd response is much richer.
type rspamdResponse struct {
	Score    float64 `json:"score"`
	Required float64 `json:"required_score"`
	Action   string  `json:"action"`
	Symbols  map[string]struct {
		Score  float64 `json:"score"`
		Name   string  `json:"name"`
		Metric string  `json:"metric_score,omitempty"`
	} `json:"symbols"`
}

// Score implements evaluate.RspamdClient. It assembles a minimal raw
// email from req, POSTs it to /checkv2, and returns the structured
// outcome. Latency is measured wall-clock.
func (c *RspamdHTTPClient) Score(ctx context.Context, req dto.EvaluateRequest) (dto.RspamdOutcome, error) {
	if c == nil {
		return dto.RspamdOutcome{}, errors.New("rspamd: client is nil")
	}
	rctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	payload := buildRawEmail(req)

	httpReq, err := http.NewRequestWithContext(rctx, http.MethodPost, c.url+c.path, bytes.NewReader(payload))
	if err != nil {
		return dto.RspamdOutcome{}, fmt.Errorf("rspamd: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if c.password != "" {
		httpReq.Header.Set("Password", sanitiseHeaderValue(c.password))
	}
	// Hint Rspamd about the envelope identities so plugins like SPF
	// have something to work with. These are also recognised
	// alternatives to embedding Return-Path / Received headers.
	// Each value is CRLF-stripped — Go's net/http already rejects
	// CRLF at write time, but doing it here makes the contract
	// explicit and matches the buildRawEmail() body, where stdlib
	// validation does not apply.
	if req.Sender != "" {
		httpReq.Header.Set("From", sanitiseHeaderValue(req.Sender))
	}
	if req.Recipient != "" {
		httpReq.Header.Set("Rcpt", sanitiseHeaderValue(req.Recipient))
	}
	if req.MessageID != "" {
		httpReq.Header.Set("Queue-Id", sanitiseHeaderValue(req.MessageID))
	}

	start := time.Now()
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return dto.RspamdOutcome{}, fmt.Errorf("rspamd: do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return dto.RspamdOutcome{}, fmt.Errorf("rspamd: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed rspamdResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return dto.RspamdOutcome{}, fmt.Errorf("rspamd: decode response: %w", err)
	}

	symbols := map[string]float64{}
	for name, sym := range parsed.Symbols {
		key := name
		if sym.Name != "" {
			key = sym.Name
		}
		symbols[key] = sym.Score
	}

	out := dto.RspamdOutcome{
		Score:     clampRspamdScore(parsed.Score),
		Threshold: parsed.Required,
		Action:    parsed.Action,
		Symbols:   symbols,
		LatencyMs: time.Since(start).Milliseconds(),
	}
	return out, nil
}

// buildRawEmail synthesises the smallest valid RFC-5322 message Rspamd
// is willing to score. We avoid pulling in net/mail builders because
// the wire format is trivially small for our needs and we don't want
// to mask the actual subject / body when Rspamd parses headers.
//
// Every header value is fed through sanitiseHeaderValue() before being
// written into the byte buffer. That strips embedded CR / LF bytes so
// an attacker cannot smuggle additional headers (e.g.
// "X-Spamd-Result: default: True") through a maliciously crafted
// Sender / Recipient / Subject / MessageID. Ingestion is expected to
// normalise these upstream, but defending at the boundary is cheap
// and removes the assumption from the trust calculation.
func buildRawEmail(req dto.EvaluateRequest) []byte {
	var b bytes.Buffer
	if req.MessageID != "" {
		fmt.Fprintf(&b, "Message-ID: <%s>\r\n", sanitiseHeaderValue(req.MessageID))
	}
	if req.Sender != "" {
		fmt.Fprintf(&b, "From: %s\r\n", sanitiseHeaderValue(req.Sender))
	}
	if req.Recipient != "" {
		fmt.Fprintf(&b, "To: %s\r\n", sanitiseHeaderValue(req.Recipient))
	}
	// RFC 5322 §3.6.3: the Cc field is a single header whose value
	// is a comma-separated address-list. Emitting one Cc line per
	// address (as we did initially) is technically a multi-field
	// header and confuses some MTAs and Rspamd plugins that index
	// the first Cc only. Sanitise each address, drop empties, and
	// fold into one header line.
	if cc := joinCCAddresses(req.CC); cc != "" {
		fmt.Fprintf(&b, "Cc: %s\r\n", cc)
	}
	if req.Subject != "" {
		fmt.Fprintf(&b, "Subject: %s\r\n", sanitiseHeaderValue(req.Subject))
	}
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(req.Body)
	return b.Bytes()
}

// sanitiseHeaderValue strips CR and LF bytes from s so it can be
// safely interpolated into an RFC-5322 header line or a Go HTTP
// header value without enabling header-injection attacks. We
// deliberately replace with "" rather than " " to avoid silently
// joining tokens an attacker tried to split.
func sanitiseHeaderValue(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// joinCCAddresses sanitises every entry in addrs and joins the
// non-empty results with ", " so the caller can emit a single
// RFC-5322 Cc header. Returns "" when every entry is blank.
func joinCCAddresses(addrs []string) string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		s := sanitiseHeaderValue(a)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

// clampRspamdScore caps the score into a reasonable range. Rspamd's
// raw score is unbounded but in practice tops out around ±15. We
// clamp at [-50, 100] to keep the value tractable for the SN360
// aggregator without losing the extreme cases.
func clampRspamdScore(s float64) float64 {
	switch {
	case s < -50:
		return -50
	case s > 100:
		return 100
	default:
		return s
	}
}
