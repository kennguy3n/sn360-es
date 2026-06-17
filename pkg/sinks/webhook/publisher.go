package webhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// DefaultPublishTimeout is the per-request timeout the dispatcher
// applies when no caller-supplied context deadline is shorter.
// 5 seconds matches the fan-out budget documented in the WS-5B.2
// scope (consumers_action handle path is best-effort and the
// per-sink call must not stall the verdict's publish path).
const DefaultPublishTimeout = 5 * time.Second

// PublishOutcome is the closed set of dispatch outcomes the
// per-sink Publisher reports to the dispatcher.
type PublishOutcome int

const (
	// OutcomeUnknown is the zero value; callers should never see
	// this — Publish either returns one of the explicit outcomes
	// or an error.
	OutcomeUnknown PublishOutcome = iota
	// OutcomeSuccess: the customer endpoint returned 2xx.
	OutcomeSuccess
	// OutcomePermanentFailure: the customer endpoint returned
	// 4xx (other than 408 / 429 — those are retriable). The
	// dispatcher records a `dispatch_failed` audit row and
	// drops the event — replaying a 4xx is unlikely to succeed.
	OutcomePermanentFailure
	// OutcomeRetriable: 5xx, 408, 429, network error, timeout.
	// The dispatcher hands the request envelope to the DLQ
	// consumer.
	OutcomeRetriable
)

// String makes PublishOutcome useful in log fields and tests.
func (o PublishOutcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "success"
	case OutcomePermanentFailure:
		return "permanent_failure"
	case OutcomeRetriable:
		return "retriable"
	default:
		return "unknown"
	}
}

// PublishResult carries the per-publish observables the dispatcher
// needs to decide how to route the next attempt and what to record
// in the audit trail.
type PublishResult struct {
	Outcome    PublishOutcome
	HTTPStatus int
	// LatencyMS is the end-to-end wall-clock from "POST issued"
	// to "response body closed" — useful for the dispatcher's
	// metrics.
	LatencyMS int64
	// Cause is a short, no-secrets, no-PII string for the audit
	// trail. e.g. "http 503: service unavailable" or
	// "timeout after 5s". NEVER contains hmac_secret or any of
	// the request body.
	Cause string
}

// Request is the wire envelope the dispatcher constructs and the
// DLQ consumer replays. Carrying the formatted body + headers +
// secret-ciphertext means a retried delivery can be reconstituted
// without re-formatting and without re-decrypting the secret
// unless the dispatch loop chooses to (the retry path always
// re-decrypts because the AES envelope rotates regularly).
type Request struct {
	SinkID     string
	TenantID   string
	SinkName   string
	URL        string
	Format     repository.WebhookSinkFormat
	Body       []byte
	Signature  string
	EventType  string
	EventID    string
	OccurredAt time.Time
	// Attempt is the 1-based attempt counter the dispatcher
	// stamps into the envelope. The DLQ consumer increments it
	// per retry; the final-fail handler stamps the audit row's
	// dedup_id as sha256(sink_id|event_id|attempt) so re-deliveries
	// of the same final-fail collapse to one audit row.
	Attempt int
}

// Publisher posts a Request to the customer endpoint, classifies
// the response into a PublishOutcome, and returns the
// PublishResult.
//
// Concrete implementations are provided by HTTPPublisher (real
// net/http) and the test helpers; the interface lets the dispatcher
// be unit-tested with a mock that returns a scripted outcome
// without spinning up an httptest.Server.
type Publisher interface {
	Publish(ctx context.Context, req *Request) (PublishResult, error)
}

// HTTPPublisher is the production implementation.
type HTTPPublisher struct {
	Client *http.Client
	// MaxResponseBodyBytes caps how much of the customer's
	// response body the dispatcher reads into the audit trail's
	// Cause string. Some SIEMs return verbose JSON errors;
	// reading them all would let a misbehaving customer endpoint
	// fill the audit table. Default: 512 bytes.
	MaxResponseBodyBytes int64
	// UserAgent is the User-Agent header. Default:
	// "sn360-es-webhook/1.0".
	UserAgent string
}

// HTTPPublisherConfig wires an HTTPPublisher. Every field is
// optional: leave them at zero values for the production defaults
// (5s timeout, 512-byte response cap, "sn360-es-webhook/1.0"
// User-Agent).
type HTTPPublisherConfig struct {
	// Timeout is the per-request http.Client timeout. <= 0 means
	// DefaultPublishTimeout.
	Timeout time.Duration
	// MaxResponseBodyBytes caps the response body read for the
	// audit Cause string. <= 0 means 512.
	MaxResponseBodyBytes int64
	// UserAgent overrides the default User-Agent header.
	UserAgent string
	// Client lets a caller (typically tests) supply a custom
	// http.Client — e.g. one with a captured Transport. When
	// nil, a fresh client is built with Timeout.
	Client *http.Client
	// AllowPrivateDestinations disables the dial-time SSRF guard so
	// the publisher may POST to private/loopback/link-local IPs. It
	// is the operator escape hatch for a deployment that legitimately
	// ships verdicts to a private SIEM with no public ingress.
	// Default (false) blocks non-public destinations.
	//
	// Only consulted when Client is nil; a caller wiring its own
	// http.Client is responsible for its own dial guard.
	AllowPrivateDestinations bool
	// AllowedDestinationCIDRs narrows the escape hatch: even with the
	// guard active, destinations inside these prefixes are permitted.
	// Only consulted when Client is nil and AllowPrivateDestinations
	// is false.
	AllowedDestinationCIDRs []netip.Prefix
}

// NewHTTPPublisher wires an HTTPPublisher with sensible defaults.
// The http.Client is constructed once per dispatcher so connection
// reuse across sinks is possible.
func NewHTTPPublisher(cfg ...HTTPPublisherConfig) *HTTPPublisher {
	var c HTTPPublisherConfig
	if len(cfg) > 0 {
		c = cfg[0]
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultPublishTimeout
	}
	body := c.MaxResponseBodyBytes
	if body <= 0 {
		body = 512
	}
	ua := c.UserAgent
	if ua == "" {
		ua = "sn360-es-webhook/1.0"
	}
	client := c.Client
	if client == nil {
		// SSRF defense-in-depth: refuse to follow redirects. The
		// validateWebhookURL gate (handler) and migration 0025's
		// CHECK constraint both enforce https:// on the INITIAL URL
		// stored against the sink, but Go's default redirect policy
		// would follow up to 10 redirects on POST — and a 307/308
		// from the customer's HTTPS endpoint to an http:// (or
		// link-local) target would resend the X-SN360-Signature
		// header AND the full POST body (the evaluation verdict)
		// in plaintext, defeating the HTTPS-only invariant. With
		// ErrUseLastResponse, the 3xx surfaces as the response and
		// Publish classifies any 3xx as PermanentFailure (with the
		// Location echoed into the audit Cause) so the operator
		// sees "fix your URL" on the first dispatch_failed row
		// rather than after the DLQ burns through 5 retries. A
		// caller wiring a custom http.Client (tests) is responsible
		// for the equivalent guard.
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		// SSRF dial-time guard: unless the operator has opted into
		// private destinations, install a Control hook that refuses
		// to connect to non-public IPs. This runs after DNS
		// resolution on the concrete target IP, so it also defeats
		// DNS-rebinding (a hostname that validates as public but
		// resolves to 169.254.169.254 / 127.0.0.1 / an RFC1918 host
		// at dial time). Cloning DefaultTransport preserves the
		// stdlib's proxy, TLS, idle-conn and HTTP/2 defaults.
		if !c.AllowPrivateDestinations {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			guard := NewSSRFGuard(false, c.AllowedDestinationCIDRs)
			transport.DialContext = (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
				Control:   guard.Control,
			}).DialContext
			client.Transport = transport
		}
	}
	return &HTTPPublisher{
		Client:               client,
		MaxResponseBodyBytes: body,
		UserAgent:            ua,
	}
}

// Publish implements Publisher.
func (p *HTTPPublisher) Publish(ctx context.Context, req *Request) (PublishResult, error) {
	if req == nil {
		return PublishResult{}, errors.New("webhook: nil publish request")
	}
	if req.URL == "" {
		return PublishResult{}, errors.New("webhook: empty url")
	}
	if !strings.HasPrefix(strings.ToLower(req.URL), "https://") {
		return PublishResult{}, fmt.Errorf("webhook: url must be https: %q", req.URL)
	}
	if len(req.Body) == 0 {
		return PublishResult{}, errors.New("webhook: empty body")
	}
	if req.Signature == "" {
		return PublishResult{}, errors.New("webhook: missing signature")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return PublishResult{
			Outcome: OutcomeRetriable,
			Cause:   "build request: " + err.Error(),
		}, err
	}
	httpReq.Header.Set("Content-Type", ContentTypeForFormat(req.Format))
	httpReq.Header.Set(SignatureHeader, req.Signature)
	httpReq.Header.Set(EventTypeHeader, req.EventType)
	httpReq.Header.Set("User-Agent", p.userAgent())
	if req.EventID != "" {
		httpReq.Header.Set("X-SN360-Event-Id", req.EventID)
	}
	if req.Attempt > 0 {
		httpReq.Header.Set("X-SN360-Attempt", fmt.Sprintf("%d", req.Attempt))
	}

	started := time.Now()
	resp, err := p.client().Do(httpReq)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		// Distinguish context deadline from a network error so
		// the dispatcher can put a clean cause string on the
		// audit row.
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return PublishResult{
				Outcome:   OutcomeRetriable,
				LatencyMS: latency,
				Cause:     "timeout",
			}, nil
		}
		return PublishResult{
			Outcome:   OutcomeRetriable,
			LatencyMS: latency,
			Cause:     "network: " + sanitiseError(err),
		}, nil
	}
	defer func() {
		// Drain so connection reuse stays cheap; ignore errors.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body := readCapped(resp.Body, p.maxBodyBytes())

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return PublishResult{
			Outcome:    OutcomeSuccess,
			HTTPStatus: resp.StatusCode,
			LatencyMS:  latency,
			Cause:      fmt.Sprintf("http %d", resp.StatusCode),
		}, nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// 3xx surfaces here only because we set CheckRedirect =
		// ErrUseLastResponse (see NewHTTPPublisher), which holds
		// the redirect chain at the customer endpoint instead of
		// silently re-POSTing the signed body to the Location
		// target. Treat it as a permanent failure with a clear
		// cause so the operator sees "fix your URL" on the first
		// dispatch_failed audit row rather than after the DLQ
		// burns through all 5 retries with the same outcome.
		return PublishResult{
			Outcome:    OutcomePermanentFailure,
			HTTPStatus: resp.StatusCode,
			LatencyMS:  latency,
			Cause:      fmt.Sprintf("http %d: redirect not followed (Location=%q)", resp.StatusCode, sanitiseLocation(resp.Header.Get("Location"))),
		}, nil
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests:
		// 408 / 429 → retriable. 429 specifically is the SIEM
		// telling us to back off; the DLQ exponential schedule
		// handles that.
		return PublishResult{
			Outcome:    OutcomeRetriable,
			HTTPStatus: resp.StatusCode,
			LatencyMS:  latency,
			Cause:      fmt.Sprintf("http %d: %s", resp.StatusCode, shortCause(body)),
		}, nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return PublishResult{
			Outcome:    OutcomePermanentFailure,
			HTTPStatus: resp.StatusCode,
			LatencyMS:  latency,
			Cause:      fmt.Sprintf("http %d: %s", resp.StatusCode, shortCause(body)),
		}, nil
	default:
		// 5xx and anything else → retriable.
		return PublishResult{
			Outcome:    OutcomeRetriable,
			HTTPStatus: resp.StatusCode,
			LatencyMS:  latency,
			Cause:      fmt.Sprintf("http %d: %s", resp.StatusCode, shortCause(body)),
		}, nil
	}
}

func (p *HTTPPublisher) client() *http.Client {
	if p == nil || p.Client == nil {
		return &http.Client{Timeout: DefaultPublishTimeout}
	}
	return p.Client
}

func (p *HTTPPublisher) userAgent() string {
	if p == nil || p.UserAgent == "" {
		return "sn360-es-webhook/1.0"
	}
	return p.UserAgent
}

func (p *HTTPPublisher) maxBodyBytes() int64 {
	if p == nil || p.MaxResponseBodyBytes <= 0 {
		return 512
	}
	return p.MaxResponseBodyBytes
}

// readCapped reads at most maxBytes from r and returns the (possibly
// truncated) bytes. Errors are swallowed because the body is only
// used for an audit-trail Cause field — we don't want a misbehaving
// customer endpoint to fail the dispatcher.
func readCapped(r io.Reader, maxBytes int64) []byte {
	buf, _ := io.ReadAll(io.LimitReader(r, maxBytes))
	return buf
}

// shortCause renders a customer-response-body excerpt for the
// audit row. Multi-line / non-printable bodies get collapsed to
// a single-line printable string.
func shortCause(body []byte) string {
	if len(body) == 0 {
		return "no body"
	}
	s := string(body)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	// Trim consecutive spaces.
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// sanitiseError redacts request URLs from net/http errors so the
// audit row doesn't leak the customer endpoint (which is
// authentication-grade material in some deployments).
func sanitiseError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// net/http stamps the URL into wrapping errors as `Post "url": ...`.
	if i := strings.Index(msg, `"`); i >= 0 {
		if j := strings.Index(msg[i+1:], `"`); j >= 0 {
			// Drop the URL — replace the quoted portion with `<redacted>`.
			msg = msg[:i] + `"<redacted>"` + msg[i+1+j+1:]
		}
	}
	if len(msg) > 240 {
		msg = msg[:240] + "..."
	}
	return msg
}

// isTimeout reports whether err is a net-package timeout error.
func isTimeout(err error) bool {
	type timeoutInterface interface{ Timeout() bool }
	var to timeoutInterface
	if errors.As(err, &to) {
		return to.Timeout()
	}
	return false
}

// sanitiseLocation trims and bounds the Location header value before
// it lands in the audit Cause. The header CAN contain an attacker-
// chosen URL when the customer endpoint is compromised, so we keep
// it short and strip ANSI / control characters that would mangle
// log readers. We deliberately do NOT validate it as a URL — the
// audit row's job is to record what the endpoint actually replied
// with, not to opine on its correctness.
func sanitiseLocation(loc string) string {
	if loc == "" {
		return ""
	}
	s := strings.ReplaceAll(loc, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		s = s[:256] + "..."
	}
	return s
}
