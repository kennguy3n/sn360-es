// Package httpclient hosts the SN360-ES persistent HTTP/2 client used by
// every outbound integration (VirusTotal, ClamAV, encoder inference, LLM
// gateway, Rspamd HTTP API, Microsoft Graph, Google Workspace).
//
// The client wraps net/http with:
//
//   - HTTP/2 forced via http2.ConfigureTransport so multiplexed
//     connections are reused under load
//   - A bounded connection pool with idle-conn TTL so dead peers do not
//     hold sockets indefinitely
//   - Per-call timeouts that compose with the caller's context
//   - Exponential-backoff retries scoped to idempotent verbs
//   - A circuit breaker around the underlying transport so a
//     misbehaving upstream cannot pin every goroutine
//
// The package is dependency-free except for golang.org/x/net/http2 which
// is already required by NATS/redis transitively, so it pulls no new
// surface into the service binary.
package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Config configures a Client. Zero-valued fields fall back to defaults.
type Config struct {
	// Name is a human-readable identifier (used in error messages and
	// metric labels). Required.
	Name string

	// BaseURL is prepended to relative request paths when callers use
	// [Client.Do] with a relative URL.
	BaseURL string

	// Timeout is the per-request budget (dial + read + write + body).
	// Default: 10s.
	Timeout time.Duration

	// DialTimeout overrides the dialer timeout. Default: 5s.
	DialTimeout time.Duration

	// KeepAlive controls the TCP keepalive interval. Default: 30s.
	KeepAlive time.Duration

	// IdleConnTimeout controls how long an idle conn lingers in the
	// pool. Default: 90s.
	IdleConnTimeout time.Duration

	// MaxIdleConns is the global cap on idle conns. Default: 100.
	MaxIdleConns int

	// MaxIdleConnsPerHost caps idle conns per host. Default: 16.
	MaxIdleConnsPerHost int

	// MaxConnsPerHost caps the *total* (idle + active) conns per host.
	// 0 = unbounded. Default: 64.
	MaxConnsPerHost int

	// MaxRetries is the number of retry attempts for idempotent
	// failures. Default: 2 (so each call makes at most 3 attempts).
	MaxRetries int

	// RetryBaseDelay is the first retry backoff. Each subsequent retry
	// doubles. Default: 100ms.
	RetryBaseDelay time.Duration

	// CircuitFailureThreshold is the consecutive-failure count that
	// trips the breaker. 0 disables the breaker. Default: 5.
	CircuitFailureThreshold int

	// CircuitOpenTimeout is how long the breaker stays open before
	// allowing a half-open trial request. Default: 30s.
	CircuitOpenTimeout time.Duration

	// InsecureSkipVerify disables TLS cert verification (test only).
	InsecureSkipVerify bool

	// UserAgent is sent on every request. Default: "sn360-es/1.0".
	UserAgent string
}

func (c Config) defaulted() Config {
	if c.Name == "" {
		c.Name = "httpclient"
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.KeepAlive == 0 {
		c.KeepAlive = 30 * time.Second
	}
	if c.IdleConnTimeout == 0 {
		c.IdleConnTimeout = 90 * time.Second
	}
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = 100
	}
	if c.MaxIdleConnsPerHost == 0 {
		c.MaxIdleConnsPerHost = 16
	}
	if c.MaxConnsPerHost == 0 {
		c.MaxConnsPerHost = 64
	}
	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	} else if c.MaxRetries == 0 {
		c.MaxRetries = 2
	}
	if c.RetryBaseDelay == 0 {
		c.RetryBaseDelay = 100 * time.Millisecond
	}
	if c.CircuitFailureThreshold == 0 {
		c.CircuitFailureThreshold = 5
	}
	if c.CircuitOpenTimeout == 0 {
		c.CircuitOpenTimeout = 30 * time.Second
	}
	if c.UserAgent == "" {
		c.UserAgent = "sn360-es/1.0"
	}
	return c
}

// Client is a resilient HTTP/2 client. It is safe for concurrent use.
type Client struct {
	cfg     Config
	httpDo  func(*http.Request) (*http.Response, error)
	breaker *breaker
	closer  func()
}

// New constructs a Client. The underlying transport is wired for HTTP/2
// with connection pooling tuned for the SN360-ES workload.
func New(cfg Config) (*Client, error) {
	cfg = cfg.defaulted()
	if cfg.MaxRetries > 16 {
		return nil, errors.New("httpclient: MaxRetries unreasonably high")
	}
	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: cfg.KeepAlive,
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.DialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // intentional knob for tests
		},
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, fmt.Errorf("httpclient: configure http/2: %w", err)
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}
	return &Client{
		cfg:    cfg,
		httpDo: httpClient.Do,
		breaker: newBreaker(
			cfg.CircuitFailureThreshold,
			cfg.CircuitOpenTimeout,
		),
		closer: transport.CloseIdleConnections,
	}, nil
}

// FromHTTPClient wraps an existing *http.Client. Useful in tests where
// the test fixture provides its own transport (e.g. httptest.Server).
func FromHTTPClient(name string, hc *http.Client, opts ...Option) *Client {
	cfg := Config{Name: name}
	for _, o := range opts {
		o(&cfg)
	}
	cfg = cfg.defaulted()
	return &Client{
		cfg:    cfg,
		httpDo: hc.Do,
		breaker: newBreaker(
			cfg.CircuitFailureThreshold,
			cfg.CircuitOpenTimeout,
		),
		closer: func() {
			if t, ok := hc.Transport.(interface{ CloseIdleConnections() }); ok {
				t.CloseIdleConnections()
			}
		},
	}
}

// Option mutates a Config (used by FromHTTPClient).
type Option func(*Config)

// WithMaxRetries overrides the retry budget.
func WithMaxRetries(n int) Option { return func(c *Config) { c.MaxRetries = n } }

// WithRetryBaseDelay overrides the base retry delay.
func WithRetryBaseDelay(d time.Duration) Option { return func(c *Config) { c.RetryBaseDelay = d } }

// WithBaseURL overrides the base URL.
func WithBaseURL(s string) Option { return func(c *Config) { c.BaseURL = s } }

// WithUserAgent overrides the User-Agent header.
func WithUserAgent(s string) Option { return func(c *Config) { c.UserAgent = s } }

// WithCircuit overrides the breaker thresholds.
func WithCircuit(threshold int, openTimeout time.Duration) Option {
	return func(c *Config) {
		c.CircuitFailureThreshold = threshold
		c.CircuitOpenTimeout = openTimeout
	}
}

// Name returns the client's configured name.
func (c *Client) Name() string { return c.cfg.Name }

// Close releases idle connections.
func (c *Client) Close() {
	if c.closer != nil {
		c.closer()
	}
}

// CircuitState reports the current breaker state.
func (c *Client) CircuitState() State { return c.breaker.stateForRead() }

// Do executes req with retry + circuit-breaker semantics.
//
// Retries are only applied to idempotent verbs (GET / HEAD / PUT / DELETE
// / OPTIONS) and to network-level / 5xx responses. Callers that need
// retry on POST should set req.GetBody.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if !c.breaker.allow() {
		return nil, &Error{Op: "request", URL: req.URL.String(), Status: 0, Cause: ErrCircuitOpen}
	}
	if c.cfg.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}

	idempotent := isIdempotent(req)
	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt > 0 {
			delay := c.cfg.RetryBaseDelay << (attempt - 1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("httpclient: rewind body: %w", err)
				}
				req.Body = body
			}
		}
		reqWithCtx := req.WithContext(ctx)
		resp, err := c.httpDo(reqWithCtx)
		if err != nil {
			lastErr = err
			c.breaker.failure()
			if !idempotent {
				return nil, &Error{Op: "request", URL: req.URL.String(), Cause: err}
			}
			continue
		}
		if resp.StatusCode >= 500 && idempotent && attempt < c.cfg.MaxRetries {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			c.breaker.failure()
			continue
		}
		if resp.StatusCode >= 500 {
			c.breaker.failure()
		} else {
			c.breaker.success()
		}
		return resp, nil
	}
	return nil, &Error{Op: "request", URL: req.URL.String(), Cause: lastErr}
}

func isIdempotent(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions:
		return true
	}
	// POST may carry GetBody for retry support; treat it as
	// idempotent only when the caller opted in.
	if req.Method == http.MethodPost && req.GetBody != nil {
		return true
	}
	return false
}

// --- breaker -------------------------------------------------------------

// State is the public state of the circuit breaker.
type State int32

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

// String renders a State for logs and tests.
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "closed"
	}
}

// breaker is a simple consecutive-failure circuit breaker.
//
// It transitions Closed -> Open after `threshold` consecutive failures.
// While Open it rejects every call until `timeout` elapses, after which
// the next call moves the breaker to Half-Open and is allowed through
// as a trial. A successful trial closes the breaker; a failed trial
// reopens it (and resets the cooldown).
type breaker struct {
	threshold    int32
	timeout      time.Duration
	mu           sync.Mutex
	failures     int32
	state        State
	openedAt     time.Time
	tripDisabled bool
}

func newBreaker(threshold int, timeout time.Duration) *breaker {
	b := &breaker{
		threshold: int32(threshold),
		timeout:   timeout,
		state:     StateClosed,
	}
	if threshold <= 0 {
		b.tripDisabled = true
	}
	return b
}

func (b *breaker) currentState() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// state is exposed so the public Client.CircuitState wrapper can read it.
func (b *breaker) stateForRead() State { return b.currentState() }

func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case StateClosed, StateHalfOpen:
		return true
	case StateOpen:
		if time.Since(b.openedAt) < b.timeout {
			return false
		}
		b.state = StateHalfOpen
		return true
	}
	return false
}

func (b *breaker) success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.state = StateClosed
}

func (b *breaker) failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tripDisabled {
		return
	}
	b.failures++
	if b.failures >= b.threshold || b.state == StateHalfOpen {
		b.state = StateOpen
		b.openedAt = time.Now()
	}
}

// --- errors --------------------------------------------------------------

// ErrCircuitOpen is returned (wrapped in [*Error]) when the breaker
// short-circuits a request.
var ErrCircuitOpen = errors.New("httpclient: circuit breaker open")

// Error is the typed error wrapper returned by Client.Do failures.
type Error struct {
	Op     string
	URL    string
	Status int
	Cause  error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		if e.Status != 0 {
			return fmt.Sprintf("httpclient: %s %s: status=%d: %v", e.Op, e.URL, e.Status, e.Cause)
		}
		return fmt.Sprintf("httpclient: %s %s: %v", e.Op, e.URL, e.Cause)
	}
	return fmt.Sprintf("httpclient: %s %s: status=%d", e.Op, e.URL, e.Status)
}

func (e *Error) Unwrap() error { return e.Cause }
