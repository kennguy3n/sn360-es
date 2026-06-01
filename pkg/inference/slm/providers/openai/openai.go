// Package openai implements a strict OpenAI-compatible Tier 2 SLM
// client. It is used as the canonical "external fallback" provider
// today and as a generic adapter for any OpenAI-spec endpoint
// (OpenAI itself, vLLM, Anthropic via openai-compat layer, Bedrock-
// OpenAI shim, Azure OpenAI, etc.).
//
// Strict means: the implementation FAILS LOUD when the response
// shape deviates from the OpenAI spec. Missing choices, missing
// content, malformed JSON in content — all return typed errors so
// the circuit breaker can route to the primary provider instead
// of silently emitting a zero verdict. This is the opposite of the
// llamaserver tolerance: when we are paying OpenAI per token, a
// malformed response is a billable failure and we want it visible.
//
// 429 (rate-limited) and 5xx responses are honoured with one
// bounded retry that respects the server's Retry-After header
// (RFC 7231 §7.1.3, supports both delta-seconds and HTTP-date).
// We retry once because doubling the per-call latency is the
// upper bound the Tier 2 timeout budget can absorb — beyond one
// retry the fallback circuit breaker should take over.
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
)

// Name is the registry key for this provider.
const Name = "openai"

// Defaults match the OpenAI hosted-service operational envelope.
// MaxRetries is configurable via ProviderOpts["max_retries"]; 1 is
// the production default — see package doc for the rationale.
const (
	DefaultModel       = "gpt-4o-mini"
	DefaultTimeout     = 30 * time.Second
	DefaultMaxTokens   = 512
	DefaultTemperature = 0.1
	DefaultMaxRetries  = 1
	// MaxRetryAfter caps the per-attempt Retry-After we honour.
	// A misbehaving server that advertises Retry-After: 86400
	// would otherwise stall the whole Tier 2 pipeline for a day;
	// we cap at 30s so the circuit breaker takes over on the
	// next consecutive failure instead.
	MaxRetryAfter = 30 * time.Second
)

// Config configures the OpenAI-compat client.
type Config struct {
	URL         string
	APIKey      string
	Model       string
	Timeout     time.Duration
	MaxTokens   int
	Temperature float64
	HTTPClient  *http.Client

	// MaxRetries caps the number of retries on 429 / 5xx. The
	// initial attempt is not counted, so MaxRetries=1 means
	// "one initial try + one retry on failure".
	MaxRetries int

	// Now is the clock used for HTTP-date Retry-After parsing.
	// Defaults to time.Now; tests override.
	Now func() time.Time

	// Sleep is the function used to wait between retries.
	// Defaults to a context-aware sleep; tests override to keep
	// runtime bounded.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Client implements slm.Client against an OpenAI-compat endpoint.
type Client struct {
	url         string
	apiKey      string
	model       string
	timeout     time.Duration
	maxTokens   int
	temperature float64
	maxRetries  int
	http        *http.Client
	now         func() time.Time
	sleep       func(ctx context.Context, d time.Duration) error
}

// NewClient validates cfg and returns a ready-to-use client.
func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("openai: URL is required")
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = DefaultMaxTokens
	}
	if cfg.Temperature <= 0 {
		cfg.Temperature = DefaultTemperature
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	} else if cfg.MaxRetries == 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = ctxSleep
	}
	return &Client{
		url:         strings.TrimRight(cfg.URL, "/"),
		apiKey:      cfg.APIKey,
		model:       cfg.Model,
		timeout:     cfg.Timeout,
		maxTokens:   cfg.MaxTokens,
		temperature: cfg.Temperature,
		maxRetries:  cfg.MaxRetries,
		http:        cfg.HTTPClient,
		now:         cfg.Now,
		sleep:       cfg.Sleep,
	}, nil
}

// Evaluate implements slm.Client. Strict parsing: any deviation
// from the OpenAI response shape returns a typed error.
func (c *Client) Evaluate(ctx context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	if c == nil {
		return dto.Tier2Outcome{}, errors.New("openai: client is nil")
	}
	rctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	chat := slm.ChatRequest{
		Model: c.model,
		Messages: []slm.ChatMessage{
			{Role: "system", Content: slm.SystemPrompt},
			{Role: "user", Content: slm.BuildUserPrompt(req, hint)},
		},
		Temperature: c.temperature,
		MaxTokens:   c.maxTokens,
		Response:    &slm.ResponseFormat{Type: "json_object"},
	}
	body, err := json.Marshal(chat)
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("openai: marshal request: %w", err)
	}

	start := time.Now()
	parsed, err := c.doWithRetry(rctx, body)
	if err != nil {
		return dto.Tier2Outcome{}, err
	}
	if len(parsed.Choices) == 0 {
		return dto.Tier2Outcome{}, fmt.Errorf("openai: %w (missing choices)", slm.ErrEmptyResponse)
	}
	content := parsed.Choices[0].Message.Content
	if strings.TrimSpace(content) == "" {
		return dto.Tier2Outcome{}, fmt.Errorf("openai: %w (empty content)", slm.ErrEmptyResponse)
	}

	verdict, err := slm.ParseVerdict(content)
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("openai: %w", err)
	}

	out := dto.Tier2Outcome{
		Score:       slm.ClampScore(verdict.Score),
		Categories:  slm.MapCategories(verdict.Categories),
		Explanation: strings.TrimSpace(verdict.Explanation),
		Confidence:  slm.ClampConfidence(verdict.Confidence),
		ModelName:   c.model,
		LatencyMs:   time.Since(start).Milliseconds(),
	}
	return out, nil
}

// doWithRetry issues the chat-completions request, honouring up to
// c.maxRetries retries on 429 / 5xx with Retry-After-aware backoff.
// Returns the decoded ChatResponse on 2xx.
//
// Non-retryable 4xx (400/401/403/404/etc.) returns immediately
// with a wrapped error so callers can distinguish a misconfigured
// model name (404) from a rate limit (429) for alerting.
func (c *Client) doWithRetry(ctx context.Context, body []byte) (*slm.ChatResponse, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return nil, fmt.Errorf("openai: %w (after %d attempts: %v)", ctx.Err(), attempt, lastErr)
			}
			return nil, fmt.Errorf("openai: %w", ctx.Err())
		default:
		}

		resp, err := c.doOnce(ctx, body)
		if err != nil {
			// Transport / network errors are retryable. Honour
			// the context budget — if the next attempt cannot
			// fit before the deadline, give up.
			lastErr = err
			if attempt == c.maxRetries {
				return nil, fmt.Errorf("openai: do request: %w", err)
			}
			if err := c.sleep(ctx, 100*time.Millisecond); err != nil {
				return nil, fmt.Errorf("openai: do request retry interrupted: %w", err)
			}
			continue
		}

		if resp.StatusCode/100 == 2 {
			parsed, decodeErr := decodeChatResponse(resp)
			// Body fully drained / decoded above; close errors here
			// cannot recover the request, so they are intentionally
			// swallowed (HTTP keep-alive will recycle the connection).
			_ = resp.Body.Close()
			if decodeErr != nil {
				return nil, fmt.Errorf("openai: decode response: %w", decodeErr)
			}
			return parsed, nil
		}

		// Non-2xx. Build a typed error so the caller can
		// distinguish 429 / 5xx / 4xx.
		snippet, retryAfter := readSnippetAndRetryAfter(resp, c.now)
		// Same rationale as the 2xx branch above.
		_ = resp.Body.Close()

		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			lastErr = &slm.RateLimitedError{
				StatusCode: resp.StatusCode,
				RetryAfter: retryAfter,
				Snippet:    snippet,
			}
		case resp.StatusCode >= 500:
			lastErr = &slm.ServerError{
				StatusCode: resp.StatusCode,
				RetryAfter: retryAfter,
				Snippet:    snippet,
			}
		default:
			// Non-retryable 4xx — return immediately with a
			// wrapped error.
			if snippet == "" {
				return nil, fmt.Errorf("openai: HTTP %d", resp.StatusCode)
			}
			return nil, fmt.Errorf("openai: HTTP %d: %s", resp.StatusCode, snippet)
		}

		if attempt == c.maxRetries {
			return nil, lastErr
		}

		wait := retryAfter
		if wait <= 0 {
			wait = 200 * time.Millisecond
		}
		if wait > MaxRetryAfter {
			wait = MaxRetryAfter
		}
		if err := c.sleep(ctx, wait); err != nil {
			return nil, fmt.Errorf("openai: retry interrupted: %w", err)
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("openai: retry loop exited without result")
}

// doOnce issues a single HTTP request. The caller is responsible
// for closing the response body.
func (c *Client) doOnce(ctx context.Context, body []byte) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.url+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	return c.http.Do(httpReq)
}

// decodeChatResponse decodes the response body into slm.ChatResponse.
// It is strict — a malformed JSON body returns an error rather than
// a zero-value struct, so the evaluator can surface the failure
// instead of silently scoring every message as 0.
func decodeChatResponse(resp *http.Response) (*slm.ChatResponse, error) {
	var parsed slm.ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	return &parsed, nil
}

// readSnippetAndRetryAfter reads a bounded prefix of the response
// body and parses the Retry-After header. Both delta-seconds (e.g.
// "30") and HTTP-date forms (e.g. "Fri, 31 Dec 1999 23:59:59 GMT")
// are supported, with the date form converted to a duration via
// the supplied now function.
//
// Returns retryAfter == 0 when the header is missing or malformed.
func readSnippetAndRetryAfter(resp *http.Response, now func() time.Time) (string, time.Duration) {
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	snippet := strings.TrimSpace(string(bodyBytes))

	raw := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if raw == "" {
		return snippet, 0
	}
	// delta-seconds (RFC 7231 §7.1.3): "Retry-After: 120"
	if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
		return snippet, time.Duration(secs) * time.Second
	}
	// HTTP-date form: "Retry-After: Fri, 31 Dec 1999 23:59:59 GMT"
	if t, err := http.ParseTime(raw); err == nil {
		d := t.Sub(now())
		if d > 0 {
			return snippet, d
		}
	}
	return snippet, 0
}

// ctxSleep blocks for d or returns when ctx is cancelled. Honouring
// context cancellation here is what lets a Tier 2 timeout fire
// mid-retry instead of stalling the evaluator past its budget.
func ctxSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Factory adapts NewClient to the slm.Factory signature. Honours
// the documented ProviderOpts keys:
//   - "max_retries" → Config.MaxRetries (default DefaultMaxRetries)
func Factory(cfg slm.ProviderConfig) (slm.Client, error) {
	maxRetries := 0 // sentinel "use default"
	if v, ok := cfg.ProviderOpts["max_retries"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("openai: invalid max_retries %q: %w", v, err)
		}
		if n < 0 {
			return nil, fmt.Errorf("openai: max_retries must be >= 0, got %d", n)
		}
		// 0 means "no retries", so we encode it as -1 → 0 below
		// to avoid colliding with the NewClient "use default"
		// sentinel.
		if n == 0 {
			maxRetries = -1
		} else {
			maxRetries = n
		}
	}
	return NewClient(Config{
		URL:         cfg.URL,
		APIKey:      cfg.APIKey,
		Model:       cfg.Model,
		Timeout:     cfg.Timeout,
		MaxTokens:   cfg.MaxTokens,
		Temperature: cfg.Temperature,
		MaxRetries:  maxRetries,
	})
}

func init() {
	slm.Register(Name, Factory)
}
