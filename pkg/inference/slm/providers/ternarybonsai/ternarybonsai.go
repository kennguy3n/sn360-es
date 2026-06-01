// Package ternarybonsai implements the Tier 2 SLM client for the
// kennguy3n/llama.cpp "Ternary-Bonsai-8B" self-hosted server.
//
// This is the deployment default — every preceding evaluator
// release shipped a hard-coded Ternary-Bonsai HTTP client; the
// abstraction in pkg/inference/slm splits that client out into a
// registered provider so we can swap in alternative SLMs (llama-
// server, vLLM, Bedrock, etc.) via config alone.
//
// The wire format is strictly OpenAI chat-completions
// (POST /v1/chat/completions) with response_format=json_object so
// the model emits a parseable Verdict. Auth is a Bearer token (most
// local Ternary-Bonsai deployments leave the API key empty).
package ternarybonsai

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
	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
)

// Name is the registry key for this provider. Exported so the
// composition root can reference it without a string literal.
const Name = "ternarybonsai"

// DefaultModel matches the model identifier the Ternary-Bonsai
// server registers under at boot. Used when ProviderConfig.Model
// is empty so existing AI_URL deployments do not need to set
// TIER2_PROVIDER_OPTS.
const DefaultModel = "ternary-bonsai-8b"

// DefaultTimeout matches the historical Tier2HTTPClient default
// (30s). Tier 2 is the slowest stage in the pipeline; under-budget
// timeouts here cause spurious circuit-breaker trips that drive
// the evaluator onto fallback for healthy traffic.
const DefaultTimeout = 30 * time.Second

// DefaultMaxTokens is the response budget for the Verdict JSON.
// 512 is generous — a typical verdict is <200 tokens; the buffer
// allows for long explanations without truncating the closing
// brace.
const DefaultMaxTokens = 512

// DefaultTemperature is the deterministic-classifier setting. A
// non-zero value (rather than literal 0) keeps the model from
// collapsing onto a single category in adversarial edge cases
// where every category is plausible.
const DefaultTemperature = 0.1

// Config configures the Ternary-Bonsai client. The shape is kept
// public so the back-compat shim in internal/service/evaluate
// (Tier2HTTPConfig type alias) preserves the old API without
// dragging a private struct through the alias boundary.
type Config struct {
	URL       string
	APIKey    string
	Model     string
	Timeout   time.Duration
	MaxTokens int
	// Temperature is *float64 so the caller can distinguish
	// "unset, use DefaultTemperature" (nil) from "explicitly
	// chose 0.0 for greedy argmax sampling" (non-nil pointer to
	// 0). See pkg/inference/slm/config.go ProviderConfig.Temperature
	// for the rationale.
	Temperature *float64
	// HTTPClient lets tests inject a custom transport. Defaults
	// to a freshly constructed http.Client with the configured
	// Timeout.
	HTTPClient *http.Client
}

// Client implements slm.Client against an OpenAI-compatible chat-
// completions endpoint. Safe for concurrent use across goroutines
// — http.Client and the immutable config fields are the only
// shared state.
type Client struct {
	url         string
	apiKey      string
	model       string
	timeout     time.Duration
	maxTokens   int
	temperature float64
	http        *http.Client
}

// NewClient validates cfg and returns a ready-to-use client.
// Returns an error for invalid configuration (empty URL) so a
// misconfigured boot fails loudly. All other fields apply their
// documented defaults when zero.
func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("ternarybonsai: URL is required")
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
	temperature := DefaultTemperature
	if cfg.Temperature != nil {
		temperature = *cfg.Temperature
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{
		url:         strings.TrimRight(cfg.URL, "/"),
		apiKey:      cfg.APIKey,
		model:       cfg.Model,
		timeout:     cfg.Timeout,
		maxTokens:   cfg.MaxTokens,
		temperature: temperature,
		http:        cfg.HTTPClient,
	}, nil
}

// Evaluate implements slm.Client. Returns a structured outcome on
// success, or an error when the call fails / the response cannot
// be parsed. Latency is wall-clock and includes both HTTP RTT and
// model inference time.
func (c *Client) Evaluate(ctx context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	if c == nil {
		return dto.Tier2Outcome{}, errors.New("ternarybonsai: client is nil")
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
		return dto.Tier2Outcome{}, fmt.Errorf("ternarybonsai: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(rctx, http.MethodPost,
		c.url+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("ternarybonsai: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	start := time.Now()
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("ternarybonsai: do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// Drain a bounded prefix of the body so operators see the
		// llama.cpp error envelope (e.g. {"error":{"message":...}})
		// instead of a bare status code. Cap the read so a
		// misbehaving server cannot bloat error messages with a
		// multi-MB payload.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		snippet := strings.TrimSpace(string(body))
		if snippet == "" {
			return dto.Tier2Outcome{}, fmt.Errorf("ternarybonsai: HTTP %d", resp.StatusCode)
		}
		return dto.Tier2Outcome{}, fmt.Errorf("ternarybonsai: HTTP %d: %s", resp.StatusCode, snippet)
	}

	var parsed slm.ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("ternarybonsai: decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return dto.Tier2Outcome{}, fmt.Errorf("ternarybonsai: %w", slm.ErrEmptyResponse)
	}

	verdict, err := slm.ParseVerdict(parsed.Choices[0].Message.Content)
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("ternarybonsai: %w", err)
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

// Factory adapts NewClient to the slm.Factory signature. Exported
// so the composition root (and tests) can construct a client by
// going through the same path as slm.New + registry, without
// importing the registry package.
func Factory(cfg slm.ProviderConfig) (slm.Client, error) {
	return NewClient(Config{
		URL:         cfg.URL,
		APIKey:      cfg.APIKey,
		Model:       cfg.Model,
		Timeout:     cfg.Timeout,
		MaxTokens:   cfg.MaxTokens,
		Temperature: cfg.Temperature,
	})
}

// init registers the Ternary-Bonsai factory under the "ternarybonsai"
// name. The slm.Register call panics on duplicate registration, so a
// blank import collision is caught at boot.
func init() {
	slm.Register(Name, Factory)
}
