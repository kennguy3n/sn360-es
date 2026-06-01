// Package llamaserver implements the Tier 2 SLM client for a
// generic llama.cpp "llama-server" instance.
//
// llama-server exposes an OpenAI-compatible /v1/chat/completions
// endpoint but has historically deviated from the OpenAI spec in
// three ways we have to defend against:
//
//  1. Model name is path-shaped. The /models endpoint and the
//     response.model field surface the full filesystem path of the
//     GGUF file (e.g. "/models/llama-3-8b-instruct.Q4_K_M.gguf").
//     The Tier 2 telemetry expects a stable identifier — we strip
//     directory + extension before publishing so a model swap on
//     disk does not silently change the model_name attached to
//     every verdict.
//
//  2. Usage / token-count fields are missing in some builds. The
//     OpenAI spec requires "usage": { "prompt_tokens", ... } on
//     every response; llama-server omits it for several minor
//     versions (notably the b30xx series, which is still common in
//     production). Treating absent usage as an error would fail
//     every evaluation against an older server, so we tolerate it.
//
//  3. Auth header is optional and llama-server >= b3300 supports a
//     custom "X-API-Key" header in addition to the standard Bearer
//     token. We send Authorization: Bearer by default and let the
//     ProviderOpts knob "auth_header_name" override the header
//     name for deployments behind an API gateway that rewrites the
//     standard header.
//
// Everything else (prompt template, verdict parsing, category
// vocabulary) is shared with the other built-in providers via the
// slm package — the model variable is the only thing we want
// changing across providers.
package llamaserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
)

// Name is the registry key for this provider.
const Name = "llamaserver"

// Defaults document the historical llama-server timing budget. The
// 60s Timeout is wider than Ternary-Bonsai because llama-server
// frequently runs on CPU-only hosts (no GPU) where 8B-class
// inference latency can stretch into the high tens of seconds for
// long bodies even after our MaxUserPromptBodyBytes truncation.
const (
	DefaultModel       = "llama-server"
	DefaultTimeout     = 60 * time.Second
	DefaultMaxTokens   = 512
	DefaultTemperature = 0.1

	// DefaultAuthHeader is the header name we emit by default.
	// Override via ProviderOpts["auth_header_name"] for
	// deployments behind a gateway that rewrites Authorization.
	DefaultAuthHeader = "Authorization"

	// DefaultAuthScheme is the scheme prefix on the
	// Authorization header. Empty means "send the API key
	// verbatim" — used for llama-server >= b3300's X-API-Key
	// style where the header value is the key itself, no
	// "Bearer ".
	DefaultAuthScheme = "Bearer "
)

// Config configures the llama-server client.
type Config struct {
	URL       string
	APIKey    string
	Model     string
	Timeout   time.Duration
	MaxTokens int
	// Temperature is *float64 so the caller can distinguish
	// "unset, use DefaultTemperature" (nil) from "explicitly
	// chose 0.0" (non-nil pointer to 0). See
	// pkg/inference/slm/config.go ProviderConfig.Temperature.
	Temperature *float64
	HTTPClient  *http.Client

	// AuthHeader names the header used for API-key auth. Defaults
	// to "Authorization". Useful when llama-server sits behind a
	// reverse proxy that rewrites Authorization (e.g. an
	// AWS ALB that injects its own AWS_SIGV4 Authorization).
	AuthHeader string

	// AuthScheme is the prefix prepended to APIKey when
	// constructing the AuthHeader value. Defaults to "Bearer ".
	// Set to "" to send APIKey verbatim (X-API-Key style).
	AuthScheme string
}

// Client implements slm.Client against a llama-server instance.
type Client struct {
	url         string
	apiKey      string
	model       string
	timeout     time.Duration
	maxTokens   int
	temperature float64
	authHeader  string
	authScheme  string
	http        *http.Client
}

// NewClient validates cfg and returns a ready-to-use client.
func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("llamaserver: URL is required")
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
	if cfg.AuthHeader == "" {
		cfg.AuthHeader = DefaultAuthHeader
	}
	// AuthScheme is intentionally allowed to be "" so callers can
	// opt into X-API-Key style auth. We can't distinguish "unset"
	// from "deliberately empty" with a plain string, so we use a
	// constant default only when the header is the default too —
	// callers overriding the header are presumed to have a reason
	// to also override the scheme.
	if cfg.AuthScheme == "" && cfg.AuthHeader == DefaultAuthHeader {
		cfg.AuthScheme = DefaultAuthScheme
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
		authHeader:  cfg.AuthHeader,
		authScheme:  cfg.AuthScheme,
		http:        cfg.HTTPClient,
	}, nil
}

// llamaChatResponse extends slm.ChatResponse with the llama-server-
// specific fields we want to surface (model). Token-count fields
// are deliberately omitted: in newer llama-server builds they live
// under "usage", and consuming code does not need them — the
// evaluator computes wall-clock latency itself.
type llamaChatResponse struct {
	slm.ChatResponse
	// Model is the path-shaped identifier llama-server echoes in
	// the response. We use it (when present) to derive a stable
	// model_name for the verdict, with the configured model as a
	// fallback.
	Model string `json:"model,omitempty"`
}

// Evaluate implements slm.Client.
func (c *Client) Evaluate(ctx context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	if c == nil {
		return dto.Tier2Outcome{}, errors.New("llamaserver: client is nil")
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
		return dto.Tier2Outcome{}, fmt.Errorf("llamaserver: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(rctx, http.MethodPost,
		c.url+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("llamaserver: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set(c.authHeader, c.authScheme+c.apiKey)
	}

	start := time.Now()
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("llamaserver: do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		snippet := strings.TrimSpace(string(bodyBytes))
		if snippet == "" {
			return dto.Tier2Outcome{}, fmt.Errorf("llamaserver: HTTP %d", resp.StatusCode)
		}
		return dto.Tier2Outcome{}, fmt.Errorf("llamaserver: HTTP %d: %s", resp.StatusCode, snippet)
	}

	var parsed llamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("llamaserver: decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return dto.Tier2Outcome{}, fmt.Errorf("llamaserver: %w", slm.ErrEmptyResponse)
	}

	verdict, err := slm.ParseVerdict(parsed.Choices[0].Message.Content)
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("llamaserver: %w", err)
	}

	out := dto.Tier2Outcome{
		Score:       slm.ClampScore(verdict.Score),
		Categories:  slm.MapCategories(verdict.Categories),
		Explanation: strings.TrimSpace(verdict.Explanation),
		Confidence:  slm.ClampConfidence(verdict.Confidence),
		ModelName:   pickModelName(parsed.Model, c.model),
		LatencyMs:   time.Since(start).Milliseconds(),
	}
	return out, nil
}

// pickModelName derives a stable, telemetry-friendly model
// identifier from the path-shaped name llama-server returns. When
// the response carries no model field we fall back to the
// configured value.
//
// The transform is: take the last path component, strip the
// extension. So:
//
//	/models/llama-3-8b-instruct.Q4_K_M.gguf
//	→ llama-3-8b-instruct.Q4_K_M
//
// We leave inner dots intact so quantisation tag (Q4_K_M, Q5_1)
// is still visible in metrics — it is genuinely useful operator
// information when comparing model quality across quant tiers.
//
// If responseModel is empty the configured Model is returned
// verbatim, ensuring every verdict has a non-empty ModelName.
func pickModelName(responseModel, configured string) string {
	responseModel = strings.TrimSpace(responseModel)
	if responseModel == "" {
		return configured
	}
	base := filepath.Base(responseModel)
	if ext := filepath.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" || base == "." || base == "/" {
		return configured
	}
	return base
}

// Factory adapts NewClient to the slm.Factory signature. Honours
// the documented ProviderOpts keys:
//   - "auth_header_name"  → Config.AuthHeader (default Authorization)
//   - "auth_header_scheme" → Config.AuthScheme (default "Bearer ")
//
// Unknown keys are ignored so a deployment can carry forward
// future tuning knobs without breaking the boot.
func Factory(cfg slm.ProviderConfig) (slm.Client, error) {
	authHeader := DefaultAuthHeader
	authScheme := DefaultAuthScheme
	if v, ok := cfg.ProviderOpts["auth_header_name"]; ok && v != "" {
		authHeader = v
		// If the caller overrode the header, default scheme is
		// "" (X-API-Key style) unless they ALSO supply
		// auth_header_scheme.
		authScheme = ""
	}
	if v, ok := cfg.ProviderOpts["auth_header_scheme"]; ok {
		authScheme = v
	}
	return NewClient(Config{
		URL:         cfg.URL,
		APIKey:      cfg.APIKey,
		Model:       cfg.Model,
		Timeout:     cfg.Timeout,
		MaxTokens:   cfg.MaxTokens,
		Temperature: cfg.Temperature,
		AuthHeader:  authHeader,
		AuthScheme:  authScheme,
	})
}

func init() {
	slm.Register(Name, Factory)
}
