package evaluate

import (
	"net/http"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
	"github.com/kennguy3n/sn360-es/pkg/inference/slm/providers/ternarybonsai"
)

// Tier2HTTPConfig configures the historical Tier 2 HTTP client.
//
// As of WS-4c the underlying implementation lives in
// pkg/inference/slm/providers/ternarybonsai — this struct stays in
// the evaluate package as the back-compat construction surface so
// existing callers (cmd/sn360-es/app.go, integration tests, and the
// evaluate/tier2_http_test.go suite) keep compiling unchanged.
//
// New code that wires up Tier 2 SHOULD go through slm.New /
// slm.Router instead; this type is retained because the wire format
// it produces is identical to the ternarybonsai provider's wire
// format, and the in-package tests below assert details of that
// wire format directly.
type Tier2HTTPConfig struct {
	// URL is the base URL of the OpenAI-compatible server. Required.
	URL string
	// APIKey is sent as Bearer token when non-empty.
	APIKey string
	// Model is the model identifier sent in the chat request.
	// Defaults to ternarybonsai.DefaultModel.
	Model string
	// Timeout caps the per-call duration. Defaults to
	// ternarybonsai.DefaultTimeout.
	Timeout time.Duration
	// MaxTokens caps the response length. Defaults to
	// ternarybonsai.DefaultMaxTokens.
	MaxTokens int
	// Temperature controls sampling diversity. Defaults to
	// ternarybonsai.DefaultTemperature.
	Temperature float64
	// HTTPClient lets tests inject a custom transport.
	HTTPClient *http.Client
}

// Tier2HTTPClient is the historical alias for the Ternary-Bonsai
// SLM client. It is retained so existing call sites (composition
// root, integration tests, fallback wrapper) keep compiling
// unchanged. The underlying type is ternarybonsai.Client.
//
// New code SHOULD use ternarybonsai.NewClient directly (or, more
// commonly, go through slm.New + slm.Router so the deployment can
// swap providers via TIER2_PROVIDER).
type Tier2HTTPClient = ternarybonsai.Client

// NewTier2HTTPClient validates cfg and returns a ready-to-use
// Tier 2 client. It is a thin shim over ternarybonsai.NewClient
// that keeps the historical Tier2HTTPConfig field names so callers
// do not have to know about the package move.
func NewTier2HTTPClient(cfg Tier2HTTPConfig) (*Tier2HTTPClient, error) {
	return ternarybonsai.NewClient(ternarybonsai.Config{
		URL:         cfg.URL,
		APIKey:      cfg.APIKey,
		Model:       cfg.Model,
		Timeout:     cfg.Timeout,
		MaxTokens:   cfg.MaxTokens,
		Temperature: cfg.Temperature,
		HTTPClient:  cfg.HTTPClient,
	})
}

// The remaining symbols in this file are package-private aliases
// kept ONLY for the in-package tier2_http_test.go test suite. They
// MUST NOT be referenced by other production code in the evaluate
// package; new call sites that need these types should import the
// slm package directly.

// tier2ChatRequest is an alias for slm.ChatRequest. Kept private
// so the alias does not leak out of the evaluate package.
type tier2ChatRequest = slm.ChatRequest

// tier2ChatMessage is an alias for slm.ChatMessage.
type tier2ChatMessage = slm.ChatMessage

// tier2Verdict is an alias for slm.Verdict.
type tier2Verdict = slm.Verdict

// tier2ChatResponse mirrors the historical anonymous-struct response
// shape the test fixtures construct. We keep it as a concrete (not
// aliased) type because the test files build it with a positional
// anonymous-struct literal, which Go does not allow against a type
// alias whose target is a named struct.
type tier2ChatResponse struct {
	Choices []struct {
		Message tier2ChatMessage `json:"message"`
	} `json:"choices"`
}

// parseTier2Verdict forwards to slm.ParseVerdict so the in-package
// tests can exercise the parser through the historical name.
func parseTier2Verdict(content string) (tier2Verdict, error) {
	return slm.ParseVerdict(content)
}

// clampTier2Score forwards to slm.ClampScore.
//
// layout. New evaluator code clamps through slm.ClampScore.
//
//nolint:unused // Retained for ABI parity with the previous file
func clampTier2Score(s int) int { return slm.ClampScore(s) }

// clampConfidence forwards to slm.ClampConfidence.
//
// layout. New evaluator code clamps through slm.ClampConfidence.
//
//nolint:unused // Retained for ABI parity with the previous file
func clampConfidence(c float64) float64 { return slm.ClampConfidence(c) }

// mapTier2Categories forwards to slm.MapCategories.
//
// layout. New evaluator code maps through slm.MapCategories.
//
//nolint:unused // Retained for ABI parity with the previous file
func mapTier2Categories(raw []string) []constant.Category { return slm.MapCategories(raw) }
