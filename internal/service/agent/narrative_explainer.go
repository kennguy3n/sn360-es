package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// NarrativeExplainer generates natural-language explanations for email
// verdicts. Implementations can be LLM-backed or deterministic.
type NarrativeExplainer interface {
	Explain(ctx context.Context, result dto.EvaluateResult, locale string) (string, error)
}

// Tier2ExplainerConfig wires the LLM-powered explainer.
type Tier2ExplainerConfig struct {
	// URL is the OpenAI-compatible chat completions endpoint.
	URL string
	// APIKey is sent as Bearer token when non-empty.
	APIKey string
	// Model identifier. Defaults to "ternary-bonsai-8b".
	Model string
	// Timeout per call. Defaults to 15s.
	Timeout time.Duration
	// MaxTokens caps response length. Defaults to 256.
	MaxTokens int
	// Temperature for sampling. Defaults to 0.3.
	Temperature float64
	// HTTPClient lets tests inject a custom transport.
	HTTPClient *http.Client
	// Logger for debug output.
	Logger *slog.Logger
}

// Tier2Explainer calls the Tier 2 SLM to produce locale-specific
// natural-language explanations for email verdicts.
type Tier2Explainer struct {
	url         string
	apiKey      string
	model       string
	timeout     time.Duration
	maxTokens   int
	temperature float64
	http        *http.Client
	log         *slog.Logger
}

// NewTier2Explainer validates config and returns a ready-to-use explainer.
func NewTier2Explainer(cfg Tier2ExplainerConfig) (*Tier2Explainer, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("narrative_explainer: URL is required")
	}
	if cfg.Model == "" {
		cfg.Model = "ternary-bonsai-8b"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 256
	}
	if cfg.Temperature < 0 {
		cfg.Temperature = 0.3
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Tier2Explainer{
		url:         strings.TrimRight(cfg.URL, "/"),
		apiKey:      cfg.APIKey,
		model:       cfg.Model,
		timeout:     cfg.Timeout,
		maxTokens:   cfg.MaxTokens,
		temperature: cfg.Temperature,
		http:        cfg.HTTPClient,
		log:         cfg.Logger,
	}, nil
}

// Explain generates a natural-language explanation for the verdict in
// the requested locale by prompting the Tier 2 SLM.
func (e *Tier2Explainer) Explain(ctx context.Context, result dto.EvaluateResult, locale string) (string, error) {
	if locale == "" {
		locale = "en"
	}

	prompt := buildExplanationPrompt(result, locale)

	reqBody := chatCompletionsRequest{
		Model:       e.model,
		Messages:    []chatMessage{{Role: "user", Content: prompt}},
		MaxTokens:   e.maxTokens,
		Temperature: e.temperature,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("narrative_explainer: marshal: %w", err)
	}

	rctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(rctx, http.MethodPost,
		e.url+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("narrative_explainer: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}

	resp, err := e.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("narrative_explainer: call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("narrative_explainer: status %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp chatCompletionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", fmt.Errorf("narrative_explainer: decode: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return "", errors.New("narrative_explainer: no choices returned")
	}

	explanation := strings.TrimSpace(chatResp.Choices[0].Message.Content)
	return explanation, nil
}

type chatCompletionsRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionsResponse struct {
	Choices []chatChoice `json:"choices"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

func buildExplanationPrompt(result dto.EvaluateResult, locale string) string {
	var b strings.Builder
	b.WriteString("You are an email security assistant. Explain the following email verdict to a non-technical user. ")
	b.WriteString(fmt.Sprintf("Generate your response ENTIRELY in the '%s' language (use the correct locale/dialect). ", locale))
	b.WriteString("Be concise (2-3 sentences), factual, and helpful. Do not invent details beyond what is given.\n\n")

	b.WriteString("Verdict details:\n")
	b.WriteString(fmt.Sprintf("- Tier: %s\n", result.Tier))
	b.WriteString(fmt.Sprintf("- Final score: %d/100\n", result.Score))

	if result.Primary != "" {
		b.WriteString(fmt.Sprintf("- Primary threat category: %s\n", result.Primary))
	}
	if len(result.ReasonCodes) > 0 {
		b.WriteString(fmt.Sprintf("- Reason codes: %s\n", strings.Join(result.ReasonCodes, ", ")))
	}
	if result.Degraded {
		b.WriteString("- Note: some detection services were unavailable during evaluation.\n")
	}

	b.WriteString("\nProvide a brief, clear explanation suitable for display in an email security banner.")
	return b.String()
}

// DeterministicExplainer wraps the existing catalog-based explanation
// logic as a NarrativeExplainer, providing a non-LLM fallback.
type DeterministicExplainer struct {
	Catalog *ExplanationCatalog
}

// Explain implements NarrativeExplainer using the deterministic catalog.
func (d *DeterministicExplainer) Explain(_ context.Context, result dto.EvaluateResult, locale string) (string, error) {
	return ExplainVerdictWith(d.Catalog, result, locale), nil
}

// FallbackExplainer tries the primary explainer first, falling back to
// the deterministic one on error.
type FallbackExplainer struct {
	Primary  NarrativeExplainer
	Fallback NarrativeExplainer
	Logger   *slog.Logger
}

// Explain implements NarrativeExplainer with fallback logic.
func (f *FallbackExplainer) Explain(ctx context.Context, result dto.EvaluateResult, locale string) (string, error) {
	if f.Primary != nil {
		text, err := f.Primary.Explain(ctx, result, locale)
		if err == nil && text != "" {
			return text, nil
		}
		if f.Logger != nil {
			f.Logger.WarnContext(ctx, "narrative_explainer: primary failed, using fallback",
				slog.Any("error", err))
		}
	}
	if f.Fallback != nil {
		return f.Fallback.Explain(ctx, result, locale)
	}
	return ExplainVerdict(result, locale), nil
}

// compile-time assertions
var (
	_ NarrativeExplainer = (*Tier2Explainer)(nil)
	_ NarrativeExplainer = (*DeterministicExplainer)(nil)
	_ NarrativeExplainer = (*FallbackExplainer)(nil)
)
