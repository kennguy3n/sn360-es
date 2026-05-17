package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/scripts/corpus_generator/templates"
)

// LLMClient is the OpenAI-compatible HTTP client that talks to the
// Ternary-Bonsai-8B server served by kennguy3n/llama.cpp at
// (defaults to) http://127.0.0.1:9000.
//
// Only the chat-completions endpoint is used. No other LLM provider
// or model is supported by design — the corpus must be reproducible
// against this exact runtime.
type LLMClient struct {
	BaseURL string
	HTTP    *http.Client
	Model   string
	Timeout time.Duration
}

// NewLLMClient returns a client pointing at baseURL.
func NewLLMClient(baseURL string) *LLMClient {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:9000"
	}
	return &LLMClient{
		BaseURL: baseURL,
		Model:   "ternary-bonsai-8b",
		Timeout: 45 * time.Second,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

// chatRequest is a minimal subset of the OpenAI /v1/chat/completions
// payload that the kennguy3n/llama.cpp server exposes.
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens"`
	ResponseFmt struct {
		Type string `json:"type"`
	} `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// llmEmail is the JSON shape we ask Ternary-Bonsai-8B to emit. The
// model output is constrained to these four fields; we merge the
// result into the template-generated Payload and signals.
type llmEmail struct {
	Subject  string   `json:"subject"`
	BodyText string   `json:"body_text"`
	BodyHTML string   `json:"body_html"`
	Signals  []string `json:"signals"`
}

// Augment asks Ternary-Bonsai-8B for an alternative variant of the
// template-generated email for cat. On any error the original result
// is returned unchanged with ok=false so the generator can degrade
// gracefully when the LLM is offline.
func (c *LLMClient) Augment(cat constant.Category, opts templates.Options, base templates.Result) (templates.Result, bool) {
	if c == nil {
		return base, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	prompt := buildLLMPrompt(cat, opts, base)
	req := chatRequest{
		Model: c.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.7,
		MaxTokens:   512,
	}
	req.ResponseFmt.Type = "json_object"
	body, err := json.Marshal(req)
	if err != nil {
		return base, false
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return base, false
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return base, false
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return base, false
	}
	var parsed chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return base, false
	}
	if len(parsed.Choices) == 0 {
		return base, false
	}
	out, ok := parseLLMEmail(parsed.Choices[0].Message.Content)
	if !ok {
		return base, false
	}
	// Merge LLM output over the template. Signals are unioned: we keep
	// the deterministic signals that drive ground-truth labels and add
	// whatever the model suggested.
	merged := base
	if out.Subject != "" {
		merged.Payload.Subject = out.Subject
	}
	if out.BodyText != "" {
		merged.Payload.BodyText = out.BodyText
	}
	if out.BodyHTML != "" {
		merged.Payload.BodyHTML = out.BodyHTML
	}
	signals := make(map[string]struct{}, len(base.ExpectedSignals)+len(out.Signals))
	for _, s := range base.ExpectedSignals {
		signals[s] = struct{}{}
	}
	for _, s := range out.Signals {
		signals[strings.TrimSpace(s)] = struct{}{}
	}
	merged.ExpectedSignals = make([]string, 0, len(signals))
	for s := range signals {
		if s == "" {
			continue
		}
		merged.ExpectedSignals = append(merged.ExpectedSignals, s)
	}
	return merged, true
}

// systemPrompt nails Ternary-Bonsai-8B into the corpus-author role.
// No other LLM is supported; the system prompt is intentionally
// generic so the model isn't asked to claim a different identity.
const systemPrompt = "You are a corpus author for an email-security test suite. " +
	"Produce ONE realistic email payload in valid JSON with keys 'subject', 'body_text', 'body_html', 'signals'. " +
	"Do not include keys other than those four. Do not wrap the JSON in markdown. " +
	"Keep the payload PII-free; use placeholder names like 'alice@acme.example'."

// buildLLMPrompt assembles the user-side instruction. We tell the
// model exactly the category, locale, threat state, and difficulty so
// the output stays consistent with the deterministic ground truth.
func buildLLMPrompt(cat constant.Category, opts templates.Options, base templates.Result) string {
	intent := "benign"
	if opts.IsThreat {
		intent = "malicious"
	}
	return fmt.Sprintf(
		"Category: %s\nIntent: %s\nDifficulty: %s\nLocale: %s\n"+
			"Seed subject (rewrite freely): %q\nSeed body (rewrite freely): %q\n"+
			"Required signals (must remain plausibly present in body or headers): %v\n"+
			"Return ONLY the JSON object.",
		cat, intent, opts.Difficulty, opts.Locale,
		base.Payload.Subject, base.Payload.BodyText, base.ExpectedSignals,
	)
}

// parseLLMEmail finds the first JSON object in content and decodes it.
// kennguy3n/llama.cpp normally honours response_format=json_object but
// we still defensively trim any wrapping whitespace.
func parseLLMEmail(content string) (llmEmail, bool) {
	content = strings.TrimSpace(content)
	if len(content) == 0 {
		return llmEmail{}, false
	}
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end < start {
		return llmEmail{}, false
	}
	var out llmEmail
	if err := json.Unmarshal([]byte(content[start:end+1]), &out); err != nil {
		return llmEmail{}, false
	}
	return out, true
}
