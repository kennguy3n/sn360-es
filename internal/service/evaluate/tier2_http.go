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
	"unicode/utf8"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Tier2HTTPConfig configures the Tier 2 HTTP client. The defaults target
// the Ternary-Bonsai-8B server packaged by kennguy3n/llama.cpp; URL must
// point at the OpenAI-compatible endpoint (e.g. "http://localhost:9000").
type Tier2HTTPConfig struct {
	// URL is the base URL of the OpenAI-compatible server. Required.
	URL string
	// APIKey is sent as Bearer token when non-empty. Most local
	// llama.cpp deployments do not require auth.
	APIKey string
	// Model is the model identifier sent in the chat request. Defaults
	// to "ternary-bonsai-8b".
	Model string
	// Timeout caps the per-call duration. Defaults to 30s.
	Timeout time.Duration
	// MaxTokens caps the response length. Defaults to 512.
	MaxTokens int
	// Temperature controls sampling diversity. Defaults to 0.1 — Tier 2
	// is a classifier, not a generator, so we want low variance.
	Temperature float64
	// HTTPClient lets tests inject a custom transport. Defaults to a
	// freshly constructed http.Client with Timeout.
	HTTPClient *http.Client
}

// Tier2HTTPClient implements evaluate.Tier2Client against an OpenAI-
// compatible chat-completions endpoint. The prompt asks the model to
// return a JSON object that maps cleanly into dto.Tier2Outcome.
type Tier2HTTPClient struct {
	url         string
	apiKey      string
	model       string
	timeout     time.Duration
	maxTokens   int
	temperature float64
	http        *http.Client
}

// NewTier2HTTPClient validates cfg and returns a ready-to-use client.
func NewTier2HTTPClient(cfg Tier2HTTPConfig) (*Tier2HTTPClient, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("tier2: URL is required")
	}
	if cfg.Model == "" {
		cfg.Model = "ternary-bonsai-8b"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 512
	}
	// Treat the zero value as "unset" and fall back to the documented
	// 0.1 default. Callers who genuinely want greedy decoding can pass
	// a tiny positive number (e.g. 1e-9); anything <0 is clamped to 0.1.
	if cfg.Temperature <= 0 {
		cfg.Temperature = 0.1
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	return &Tier2HTTPClient{
		url:         strings.TrimRight(cfg.URL, "/"),
		apiKey:      cfg.APIKey,
		model:       cfg.Model,
		timeout:     cfg.Timeout,
		maxTokens:   cfg.MaxTokens,
		temperature: cfg.Temperature,
		http:        cfg.HTTPClient,
	}, nil
}

// chat-completions request / response shapes shared with the
// kennguy3n/llama.cpp server. They mirror scripts/corpus_generator/
// llm_assist.go so the wire format stays consistent.
type tier2ChatRequest struct {
	Model       string             `json:"model"`
	Messages    []tier2ChatMessage `json:"messages"`
	Temperature float64            `json:"temperature"`
	MaxTokens   int                `json:"max_tokens"`
	Response    *tier2ResponseFmt  `json:"response_format,omitempty"`
}

type tier2ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type tier2ResponseFmt struct {
	Type string `json:"type"`
}

type tier2ChatResponse struct {
	Choices []struct {
		Message tier2ChatMessage `json:"message"`
	} `json:"choices"`
}

// tier2Verdict is the JSON shape the LLM is asked to emit. Each field
// is independently optional so the parser can tolerate partial output.
type tier2Verdict struct {
	Score       int      `json:"score"`
	Categories  []string `json:"categories"`
	Confidence  float64  `json:"confidence"`
	Explanation string   `json:"explanation"`
}

// Evaluate implements evaluate.Tier2Client. It returns a structured
// outcome on success, or an error when the call fails / the response
// cannot be parsed. Latency is wall-clock.
func (c *Tier2HTTPClient) Evaluate(ctx context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	if c == nil {
		return dto.Tier2Outcome{}, errors.New("tier2: client is nil")
	}
	rctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	chat := tier2ChatRequest{
		Model: c.model,
		Messages: []tier2ChatMessage{
			{Role: "system", Content: tier2SystemPrompt},
			{Role: "user", Content: buildTier2UserPrompt(req, hint)},
		},
		Temperature: c.temperature,
		MaxTokens:   c.maxTokens,
		Response:    &tier2ResponseFmt{Type: "json_object"},
	}
	body, err := json.Marshal(chat)
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("tier2: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(rctx, http.MethodPost,
		c.url+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("tier2: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	start := time.Now()
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("tier2: do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// Drain a bounded prefix of the body so operators see
		// llama.cpp's error envelope (e.g. {"error":{"message":
		// "..."}}) instead of a bare status code. We cap the
		// read so a misbehaving server cannot bloat error
		// messages with a multi-MB payload.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		snippet := strings.TrimSpace(string(body))
		if snippet == "" {
			return dto.Tier2Outcome{}, fmt.Errorf("tier2: HTTP %d", resp.StatusCode)
		}
		return dto.Tier2Outcome{}, fmt.Errorf("tier2: HTTP %d: %s", resp.StatusCode, snippet)
	}

	var parsed tier2ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return dto.Tier2Outcome{}, fmt.Errorf("tier2: decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return dto.Tier2Outcome{}, errors.New("tier2: empty choices array")
	}

	verdict, err := parseTier2Verdict(parsed.Choices[0].Message.Content)
	if err != nil {
		return dto.Tier2Outcome{}, err
	}

	out := dto.Tier2Outcome{
		Score:       clampTier2Score(verdict.Score),
		Categories:  mapTier2Categories(verdict.Categories),
		Explanation: strings.TrimSpace(verdict.Explanation),
		Confidence:  clampConfidence(verdict.Confidence),
		ModelName:   c.model,
		LatencyMs:   time.Since(start).Milliseconds(),
	}
	return out, nil
}

// tier2SystemPrompt anchors the model in the email-security classifier
// role and constrains the output shape. Categories are echoed from
// internal/constant/categories.go so the model learns the canonical
// vocabulary; "score" is the only required field.
const tier2SystemPrompt = "You are an email-security classifier. " +
	"Given an email subject, body, and the Tier-1 encoder hint, classify the email's risk. " +
	"Respond ONLY with a single JSON object containing these keys: " +
	"'score' (integer 0-100, where 0=clean and 100=most malicious), " +
	"'categories' (array of category labels — pick from: LIKELY_PHISHING, BEC_IMPERSONATION, " +
	"LOOKALIKE_DOMAIN, SUSPICIOUS_URL, SUSPICIOUS_ATTACHMENT, FIRST_CONTACT_EXTERNAL, " +
	"ACCOUNT_TAKEOVER_SUSPECTED, VENDOR_COMPROMISE, CREDENTIAL_HARVESTING, INVOICE_FRAUD, " +
	"QR_PHISHING, SCAM_FRAUD, AUTH_FAILED, INTERNAL_TRUSTED, VENDOR_TRUSTED, NEWSLETTER), " +
	"'confidence' (float 0-1), and 'explanation' (one short English sentence). " +
	"Do not wrap the JSON in markdown. Do not include any other keys."

// buildTier2UserPrompt assembles the per-message context. We feed the
// Tier-1 hint score and reason codes so the LLM can either confirm or
// override the encoder's verdict rather than starting from scratch.
func buildTier2UserPrompt(req dto.EvaluateRequest, hint dto.Tier1Outcome) string {
	var b strings.Builder
	if req.Subject != "" {
		b.WriteString("Subject: ")
		b.WriteString(req.Subject)
		b.WriteString("\n")
	}
	if req.Signals.SenderDomain != "" {
		b.WriteString("Sender domain: ")
		b.WriteString(req.Signals.SenderDomain)
		b.WriteString("\n")
	}
	body := req.Body
	// Cap the body to a few thousand chars so the chat request stays
	// well under the model's context window. Tier 2 is a classifier
	// not a summariser — the first ~4kB of body is overwhelmingly
	// sufficient signal.
	//
	// Slicing at a raw byte offset can split a multi-byte UTF-8 rune
	// (Vietnamese, Thai, CJK, Arabic, etc. — see ARCHITECTURE.md §3.5)
	// and feed invalid UTF-8 into the chat prompt, where it manifests
	// as replacement characters or tokenizer errors at the LLM. Walk
	// back to the last rune boundary at or before maxBody so the
	// truncated prefix is always valid UTF-8.
	const maxBody = 4096
	if len(body) > maxBody {
		cut := maxBody
		for cut > 0 && !utf8.RuneStart(body[cut]) {
			cut--
		}
		body = body[:cut] + "\n[truncated]"
	}
	if body != "" {
		b.WriteString("Body:\n")
		b.WriteString(body)
		b.WriteString("\n")
	}
	if hint.Score != 0 || hint.Confidence != 0 {
		fmt.Fprintf(&b, "Tier-1 hint: score=%d, confidence=%.2f\n", hint.Score, hint.Confidence)
	}
	b.WriteString("Return ONLY the JSON verdict object.")
	return b.String()
}

// parseTier2Verdict locates the first balanced JSON object in content
// and decodes it. llama.cpp normally honours response_format=json_object
// but we still defensively extract the JSON sub-string in case the
// model wraps its output.
func parseTier2Verdict(content string) (tier2Verdict, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return tier2Verdict{}, errors.New("tier2: empty model content")
	}
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end < start {
		return tier2Verdict{}, errors.New("tier2: no JSON object in model output")
	}
	var out tier2Verdict
	if err := json.Unmarshal([]byte(content[start:end+1]), &out); err != nil {
		return tier2Verdict{}, fmt.Errorf("tier2: decode verdict: %w", err)
	}
	return out, nil
}

// mapTier2Categories filters the model output through the canonical
// category vocabulary. Anything the model invents is silently dropped
// so the downstream categoriser doesn't have to defend against unknown
// labels.
func mapTier2Categories(raw []string) []constant.Category {
	if len(raw) == 0 {
		return nil
	}
	out := make([]constant.Category, 0, len(raw))
	for _, r := range raw {
		c := constant.Category(strings.TrimSpace(strings.ToUpper(r)))
		if c.Valid() {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func clampTier2Score(s int) int {
	switch {
	case s < 0:
		return 0
	case s > 100:
		return 100
	default:
		return s
	}
}

func clampConfidence(c float64) float64 {
	switch {
	case c < 0:
		return 0
	case c > 1:
		return 1
	default:
		return c
	}
}
