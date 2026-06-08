package education

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// LessonContext carries the per-tenant / per-recipient signals used to
// contextualise a generated micro-lesson (4C.1). Every field is
// optional: an empty LessonContext yields a generic lesson, and the
// presence of any field is what opts a Serve call into the LLM
// generation path (see MicroLessonService.Serve).
type LessonContext struct {
	// Industry is the tenant's sector overlay (e.g. "financial-services",
	// "healthcare"). Used to ground examples in the recipient's world.
	Industry string
	// EmployeeRole is the recipient's job family (e.g. "finance",
	// "engineering", "executive"). Used to tailor the scenario.
	EmployeeRole string
	// ThreatProfile is a short free-text description of the threat that
	// triggered the lesson (e.g. "invoice-fraud wave targeting AP").
	ThreatProfile string
}

// IsZero reports whether no contextual signal is set. The Serve path
// uses this to decide whether to invoke the (cost-bearing) generator
// at all — with no context there is nothing to contextualise, so the
// deterministic catalog lesson is served directly.
func (c LessonContext) IsZero() bool {
	return c.Industry == "" && c.EmployeeRole == "" && c.ThreatProfile == ""
}

// LessonGenerator produces a (possibly contextualised) lesson from a
// deterministic base lesson. Implementations may be LLM-backed or
// deterministic. The returned lesson MUST keep the base lesson's
// identity fields (LessonID, Category, Title) — only the body prose is
// allowed to change — so downstream credit/telemetry keyed on
// lesson_id stays stable and the model can never inject a new title or
// re-categorise the lesson.
type LessonGenerator interface {
	Generate(ctx context.Context, base MicroLesson, lc LessonContext, locale string) (MicroLesson, error)
}

// Tier2LessonGeneratorConfig wires the LLM-powered lesson generator.
// Field names and defaults mirror agent.Tier2ExplainerConfig so the
// composition root can configure both from the same Tier 2 settings.
type Tier2LessonGeneratorConfig struct {
	// URL is the OpenAI-compatible chat completions endpoint. Required.
	URL string
	// APIKey is sent as a Bearer token when non-empty.
	APIKey string
	// Model identifier. Defaults to "ternary-bonsai-8b".
	Model string
	// Timeout per call. Defaults to 15s.
	Timeout time.Duration
	// MaxTokens caps response length. Defaults to 512 (a 2-minute
	// lesson is longer than a banner explanation).
	MaxTokens int
	// Temperature for sampling. Defaults to 0.4.
	Temperature float64
	// HTTPClient lets tests inject a custom transport.
	HTTPClient *http.Client
	// Logger for debug output.
	Logger *slog.Logger
}

// Tier2LessonGenerator calls the Tier 2 SLM to rewrite a base lesson's
// body so it is contextualised to the tenant's industry, the
// recipient's role, and the active threat profile. The model returns
// plain text only; the body is escaped and wrapped in a fixed HTML
// envelope locally (see renderLessonHTML), so the model can never
// introduce markup, scripts, or remote assets into a surface that is
// rendered as HTML in email clients.
type Tier2LessonGenerator struct {
	url         string
	apiKey      string
	model       string
	timeout     time.Duration
	maxTokens   int
	temperature float64
	http        *http.Client
	log         *slog.Logger
}

// NewTier2LessonGenerator validates config and returns a ready-to-use
// generator.
func NewTier2LessonGenerator(cfg Tier2LessonGeneratorConfig) (*Tier2LessonGenerator, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("education: lesson generator URL is required")
	}
	if cfg.Model == "" {
		cfg.Model = "ternary-bonsai-8b"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 512
	}
	if cfg.Temperature < 0 {
		cfg.Temperature = 0.4
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Tier2LessonGenerator{
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

// Generate prompts the SLM for a contextualised body and returns a new
// MicroLesson that keeps base's identity fields but carries the
// generated, locally-rendered HTML body. An error is returned (and the
// base lesson untouched) on any transport, status, decode, or
// empty-content failure so a FallbackLessonGenerator can fall back to
// the deterministic catalog lesson.
func (g *Tier2LessonGenerator) Generate(ctx context.Context, base MicroLesson, lc LessonContext, locale string) (MicroLesson, error) {
	if locale == "" {
		locale = "en"
	}
	prompt := buildLessonPrompt(base, lc, locale)

	reqBody := lessonChatRequest{
		Model:       g.model,
		Messages:    []lessonChatMessage{{Role: "user", Content: prompt}},
		MaxTokens:   g.maxTokens,
		Temperature: g.temperature,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return MicroLesson{}, fmt.Errorf("education: marshal lesson request: %w", err)
	}

	rctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(rctx, http.MethodPost,
		g.url+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return MicroLesson{}, fmt.Errorf("education: lesson request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if g.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+g.apiKey)
	}

	resp, err := g.http.Do(req)
	if err != nil {
		return MicroLesson{}, fmt.Errorf("education: lesson call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return MicroLesson{}, fmt.Errorf("education: lesson status %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp lessonChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return MicroLesson{}, fmt.Errorf("education: lesson decode: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return MicroLesson{}, errors.New("education: lesson generation returned no choices")
	}

	plain := strings.TrimSpace(chatResp.Choices[0].Message.Content)
	if plain == "" {
		return MicroLesson{}, errors.New("education: lesson generation returned empty content")
	}

	out := base
	out.BodyHTML = renderLessonHTML(base.Title, plain)
	out.EstimatedSeconds = estimateSeconds(plain, base.EstimatedSeconds)
	out.Source = LessonSourceLLM
	if err := out.Validate(); err != nil {
		// A malformed render should never be served; treat as a
		// generation failure so the fallback path serves the catalog.
		return MicroLesson{}, fmt.Errorf("education: generated lesson invalid: %w", err)
	}
	return out, nil
}

// DeterministicLessonGenerator returns the base lesson unchanged. It is
// the non-LLM fallback and the implicit behaviour when no generator is
// wired.
type DeterministicLessonGenerator struct{}

// Generate implements LessonGenerator by returning the base lesson with
// its source marked as the catalog.
func (DeterministicLessonGenerator) Generate(_ context.Context, base MicroLesson, _ LessonContext, _ string) (MicroLesson, error) {
	out := base
	if out.Source == "" {
		out.Source = LessonSourceCatalog
	}
	return out, nil
}

// FallbackLessonGenerator tries the primary generator first and falls
// back to the deterministic catalog lesson on error or empty result.
// This mirrors agent.FallbackExplainer so the LLM path is always
// best-effort: a model outage degrades to the deterministic lesson
// rather than failing the Serve call.
type FallbackLessonGenerator struct {
	Primary  LessonGenerator
	Fallback LessonGenerator
	Logger   *slog.Logger
}

// Generate implements LessonGenerator with fallback logic.
func (f FallbackLessonGenerator) Generate(ctx context.Context, base MicroLesson, lc LessonContext, locale string) (MicroLesson, error) {
	if f.Primary != nil {
		lesson, err := f.Primary.Generate(ctx, base, lc, locale)
		if err == nil && strings.TrimSpace(lesson.BodyHTML) != "" {
			return lesson, nil
		}
		if f.Logger != nil {
			f.Logger.WarnContext(ctx, "education: primary lesson generator failed, using catalog",
				slog.String("lesson_id", base.LessonID),
				slog.Any("error", err))
		}
	}
	if f.Fallback != nil {
		return f.Fallback.Generate(ctx, base, lc, locale)
	}
	return DeterministicLessonGenerator{}.Generate(ctx, base, lc, locale)
}

// --- prompt + rendering helpers --------------------------------------------

func buildLessonPrompt(base MicroLesson, lc LessonContext, locale string) string {
	var b strings.Builder
	b.WriteString("You are a security-awareness coach writing a short micro-lesson for an employee. ")
	fmt.Fprintf(&b, "Write the ENTIRE lesson in the '%s' language (use the correct locale/dialect). ", locale)
	b.WriteString("Target length is a 2-minute read (roughly 150-220 words). ")
	b.WriteString("Output PLAIN TEXT ONLY: no HTML, no Markdown, no headings, no bullet characters. ")
	b.WriteString("Separate paragraphs with a blank line. Keep it practical and reassuring, not alarmist. ")
	b.WriteString("Do not invent product features or specific people; teach the recipient how to recognise and respond to the threat.\n\n")

	fmt.Fprintf(&b, "Threat category: %s\n", base.Category)
	if ref := stripHTMLToText(base.BodyHTML); ref != "" {
		fmt.Fprintf(&b, "Reference (generic) lesson to expand on: %s\n", ref)
	}
	if lc.Industry != "" {
		fmt.Fprintf(&b, "Tenant industry: %s (ground examples in this sector)\n", lc.Industry)
	}
	if lc.EmployeeRole != "" {
		fmt.Fprintf(&b, "Recipient role: %s (tailor the scenario to this role)\n", lc.EmployeeRole)
	}
	if lc.ThreatProfile != "" {
		fmt.Fprintf(&b, "Active threat profile: %s\n", lc.ThreatProfile)
	}
	b.WriteString("\nWrite the lesson body now.")
	return b.String()
}

// renderLessonHTML escapes the model's plain-text output and wraps it
// in the same fixed HTML envelope the catalog lessons use. Because the
// only HTML is produced here (never by the model), the output cannot
// contain scripts, event handlers, or remote assets. Paragraphs are
// split on blank lines; the deterministic title is reused as the
// heading.
func renderLessonHTML(title, plain string) string {
	var b strings.Builder
	b.WriteString(`<section style="font-family:system-ui;font-size:14px;color:#1a1a1a">`)
	if t := strings.TrimSpace(title); t != "" {
		fmt.Fprintf(&b, `<h3 style="margin:0 0 8px;color:#a40000">%s</h3>`, html.EscapeString(t))
	}
	for _, para := range splitParagraphs(plain) {
		fmt.Fprintf(&b, `<p style="margin:0 0 8px">%s</p>`, html.EscapeString(para))
	}
	b.WriteString(`</section>`)
	return b.String()
}

// splitParagraphs splits text on blank lines, trims each paragraph,
// collapses intra-paragraph newlines to spaces, and drops empties.
func splitParagraphs(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	blocks := strings.Split(text, "\n\n")
	out := make([]string, 0, len(blocks))
	for _, blk := range blocks {
		para := strings.TrimSpace(strings.ReplaceAll(blk, "\n", " "))
		// Collapse runs of spaces introduced by the newline replace.
		para = strings.Join(strings.Fields(para), " ")
		if para != "" {
			out = append(out, para)
		}
	}
	if len(out) == 0 {
		// Guarantee a non-empty body so Validate passes; the caller
		// only reaches here with non-empty plain text.
		out = append(out, strings.Join(strings.Fields(text), " "))
	}
	return out
}

// stripHTMLToText removes tags from the catalog body so it can be fed
// to the model as reference text without leaking markup into the
// prompt. It is deliberately simple (drop everything between '<' and
// '>') because the catalog HTML is trusted, hand-authored, and
// script-free.
func stripHTMLToText(htmlStr string) string {
	var b strings.Builder
	depth := 0
	for _, r := range htmlStr {
		switch r {
		case '<':
			// Emit a separator so text on either side of a tag
			// boundary (e.g. "</h3><p>") is not word-joined.
			b.WriteByte(' ')
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return strings.Join(strings.Fields(html.UnescapeString(b.String())), " ")
}

// estimateSeconds returns a reading-time estimate (~200 wpm) for the
// generated text, floored at the base lesson's estimate so the value
// is always positive and never under-promises relative to the catalog.
func estimateSeconds(plain string, base int) int {
	words := len(strings.Fields(plain))
	if words == 0 {
		return base
	}
	secs := words * 60 / 200
	if secs < base {
		return base
	}
	return secs
}

// LessonSource enumerates how a served lesson's body was produced.
const (
	// LessonSourceCatalog marks a deterministic, embedded catalog lesson.
	LessonSourceCatalog = "catalog"
	// LessonSourceLLM marks a lesson whose body was generated by the LLM
	// path and rendered locally.
	LessonSourceLLM = "llm"
)

type lessonChatRequest struct {
	Model       string              `json:"model"`
	Messages    []lessonChatMessage `json:"messages"`
	MaxTokens   int                 `json:"max_tokens"`
	Temperature float64             `json:"temperature"`
}

type lessonChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type lessonChatResponse struct {
	Choices []lessonChatChoice `json:"choices"`
}

type lessonChatChoice struct {
	Message lessonChatMessage `json:"message"`
}

// compile-time assertions
var (
	_ LessonGenerator = (*Tier2LessonGenerator)(nil)
	_ LessonGenerator = DeterministicLessonGenerator{}
	_ LessonGenerator = FallbackLessonGenerator{}
)
