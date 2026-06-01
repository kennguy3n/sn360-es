package slm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// SystemPrompt anchors the Tier 2 model in the email-security
// classifier role and constrains the output shape. The vocabulary
// is echoed from internal/constant/categories.go so the model learns
// the canonical labels; "score" is the only field the parser
// strictly requires.
//
// This is shared verbatim across every built-in provider so a
// Llama-3-vs-Ternary-Bonsai head-to-head evaluation runs the exact
// same instructions and isolates the model variable.
const SystemPrompt = "You are an email-security classifier. " +
	"Given an email subject, body, and the Tier-1 encoder hint, classify the email's risk. " +
	"Respond ONLY with a single JSON object containing these keys: " +
	"'score' (integer 0-100, where 0=clean and 100=most malicious), " +
	"'categories' (array of category labels — pick from: LIKELY_PHISHING, BEC_IMPERSONATION, " +
	"LOOKALIKE_DOMAIN, SUSPICIOUS_URL, SUSPICIOUS_ATTACHMENT, FIRST_CONTACT_EXTERNAL, " +
	"ACCOUNT_TAKEOVER_SUSPECTED, VENDOR_COMPROMISE, CREDENTIAL_HARVESTING, INVOICE_FRAUD, " +
	"QR_PHISHING, SCAM_FRAUD, AUTH_FAILED, INTERNAL_TRUSTED, VENDOR_TRUSTED, NEWSLETTER), " +
	"'confidence' (float 0-1), and 'explanation' (one short English sentence). " +
	"Do not wrap the JSON in markdown. Do not include any other keys."

// MaxUserPromptBodyBytes caps the body byte length inserted into
// the user prompt. Tier 2 is a classifier (not a summariser); the
// first ~4 KiB of body carries overwhelmingly sufficient signal,
// and keeping the request inside this budget bounds tokeniser
// latency and the chat-completions context window across the wide
// variance of models (Ternary-Bonsai 4k context, Llama-3-8B 8k,
// Mistral-7B 8k, Phi-3-mini 4k).
const MaxUserPromptBodyBytes = 4096

// BuildUserPrompt assembles the per-message context the LLM sees.
// The Tier 1 hint score and confidence are passed in so the model
// can either confirm or override the encoder's verdict rather than
// starting from scratch — this is how we get useful signal out of
// an 8B-class SLM at email-security latency budgets.
//
// Bodies longer than MaxUserPromptBodyBytes are truncated at the
// last valid UTF-8 rune boundary at or before the cap (see
// ARCHITECTURE.md §3.5). Splitting a multi-byte rune would feed
// invalid UTF-8 into the chat prompt and surface as replacement
// characters or tokeniser errors at the model.
func BuildUserPrompt(req dto.EvaluateRequest, hint dto.Tier1Outcome) string {
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
	if len(body) > MaxUserPromptBodyBytes {
		cut := MaxUserPromptBodyBytes
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

// Verdict is the JSON shape every built-in provider asks the model
// to emit. Each field is independently optional so the parser can
// tolerate partial output (e.g. a model that returns only "score"
// but no explanation still produces a usable verdict).
//
// Field tags use snake_case to mirror the OpenAI/llama.cpp prompt
// vocabulary; renaming any of these breaks the on-the-wire contract
// with already-trained model checkpoints.
type Verdict struct {
	Score       int      `json:"score"`
	Categories  []string `json:"categories"`
	Confidence  float64  `json:"confidence"`
	Explanation string   `json:"explanation"`
}

// ParseVerdict extracts the first balanced JSON object from content
// and decodes it. The defensive extraction is deliberate: even
// models that honour response_format=json_object will occasionally
// emit a stray "Here is the verdict:" preamble or a trailing
// "-- end." marker. Tolerating the wrapper preserves the verdict
// instead of failing the whole Tier 2 call on a cosmetic glitch.
//
// Returns a non-nil error for the three failure modes we observe
// in production: empty content, no JSON braces at all (model
// returned prose with no structure), and braces present but
// payload that fails json.Unmarshal (malformed JSON inside the
// braces).
func ParseVerdict(content string) (Verdict, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return Verdict{}, fmt.Errorf("%w: empty model content", ErrEmptyResponse)
	}
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end < start {
		return Verdict{}, fmt.Errorf("%w: no JSON object in model output", ErrUnparseableVerdict)
	}
	var out Verdict
	if err := json.Unmarshal([]byte(content[start:end+1]), &out); err != nil {
		return Verdict{}, fmt.Errorf("%w: decode verdict: %v", ErrUnparseableVerdict, err)
	}
	return out, nil
}

// MapCategories filters the model output through the canonical
// category vocabulary. Anything the model invents is silently
// dropped so the downstream categoriser does not have to defend
// against unknown labels — the model is allowed to misspell or
// hallucinate categories without poisoning the verdict.
//
// Returns nil (not an empty slice) when no recognised category
// remains so callers can `if cats != nil { ... }` cheaply.
func MapCategories(raw []string) []constant.Category {
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

// ClampScore bounds a model-emitted score into [0, 100]. The model
// is instructed to stay in this range, but defending against
// out-of-range values protects every downstream weight calculation
// from arithmetic on a runaway integer.
func ClampScore(s int) int {
	switch {
	case s < 0:
		return 0
	case s > 100:
		return 100
	default:
		return s
	}
}

// ClampConfidence bounds confidence to [0, 1]. Same rationale as
// ClampScore: the model is told to stay in range, but a runaway
// float upstream would corrupt the AI-weight contribution in the
// scoring engine.
func ClampConfidence(c float64) float64 {
	switch {
	case c < 0:
		return 0
	case c > 1:
		return 1
	default:
		return c
	}
}

// ensureError is a package-private linker pin so the linter does
// not drop the typed-error sentinels when this package is imported
// by a binary that never calls them directly. Production callers
// reference the sentinels via errors.Is on the provider error
// path; tests reference them directly.
var _ = errors.New
