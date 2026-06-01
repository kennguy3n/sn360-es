package slm

// OpenAI-compatible chat-completions wire types. They are shared by
// all built-in providers; provider-specific extensions are local to
// each subpackage so this file stays stable.

// ChatRequest is the canonical OpenAI chat-completions request body.
// Providers may marshal additional fields by wrapping ChatRequest
// (composition) or by serialising into a private struct that
// embeds it.
type ChatRequest struct {
	Model       string          `json:"model"`
	Messages    []ChatMessage   `json:"messages"`
	Temperature float64         `json:"temperature"`
	MaxTokens   int             `json:"max_tokens"`
	Response    *ResponseFormat `json:"response_format,omitempty"`
}

// ChatMessage is the {role, content} pair used in chat-completions.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ResponseFormat is the structured-output hint. type="json_object"
// is honoured by Ternary-Bonsai, OpenAI, vLLM, llama.cpp (>= b3000),
// and most modern OpenAI-compat servers. Servers that ignore it
// degrade gracefully because parseVerdict will extract the embedded
// JSON object from prose output.
type ResponseFormat struct {
	Type string `json:"type"`
}

// ChatResponse is the canonical OpenAI chat-completions response.
// Providers that need to pick additional fields (Usage, system
// fingerprint, etc.) can either decode into a wider struct of
// their own or wrap ChatResponse via composition.
type ChatResponse struct {
	Choices []ChatChoice `json:"choices"`
}

// ChatChoice is a single chat-completions choice. Index and Reason
// are optional in many provider responses (llama-server omits them
// in some builds) so they are not annotated as required.
type ChatChoice struct {
	Index        int         `json:"index,omitempty"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason,omitempty"`
}
