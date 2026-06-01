package slm

import (
	"strings"
	"time"
)

// ProviderConfig is the universal construction payload passed to
// every registered factory. Factories pick the fields they care
// about; provider-specific knobs live in ProviderOpts so adding a
// new provider does not require widening this struct.
//
// Name is the registry key (e.g. "ternarybonsai", "llamaserver",
// "openai"). It is informational for factories — they may use it to
// label outbound metrics — but is also what slm.New uses to look
// the factory up in the registry.
//
// All other fields are the union of options that more than one
// provider consumes. A factory that does not honour a given field
// (e.g. llama-server does not require an API key) should silently
// ignore the value rather than rejecting the config; ProviderOpts
// is the escape hatch for genuinely provider-specific tuning.
type ProviderConfig struct {
	// Name identifies the registered provider this config is for.
	// Factories should treat it as advisory — the registry has
	// already validated that the name matches before dispatch.
	Name string

	// URL is the OpenAI-compatible endpoint root (no trailing
	// "/v1/chat/completions"; the factory appends that).
	URL string

	// APIKey is sent as a Bearer token. Empty disables auth.
	APIKey string

	// Model is the model identifier sent in the chat request.
	// Provider-specific defaults apply when empty.
	Model string

	// Timeout caps the per-call HTTP duration. Provider-specific
	// defaults apply when zero.
	Timeout time.Duration

	// MaxTokens caps the response token budget. Provider-specific
	// defaults apply when zero.
	MaxTokens int

	// Temperature controls sampling diversity. The pointer type
	// distinguishes "operator did not configure a value, let the
	// provider apply its documented default" (nil) from "operator
	// explicitly chose this value, including 0.0 for greedy
	// decoding" (non-nil). Collapsing the two cases onto float64
	// would silently override TIER2_TEMPERATURE=0 to 0.1 for
	// every provider, which prevents experiments that need
	// deterministic argmax sampling.
	//
	// Provider defaults (typically 0.1 — Tier 2 is a classifier,
	// so low variance is preferred) apply when this is nil.
	Temperature *float64

	// ProviderOpts carries provider-specific knobs as a flat
	// string→string map (e.g. vLLM "n_gpu_layers", Bedrock
	// "region", OpenAI "max_retries"). The factory documents which
	// keys it understands; unknown keys are ignored. The map is
	// always non-nil for factories — callers may pass nil, slm.New
	// normalises it before dispatch.
	ProviderOpts map[string]string
}

// ParseProviderOpts parses the canonical "k=v,k=v" form of
// TIER2_PROVIDER_OPTS into a string→string map.
//
// Whitespace around keys and values is trimmed. Empty keys are
// dropped silently (so a trailing comma is not an error). A value
// containing "=" preserves everything after the first "=" so opts
// like a Bedrock region "us-east-1" or an Azure base URL
// "https://example.com/v1" round-trip unchanged.
//
// Returns a nil map when raw is empty so the caller can rely on
// "no opts" being represented uniformly. A non-nil map is always
// non-empty.
func ParseProviderOpts(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		// SplitN with n=2 so the value can contain "=" without
		// being split (e.g. base64 padding, URLs with query
		// strings).
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
