package config

import (
	"time"

	"github.com/kennguy3n/sn360-es/pkg/inference/slm"
)

// Rspamd configures the Rspamd HTTP client.
type Rspamd struct {
	URL      string
	Password string
	Timeout  time.Duration
	CacheTTL time.Duration
}

func loadRspamd() Rspamd {
	return Rspamd{
		URL:      getStr("RSPAMD_URL", "http://127.0.0.1:11333"),
		Password: getStr("RSPAMD_PASSWORD", ""),
		Timeout:  getDuration("RSPAMD_TIMEOUT", 5*time.Second),
		CacheTTL: getDuration("RSPAMD_CACHE_TTL", 30*time.Minute),
	}
}

// AI configures the Tier 2 LLM client.
//
// The Tier 2 provider is selected via TIER2_PROVIDER (default
// "ternarybonsai"). URL / APIKey / Model / Timeout / MaxTokens /
// Temperature carry the deployment default's configuration; the
// selected provider's factory in pkg/inference/slm/providers/* maps
// these onto its native config. Provider-specific knobs (vLLM
// "n_gpu_layers", OpenAI "max_retries", llama-server
// "auth_header_name", etc.) live in ProviderOpts.
//
// Per-tenant override is enabled by the presence of a non-NULL
// tier2_provider on the tenant's score_engine row (see migration
// 0023); the deployment-default config above is still consulted as
// the construction inputs (URL, Model, etc.) so an override only
// needs to declare which provider to use, not duplicate the
// connection details.
type AI struct {
	URL      string
	APIKey   string
	Model    string
	Timeout  time.Duration
	CacheTTL time.Duration

	// Provider names the registered Tier 2 provider (see
	// pkg/inference/slm/registry.go). Defaults to "ternarybonsai"
	// so the existing AI_URL / AI_API_KEY deployments retain
	// bit-for-bit production behaviour.
	Provider string

	// ProviderOpts is the parsed TIER2_PROVIDER_OPTS k=v,k=v
	// payload. nil when the env var is unset / empty so callers
	// can rely on "no opts" being represented uniformly.
	ProviderOpts map[string]string

	// MaxTokens caps the response token budget. Defaults to 0
	// (which each provider interprets as its own documented
	// default — Ternary-Bonsai uses 512 to match historical
	// behaviour).
	MaxTokens int

	// Temperature controls sampling diversity. Defaults to 0
	// (which each provider interprets as its own documented
	// default — typically 0.1 for classifier-style use).
	Temperature float64
}

// ParseProviderOpts is exported so callers (Validate, tests, the
// composition root) can re-parse the env var when AI is constructed
// outside loadAI (e.g. injected from a test fixture).
//
// The parsing rule lives in the slm package so any future tweak
// (escape rules, alternative separators, etc.) lands in one place
// instead of drifting between config and slm. This thin shim is
// kept so existing config-package callers do not have to learn
// about slm.
func ParseProviderOpts(raw string) map[string]string {
	return slm.ParseProviderOpts(raw)
}

func loadAI() AI {
	return AI{
		URL:          getStr("AI_URL", "http://127.0.0.1:9000"),
		APIKey:       getStr("AI_API_KEY", ""),
		Model:        getStr("AI_MODEL", ""),
		Timeout:      getDuration("AI_TIMEOUT", 30*time.Second),
		CacheTTL:     getDuration("AI_CACHE_TTL", time.Hour),
		Provider:     getStr("TIER2_PROVIDER", "ternarybonsai"),
		ProviderOpts: ParseProviderOpts(getStr("TIER2_PROVIDER_OPTS", "")),
		MaxTokens:    getInt("TIER2_MAX_TOKENS", 0),
		Temperature:  getFloat("TIER2_TEMPERATURE", 0.0),
	}
}

// Tier1 configures the Tier 1 (encoder) client.
type Tier1 struct {
	URL           string
	Timeout       time.Duration
	BatchSize     int
	PassThreshold int
	FlagThreshold int
	// SuppressPartner is the (typically negative) offset applied to
	// PassBelow / FlagAbove for senders categorised as Partner or
	// Customer. See tier1.Thresholds.AdjustForRelationship — the
	// relationship-aware tightening is platform-wide, not per-tenant,
	// so the tuning agent never writes it. Threading it through the
	// repo Config (rather than relying on tier1.DefaultThresholds()
	// at each call site) keeps the per-message Evaluator and the
	// BatchOrchestrator reading from a single source so they cannot
	// produce divergent verdicts for the same input.
	SuppressPartner int
	// BatchEnabled selects the batched-orchestrator path on
	// es.evaluate.request (pulls in batches of up to BatchSize and
	// calls the encoder's /predict/batch endpoint). When false the
	// per-message handler is used instead.
	BatchEnabled bool
}

func loadTier1() Tier1 {
	return Tier1{
		URL:           getStr("TIER1_URL", "http://127.0.0.1:9100"),
		Timeout:       getDuration("TIER1_TIMEOUT", 5*time.Second),
		BatchSize:     getInt("TIER1_BATCH_SIZE", 64),
		PassThreshold: getInt("TIER1_PASS_THRESHOLD", 20),
		FlagThreshold: getInt("TIER1_FLAG_THRESHOLD", 60),
		// Mirrors tier1.DefaultThresholds().SuppressPartner (-10).
		// Kept as a literal here because internal/config must stay
		// stdlib-only (see package doc), so we cannot import the
		// tier1 package. Whenever the platform default changes,
		// update both locations.
		SuppressPartner: getInt("TIER1_SUPPRESS_PARTNER", -10),
		BatchEnabled:    getBool("TIER1_BATCH_ENABLED", true),
	}
}

// Tier0 controls the Tier 0 classification gates.
type Tier0 struct {
	SkipInternal         bool
	SkipVendor           bool
	SkipRecurring        bool
	HighVolumeRspamdOnly bool
}

func loadTier0() Tier0 {
	return Tier0{
		SkipInternal:         getBool("TIER0_SKIP_INTERNAL", true),
		SkipVendor:           getBool("TIER0_SKIP_VENDOR", true),
		SkipRecurring:        getBool("TIER0_SKIP_RECURRING", true),
		HighVolumeRspamdOnly: getBool("TIER0_HIGH_VOLUME_RSPAMD_ONLY", true),
	}
}
