package config

import "time"

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
type AI struct {
	URL      string
	APIKey   string
	Timeout  time.Duration
	CacheTTL time.Duration
}

func loadAI() AI {
	return AI{
		URL:      getStr("AI_URL", "http://127.0.0.1:9000"),
		APIKey:   getStr("AI_API_KEY", ""),
		Timeout:  getDuration("AI_TIMEOUT", 30*time.Second),
		CacheTTL: getDuration("AI_CACHE_TTL", time.Hour),
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
