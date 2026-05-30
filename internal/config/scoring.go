package config

import "time"

// CircuitBreaker holds shared circuit-breaker defaults.
type CircuitBreaker struct {
	FailureThreshold int
	SuccessThreshold int
	OpenTimeout      time.Duration
}

func loadCircuitBreaker() CircuitBreaker {
	return CircuitBreaker{
		FailureThreshold: getInt("CB_FAILURE_THRESHOLD", 5),
		SuccessThreshold: getInt("CB_SUCCESS_THRESHOLD", 2),
		OpenTimeout:      getDuration("CB_OPEN_TIMEOUT", 30*time.Second),
	}
}

// Privacy holds privacy-layer toggles.
type Privacy struct {
	PseudonymizeLogs bool
}

func loadPrivacy() Privacy {
	return Privacy{
		PseudonymizeLogs: getBool("PRIVACY_PSEUDONYMIZE_LOGS", true),
	}
}

// Banner holds banner / action-token configuration.
type Banner struct {
	TokenSecret   string
	TokenTTL      time.Duration
	DefaultLocale string
}

func loadBanner() Banner {
	return Banner{
		TokenSecret:   getStr("BANNER_TOKEN_SECRET", ""),
		TokenTTL:      getDuration("BANNER_TOKEN_TTL", 7*24*time.Hour),
		DefaultLocale: getStr("BANNER_DEFAULT_LOCALE", "en"),
	}
}

// ScoreThresholds defines the default per-tier score boundaries.
type ScoreThresholds struct {
	Blocked  int
	HighRisk int
	Warning  int
	Caution  int
	Info     int
}

func loadScoreThresholds() ScoreThresholds {
	return ScoreThresholds{
		Blocked:  getInt("SCORE_BLOCKED_THRESHOLD", 85),
		HighRisk: getInt("SCORE_HIGH_RISK_THRESHOLD", 70),
		Warning:  getInt("SCORE_WARNING_THRESHOLD", 50),
		Caution:  getInt("SCORE_CAUTION_THRESHOLD", 30),
		Info:     getInt("SCORE_INFO_THRESHOLD", 15),
	}
}

// URLRewrite configures the URL-rewriter interstitial.
type URLRewrite struct {
	Base string
}

func loadURLRewrite() URLRewrite {
	return URLRewrite{
		Base: getStr("URL_REWRITER_BASE", "https://l.sn360.io"),
	}
}

// SMTP configures the simulation-email transport used by the
// education engine. All fields are optional; when Host or From is
// empty the simulation sender is disabled and SimulationEngine
// continues to record interactions without dispatching mail.
type SMTP struct {
	Host       string
	Port       int
	User       string
	Password   string
	From       string
	StartTLS   bool
	Timeout    time.Duration
	SkipVerify bool
}

func loadSMTP() SMTP {
	return SMTP{
		Host:       getStr("SMTP_HOST", ""),
		Port:       getInt("SMTP_PORT", 587),
		User:       getStr("SMTP_USER", ""),
		Password:   getStr("SMTP_PASSWORD", ""),
		From:       getStr("SMTP_FROM", ""),
		StartTLS:   getBool("SMTP_STARTTLS", true),
		Timeout:    getDuration("SMTP_TIMEOUT", 10*time.Second),
		SkipVerify: getBool("SMTP_SKIP_VERIFY", false),
	}
}
