package middleware

import (
	"net/http"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/config"
)

// CORSConfig wires the CORS middleware.
type CORSConfig struct {
	// AllowedOrigins is the explicit allow-list. The literal "*"
	// matches any origin; otherwise the request's Origin header must
	// match one of the entries exactly (case-insensitive).
	AllowedOrigins []string
	// AllowedMethods overrides the default GET/POST/OPTIONS list.
	AllowedMethods []string
	// AllowedHeaders overrides the default Authorization /
	// Content-Type / X-Correlation-ID list.
	AllowedHeaders []string
	// MaxAge is the cache duration (in seconds) the browser may
	// cache preflight responses for. Zero disables the header.
	MaxAge int
}

// defaults applied when callers leave a field empty.
var (
	defaultCORSMethods = []string{http.MethodGet, http.MethodPost, http.MethodOptions}
	defaultCORSHeaders = []string{"Authorization", "Content-Type", "X-Correlation-ID"}
)

// CORS implements a minimal CORS handler. It is intentionally narrow
// because the add-in and dashboard surfaces only need GET/POST plus
// preflight OPTIONS.
type CORS struct {
	next     http.Handler
	origins  []string
	wildcard bool
	methods  string
	headers  string
	maxAge   string
}

// NewCORS wraps next with a CORS handler derived from cfg.
func NewCORS(next http.Handler, cfg CORSConfig) *CORS {
	c := &CORS{next: next}
	for _, o := range cfg.AllowedOrigins {
		o = strings.TrimSpace(o)
		if o == "*" {
			c.wildcard = true
			continue
		}
		if o != "" {
			c.origins = append(c.origins, strings.ToLower(o))
		}
	}
	methods := cfg.AllowedMethods
	if len(methods) == 0 {
		methods = defaultCORSMethods
	}
	headers := cfg.AllowedHeaders
	if len(headers) == 0 {
		headers = defaultCORSHeaders
	}
	c.methods = strings.Join(methods, ", ")
	c.headers = strings.Join(headers, ", ")
	if cfg.MaxAge > 0 {
		c.maxAge = intToASCII(cfg.MaxAge)
	}
	return c
}

// NewCORSFromConfig is a convenience constructor that resolves the
// allowed-origin allow-list in this priority order:
//
//  1. an explicit override slice (highest priority — used in tests
//     and by callers that build the slice from sources outside the
//     Config struct);
//  2. cfg.CORS.AllowedOrigins, populated from the
//     CORS_ALLOWED_ORIGINS environment variable;
//  3. wildcard ("*") when the deployment Environment is
//     development/local — the dev convenience default;
//  4. empty (no Access-Control-Allow-Origin header emitted) when
//     none of the above match.
//
// In production this means a forgotten CORS_ALLOWED_ORIGINS variable
// fails closed: the add-in / dashboard surfaces will not get the
// CORS header, which is loud and obvious rather than silently
// permissive.
func NewCORSFromConfig(next http.Handler, cfg config.Config, override []string) *CORS {
	origins := override
	if origins == nil {
		origins = cfg.CORS.AllowedOrigins
	}
	if origins == nil && cfg.Environment.IsDevelopment() {
		origins = []string{"*"}
	}
	return NewCORS(next, CORSConfig{AllowedOrigins: origins})
}

// ServeHTTP implements http.Handler.
//
// Allow-Origin (and the paired Vary: Origin) is set on every
// cross-origin response so the browser can decide whether to expose
// the body to the page. Allow-Methods, Allow-Headers and Max-Age are
// only meaningful on preflight (OPTIONS) responses per the CORS spec
// (Fetch §3.2.5), so we gate them on r.Method == OPTIONS to avoid
// shipping bytes the browser will discard on every API call.
func (c *CORS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && c.allow(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	} else if c.wildcard {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", c.methods)
		w.Header().Set("Access-Control-Allow-Headers", c.headers)
		if c.maxAge != "" {
			w.Header().Set("Access-Control-Max-Age", c.maxAge)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	c.next.ServeHTTP(w, r)
}

func (c *CORS) allow(origin string) bool {
	if c.wildcard {
		return true
	}
	o := strings.ToLower(strings.TrimSpace(origin))
	for _, allowed := range c.origins {
		if allowed == o {
			return true
		}
	}
	return false
}

// intToASCII formats a positive int without pulling in strconv at the
// call site (keeps the hot path branch-free).
func intToASCII(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
