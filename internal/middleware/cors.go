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

// NewCORSFromConfig is a convenience constructor that picks safe
// defaults based on the deployment environment: wildcard origins in
// dev/local, otherwise empty (caller must configure explicitly).
func NewCORSFromConfig(next http.Handler, cfg config.Config, override []string) *CORS {
	origins := override
	if origins == nil {
		if cfg.Environment.IsDevelopment() {
			origins = []string{"*"}
		}
	}
	return NewCORS(next, CORSConfig{AllowedOrigins: origins})
}

// ServeHTTP implements http.Handler.
func (c *CORS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && c.allow(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	} else if c.wildcard {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.Header().Set("Access-Control-Allow-Methods", c.methods)
	w.Header().Set("Access-Control-Allow-Headers", c.headers)
	if c.maxAge != "" {
		w.Header().Set("Access-Control-Max-Age", c.maxAge)
	}
	if r.Method == http.MethodOptions {
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
