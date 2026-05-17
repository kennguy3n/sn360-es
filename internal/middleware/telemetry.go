package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

// RoutePattern collapses a family of URL paths into a single
// Prometheus-friendly label. Any request whose path has Prefix as its
// prefix is reported under Label instead of the raw URL.Path. This
// keeps cardinality bounded for endpoints that include path
// parameters such as ticket IDs or signed URL tokens.
type RoutePattern struct {
	// Prefix is the path prefix that triggers collapsing. It must end
	// with `/` so prefix matches do not bleed across path segments
	// (e.g. `/l/` matches `/l/abc` but not `/long`).
	Prefix string
	// Label is the value used as the `route` label on metrics for
	// requests whose path begins with Prefix. Typically a templated
	// form such as `/v1/escalation/:id`.
	Label string
}

// TelemetryConfig wires the HTTP telemetry middleware.
type TelemetryConfig struct {
	// Metrics is the application-wide instrument set. Required.
	Metrics *telemetry.Metrics
	// Tracer is optional. When non-nil, the underlying
	// telemetry.HTTPMiddleware is also installed so every request
	// produces a server span.
	Tracer *telemetry.Tracer
	// Clock is overridable for tests; nil means time.Now.
	Clock func() time.Time
	// RoutePatterns collapses high-cardinality routes (those with
	// path parameters such as ticket IDs or signed tokens) into a
	// fixed label so the Prometheus series count stays bounded.
	// When empty, the raw r.URL.Path is used.
	RoutePatterns []RoutePattern
}

// Telemetry records per-request Prometheus counters + histograms and
// (optionally) wraps the chain with the W3C tracing middleware. The
// route label is normalised via RoutePatterns so endpoints with path
// parameters do not produce one Prometheus series per unique value.
type Telemetry struct {
	next     http.Handler
	metrics  *telemetry.Metrics
	now      func() time.Time
	patterns []RoutePattern
}

// NewTelemetry wraps next.
func NewTelemetry(next http.Handler, cfg TelemetryConfig) http.Handler {
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	h := http.Handler(&Telemetry{
		next:     next,
		metrics:  cfg.Metrics,
		now:      now,
		patterns: cfg.RoutePatterns,
	})
	if cfg.Tracer != nil {
		h = telemetry.HTTPMiddleware(cfg.Tracer)(h)
	}
	return h
}

// ServeHTTP implements http.Handler.
func (t *Telemetry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if t.metrics == nil {
		t.next.ServeHTTP(w, r)
		return
	}
	start := t.now()
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	t.next.ServeHTTP(sw, r)
	latency := t.now().Sub(start).Seconds()
	t.metrics.ObserveHTTPRequest(r.Method, t.normaliseRoute(r.URL.Path), strconv.Itoa(sw.status), latency)
}

// normaliseRoute collapses a request path against the configured
// RoutePatterns. The first matching pattern wins so more-specific
// prefixes should appear earlier in the slice.
func (t *Telemetry) normaliseRoute(path string) string {
	for _, p := range t.patterns {
		if p.Prefix == "" || p.Label == "" {
			continue
		}
		// Match either the bare prefix (e.g. `/l/` itself) or
		// anything below it (`/l/<token>`). Crucially we never
		// strip the prefix slash to avoid `/longer-path` colliding
		// with `/l/`.
		if path == strings.TrimRight(p.Prefix, "/") || strings.HasPrefix(path, p.Prefix) {
			return p.Label
		}
	}
	return path
}
