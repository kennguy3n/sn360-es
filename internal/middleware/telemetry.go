package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

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
}

// Telemetry records per-request Prometheus counters + histograms and
// (optionally) wraps the chain with the W3C tracing middleware. The
// route label is the request URL.Path; high-cardinality endpoints
// should rely on path templating before hitting this middleware.
type Telemetry struct {
	next    http.Handler
	metrics *telemetry.Metrics
	now     func() time.Time
}

// NewTelemetry wraps next.
func NewTelemetry(next http.Handler, cfg TelemetryConfig) http.Handler {
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	h := http.Handler(&Telemetry{next: next, metrics: cfg.Metrics, now: now})
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
	t.metrics.ObserveHTTPRequest(r.Method, r.URL.Path, strconv.Itoa(sw.status), latency)
}
