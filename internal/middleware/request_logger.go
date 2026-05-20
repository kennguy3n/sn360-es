package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// RequestLoggerConfig wires the request logger.
type RequestLoggerConfig struct {
	// Logger is the destination for HTTP request logs. The caller is
	// expected to pass an slog.Logger backed by LogSanitizer so PII
	// can never leak through structured attributes.
	Logger *slog.Logger
	// SkipPaths is the set of paths that bypass logging. Defaults to
	// "/healthz" and "/readyz" (high-frequency probes that would
	// otherwise drown the log stream).
	SkipPaths []string
	// Clock is overridable for tests; nil means time.Now.
	Clock func() time.Time
}

// RequestLogger is an HTTP middleware that emits one structured log
// entry per request, including method, path, status code, latency, and
// the X-Correlation-ID header (when present).
type RequestLogger struct {
	next   http.Handler
	logger *slog.Logger
	skip   map[string]bool
	now    func() time.Time
}

// NewRequestLogger wraps next.
func NewRequestLogger(next http.Handler, cfg RequestLoggerConfig) *RequestLogger {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	skip := map[string]bool{}
	paths := cfg.SkipPaths
	if paths == nil {
		paths = []string{"/healthz", "/readyz"}
	}
	for _, p := range paths {
		skip[p] = true
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	return &RequestLogger{next: next, logger: logger, skip: skip, now: now}
}

// ServeHTTP implements http.Handler.
func (l *RequestLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if l.skip[r.URL.Path] {
		l.next.ServeHTTP(w, r)
		return
	}
	start := l.now()
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	l.next.ServeHTTP(sw, r)
	latency := l.now().Sub(start)

	attrs := []any{
		slog.String("http.method", r.Method),
		slog.String("http.path", r.URL.Path),
		slog.Int("http.status", sw.status),
		slog.Int64("http.latency_ms", latency.Milliseconds()),
		slog.Int("http.bytes_out", sw.bytes),
	}
	if cid := CorrelationIDFromContext(r.Context()); cid != "" {
		attrs = append(attrs, slog.String("correlation_id", cid))
	}
	if tid := TenantIDFromContext(r.Context()); tid != "" {
		attrs = append(attrs, slog.String("tenant_id", tid))
	}
	switch {
	case sw.status >= 500:
		l.logger.LogAttrs(r.Context(), slog.LevelError, "http request", toAttrs(attrs)...)
	case sw.status >= 400:
		l.logger.LogAttrs(r.Context(), slog.LevelWarn, "http request", toAttrs(attrs)...)
	default:
		l.logger.LogAttrs(r.Context(), slog.LevelInfo, "http request", toAttrs(attrs)...)
	}
}

// statusWriter captures the response status + size for logging. We
// intentionally avoid the http/httptest.ResponseRecorder because it
// buffers the body in memory, which would defeat streaming endpoints.
type statusWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

// WriteHeader records the status and forwards the call.
func (s *statusWriter) WriteHeader(status int) {
	if !s.wroteHeader {
		s.status = status
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(status)
}

// Write tracks the number of bytes written.
func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.status = http.StatusOK
		s.wroteHeader = true
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// toAttrs converts the variadic []any of slog values to []slog.Attr
// without invoking reflection.
func toAttrs(in []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(in))
	for _, v := range in {
		if a, ok := v.(slog.Attr); ok {
			out = append(out, a)
		}
	}
	return out
}
