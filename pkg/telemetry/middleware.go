package telemetry

import (
	"net/http"
	"strconv"
)

// W3CTraceparentHeader is the canonical W3C Trace Context header name.
const W3CTraceparentHeader = "traceparent"

// HTTPMiddleware returns an http.Handler that extracts any incoming
// `traceparent` header, starts a server span for the request, and
// injects the new SpanContext into the outgoing response headers and
// the request context.
//
// Spans are named "<METHOD> <URL.Path>" and tagged with HTTP status
// and method attributes. Failed responses (>= 500) record the span as
// errored.
func HTTPMiddleware(tracer *Tracer) func(http.Handler) http.Handler {
	if tracer == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if tp := r.Header.Get(W3CTraceparentHeader); tp != "" {
				if sc, err := ParseTraceparent(tp); err == nil {
					ctx = ContextWithSpanContext(ctx, sc)
				}
			}
			ctx, span := tracer.StartSpan(ctx, r.Method+" "+r.URL.Path,
				String("http.method", r.Method),
				String("http.target", r.URL.Path),
				String("http.host", r.Host),
			)
			defer span.End()

			// Echo the active SpanContext back to the caller so they
			// can correlate logs without inspecting bodies.
			w.Header().Set(W3CTraceparentHeader, FormatTraceparent(span.Context()))

			sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r.WithContext(ctx))
			span.SetAttribute("http.status_code", strconv.Itoa(sw.status))
			if sw.status >= 500 {
				span.SetError(httpStatusError(sw.status))
			}
		})
	}
}

// statusRecorder captures the response status code so the middleware
// can tag the server span with it.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WriteHeader records the status and forwards the call.
func (s *statusRecorder) WriteHeader(status int) {
	if !s.wroteHeader {
		s.status = status
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(status)
}

// Write forwards to the wrapped ResponseWriter.
func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.status = http.StatusOK
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

type httpStatusErrorVal int

func (e httpStatusErrorVal) Error() string { return "http status " + strconv.Itoa(int(e)) }

func httpStatusError(code int) error { return httpStatusErrorVal(code) }

// InjectHTTP writes the SpanContext into outbound HTTP headers using
// the W3C traceparent format.
func InjectHTTP(h http.Header, sc SpanContext) {
	tp := FormatTraceparent(sc)
	if tp == "" {
		return
	}
	h.Set(W3CTraceparentHeader, tp)
}

// ExtractHTTP reads the SpanContext from inbound HTTP headers.
func ExtractHTTP(h http.Header) (SpanContext, bool) {
	tp := h.Get(W3CTraceparentHeader)
	if tp == "" {
		return SpanContext{}, false
	}
	sc, err := ParseTraceparent(tp)
	if err != nil {
		return SpanContext{}, false
	}
	return sc, true
}
