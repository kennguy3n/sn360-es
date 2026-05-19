package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// ctxKeyCorrelationID carries the per-request correlation ID once it
// has been resolved by RequestID. The value is always a non-empty
// string when present.
const ctxKeyCorrelationID ctxKey = "sn360.correlation_id"

// CorrelationIDHeader is the HTTP header used to propagate the
// correlation ID inbound and outbound.
const CorrelationIDHeader = "X-Correlation-ID"

// CorrelationIDFromContext returns the correlation ID attached to ctx
// by RequestID, or "" if the request did not pass through RequestID.
func CorrelationIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyCorrelationID).(string)
	return v
}

// withCorrelationID is exported only for tests that need to inject a
// correlation ID without going through HTTP.
func withCorrelationID(ctx context.Context, cid string) context.Context {
	return context.WithValue(ctx, ctxKeyCorrelationID, cid)
}

// RequestID is an HTTP middleware that resolves a correlation ID for
// every request, attaches it to r.Context(), and echoes it back on
// the response so downstream callers can correlate logs across the
// hop.
//
// Resolution order:
//
//  1. Trimmed value of the X-Correlation-ID request header, when
//     non-empty.
//  2. A fresh UUID v4 generated via crypto/rand (github.com/google/uuid).
//
// RequestID should sit immediately outside RequestLogger so the
// correlation ID is available on every log record, including 4xx /
// 5xx responses produced by inner middleware.
type RequestID struct {
	next   http.Handler
	newID  func() string
	header string
}

// NewRequestID wraps next with the request-ID middleware.
func NewRequestID(next http.Handler) *RequestID {
	return &RequestID{
		next:   next,
		newID:  uuid.NewString,
		header: CorrelationIDHeader,
	}
}

// maxInboundCorrelationIDLen caps the size of a caller-supplied
// correlation ID. The limit is generous compared with a UUID (36
// chars) so realistic upstreams that prefix the ID with a service
// name still fit, while keeping the value cheap to log and rejecting
// anything that could only be a probe.
const maxInboundCorrelationIDLen = 128

// ServeHTTP implements http.Handler.
func (m *RequestID) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cid := sanitizeInboundCID(r.Header.Get(m.header))
	if cid == "" {
		cid = m.newID()
	}
	w.Header().Set(m.header, cid)
	ctx := context.WithValue(r.Context(), ctxKeyCorrelationID, cid)
	m.next.ServeHTTP(w, r.WithContext(ctx))
}

// sanitizeInboundCID returns the trimmed correlation-ID value when it
// is safe to echo back, or "" when the caller should fall back to a
// generated UUID. We reject:
//
//   - leading/trailing whitespace (trimmed and re-checked).
//   - empty strings.
//   - strings longer than maxInboundCorrelationIDLen.
//   - any character outside printable ASCII (U+0020..U+007E).
//
// The printable-ASCII filter is what stops a caller from smuggling
// CR/LF or other control bytes back into our response headers; Go's
// net/http does eventually reject malformed header values on the
// wire, but that produces an internal write error rather than a
// clean 400, so it's better to drop the offending value here.
func sanitizeInboundCID(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" || len(v) > maxInboundCorrelationIDLen {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x20 || c > 0x7E {
			return ""
		}
	}
	return v
}
