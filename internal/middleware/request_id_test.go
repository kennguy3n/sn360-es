package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubHandler captures the inbound request so a test can assert against
// it after the middleware has run.
type stubHandler struct {
	saw *http.Request
}

func (s *stubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.saw = r
	w.WriteHeader(http.StatusNoContent)
}

func TestRequestID_PreservesIncomingHeader(t *testing.T) {
	const want = "deadbeef-1234-5678-9abc-deadbeefcafe"
	inner := &stubHandler{}
	m := NewRequestID(inner)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(CorrelationIDHeader, want)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if got := rr.Header().Get(CorrelationIDHeader); got != want {
		t.Fatalf("response header = %q, want %q", got, want)
	}
	if inner.saw == nil {
		t.Fatalf("inner handler was not invoked")
	}
	if got := CorrelationIDFromContext(inner.saw.Context()); got != want {
		t.Fatalf("context correlation_id = %q, want %q", got, want)
	}
}

func TestRequestID_GeneratesWhenMissing(t *testing.T) {
	inner := &stubHandler{}
	m := NewRequestID(inner)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	got := rr.Header().Get(CorrelationIDHeader)
	if got == "" {
		t.Fatalf("expected generated correlation ID on response, got empty")
	}
	if inner.saw == nil {
		t.Fatalf("inner handler was not invoked")
	}
	ctxID := CorrelationIDFromContext(inner.saw.Context())
	if ctxID != got {
		t.Fatalf("context correlation_id = %q, want %q (matching response header)", ctxID, got)
	}
	// UUID v4 in canonical form: 8-4-4-4-12 hex chars.
	if len(got) != 36 || strings.Count(got, "-") != 4 {
		t.Fatalf("generated correlation_id %q does not look like a UUID", got)
	}
}

func TestRequestID_WhitespaceTreatedAsAbsent(t *testing.T) {
	inner := &stubHandler{}
	m := NewRequestID(inner)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(CorrelationIDHeader, "   \t  ")
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	got := rr.Header().Get(CorrelationIDHeader)
	if got == "" {
		t.Fatalf("expected generated correlation ID, got empty")
	}
	if strings.ContainsAny(got, " \t") {
		t.Fatalf("generated correlation_id %q should not contain whitespace", got)
	}
	if got := CorrelationIDFromContext(inner.saw.Context()); strings.ContainsAny(got, " \t") || got == "" {
		t.Fatalf("context correlation_id = %q, want non-empty without whitespace", got)
	}
}

func TestRequestID_NewIDOverride(t *testing.T) {
	const stub = "stub-id"
	inner := &stubHandler{}
	m := NewRequestID(inner)
	m.newID = func() string { return stub }

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if got := rr.Header().Get(CorrelationIDHeader); got != stub {
		t.Fatalf("response header = %q, want %q", got, stub)
	}
	if got := CorrelationIDFromContext(inner.saw.Context()); got != stub {
		t.Fatalf("context correlation_id = %q, want %q", got, stub)
	}
}

func TestCorrelationIDFromContext_EmptyWhenUnset(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if got := CorrelationIDFromContext(req.Context()); got != "" {
		t.Fatalf("expected empty correlation_id on bare context, got %q", got)
	}
}

// TestRequestID_RejectsControlCharacters covers the
// sanitizeInboundCID guard: a caller-supplied X-Correlation-ID that
// contains CR / LF / NUL or any other non-printable byte is dropped
// (so it cannot smuggle a header-split into the response) and a fresh
// UUID is generated instead. The "stub" injected ID is used to prove
// the new ID path ran.
func TestRequestID_RejectsControlCharacters(t *testing.T) {
	const stub = "stub-generated-id"
	cases := map[string]string{
		"newline": "abc\nxyz",
		"cr":      "abc\rxyz",
		"crlf":    "abc\r\nxyz",
		"nul":     "abc\x00xyz",
		"tabmid":  "abc\txyz",
		"highbit": "abc\x80xyz",
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			inner := &stubHandler{}
			m := NewRequestID(inner)
			m.newID = func() string { return stub }

			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set(CorrelationIDHeader, bad)
			rr := httptest.NewRecorder()
			m.ServeHTTP(rr, req)

			if got := rr.Header().Get(CorrelationIDHeader); got != stub {
				t.Fatalf("response header = %q, want %q (sanitizer should have dropped %q)", got, stub, bad)
			}
			if got := CorrelationIDFromContext(inner.saw.Context()); got != stub {
				t.Fatalf("context correlation_id = %q, want %q", got, stub)
			}
		})
	}
}

// TestRequestID_RejectsOversizedHeader proves the length cap.
func TestRequestID_RejectsOversizedHeader(t *testing.T) {
	const stub = "stub-generated-id"
	inner := &stubHandler{}
	m := NewRequestID(inner)
	m.newID = func() string { return stub }

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(CorrelationIDHeader, strings.Repeat("a", maxInboundCorrelationIDLen+1))
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if got := rr.Header().Get(CorrelationIDHeader); got != stub {
		t.Fatalf("response header = %q, want %q", got, stub)
	}
}
