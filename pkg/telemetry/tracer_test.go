package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAndFormatTraceparent_Roundtrip(t *testing.T) {
	sc := SpanContext{TraceID: "0af7651916cd43dd8448eb211c80319c", SpanID: "b7ad6b7169203331", Sampled: true}
	v := FormatTraceparent(sc)
	if v != "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01" {
		t.Fatalf("format: %q", v)
	}
	got, err := ParseTraceparent(v)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != sc {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, sc)
	}
}

func TestParseTraceparent_RejectsBadInput(t *testing.T) {
	cases := []string{
		"",
		"00-foo",
		"00-shorttrace-b7ad6b7169203331-01",
		"00-0af7651916cd43dd8448eb211c80319c-shortspan-01",
	}
	for _, c := range cases {
		if _, err := ParseTraceparent(c); err == nil {
			t.Fatalf("expected error for %q", c)
		}
	}
}

func TestTracer_StartSpan_PropagatesParent(t *testing.T) {
	exp := NewInMemoryExporter()
	tr := NewTracer(TracerConfig{ServiceName: "test", Exporter: exp})

	parentCtx, parent := tr.StartSpan(context.Background(), "parent")
	_, child := tr.StartSpan(parentCtx, "child")
	child.SetAttribute("foo", "bar")
	child.End()
	parent.End()

	spans := exp.Spans()
	if len(spans) != 2 {
		t.Fatalf("spans: %d", len(spans))
	}
	// Child is exported first, parent second.
	c, p := spans[0], spans[1]
	if c.Name != "child" || p.Name != "parent" {
		t.Fatalf("names: %q / %q", c.Name, p.Name)
	}
	if c.TraceID != p.TraceID {
		t.Fatalf("trace ids differ: %q vs %q", c.TraceID, p.TraceID)
	}
	if c.ParentID != p.SpanID {
		t.Fatalf("child parent_id %q != parent span_id %q", c.ParentID, p.SpanID)
	}
	if c.Attributes["foo"] != "bar" {
		t.Fatalf("attribute lost: %+v", c.Attributes)
	}
}

func TestTracer_SetError(t *testing.T) {
	exp := NewInMemoryExporter()
	tr := NewTracer(TracerConfig{Exporter: exp})
	_, span := tr.StartSpan(context.Background(), "boom")
	span.SetError(errors.New("kaboom"))
	span.End()
	got := exp.Spans()[0]
	if got.Status != "error" || got.Err != "kaboom" {
		t.Fatalf("status/err: %q / %q", got.Status, got.Err)
	}
}

func TestSampler_Probability_Deterministic(t *testing.T) {
	s := ProbabilitySampler(0.5).(*probabilitySampler)
	// Deterministic per trace ID, parent-based sampler skipped if no
	// parent context — confirm extreme values work.
	if !AlwaysOn().ShouldSample(context.Background(), "x") {
		t.Fatal("AlwaysOn should sample")
	}
	if NeverOn().ShouldSample(context.Background(), "x") {
		t.Fatal("NeverOn should not sample")
	}
	// Run with a context-attached SpanContext so the probabilistic
	// sampler can derive its decision.
	ctx := ContextWithSpanContext(context.Background(), SpanContext{
		TraceID: "ffffffffffffffffffffffffffffffff",
		SpanID:  "ffffffffffffffff",
	})
	first := s.ShouldSample(ctx, "x")
	second := s.ShouldSample(ctx, "x")
	if first != second {
		t.Fatalf("expected deterministic decisions, got %v / %v", first, second)
	}
}

func TestHTTPMiddleware_PropagatesAndStarts(t *testing.T) {
	exp := NewInMemoryExporter()
	tr := NewTracer(TracerConfig{Exporter: exp})

	var seen SpanContext
	h := HTTPMiddleware(tr)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc, _ := SpanContextFromContext(r.Context())
		seen = sc
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	req.Header.Set(W3CTraceparentHeader, "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if seen.TraceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Fatalf("trace id: %q", seen.TraceID)
	}
	if rr.Header().Get(W3CTraceparentHeader) == "" {
		t.Fatal("response missing traceparent")
	}
	spans := exp.Spans()
	if len(spans) != 1 {
		t.Fatalf("spans: %d", len(spans))
	}
	if spans[0].Attributes["http.status_code"] != "200" {
		t.Fatalf("status attr: %q", spans[0].Attributes["http.status_code"])
	}
}

func TestHTTPMiddleware_RecordsErrorOn5xx(t *testing.T) {
	exp := NewInMemoryExporter()
	tr := NewTracer(TracerConfig{Exporter: exp})

	h := HTTPMiddleware(tr)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	span := exp.Spans()[0]
	if span.Status != "error" {
		t.Fatalf("status: %q", span.Status)
	}
	if span.Attributes["http.status_code"] != "502" {
		t.Fatalf("status attr: %q", span.Attributes["http.status_code"])
	}
}

func TestNATSHeaders_Roundtrip(t *testing.T) {
	h := MapHeaders{}
	sc := SpanContext{TraceID: "0af7651916cd43dd8448eb211c80319c", SpanID: "b7ad6b7169203331", Sampled: true}
	InjectNATS(h, sc)
	if h[W3CTraceparentHeader] == "" {
		t.Fatal("missing header")
	}
	got, ok := ExtractNATS(h)
	if !ok {
		t.Fatal("extract failed")
	}
	if got != sc {
		t.Fatalf("roundtrip: %+v vs %+v", got, sc)
	}
	if _, ok := ExtractNATS(MapHeaders{}); ok {
		t.Fatal("empty headers should not extract")
	}
}
