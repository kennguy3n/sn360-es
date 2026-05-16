// Package telemetry provides the OpenTelemetry tracing helpers used
// across SN360-ES (PROPOSAL.md §8 and ARCHITECTURE.md §6.2).
//
// The package is intentionally dependency-free of any specific OTel
// exporter — it speaks the W3C `traceparent` header format directly,
// builds spans in-memory, and exposes hooks so a downstream wire-up
// can route spans to OTLP, stdout, or any other sink. This keeps the
// core service buildable in environments without OpenTelemetry SDK
// availability while preserving the on-the-wire contract.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Sampler decides whether to record a span. The default sampler
// records every span (parent-based sampling lives in the OTLP
// exporter layer).
type Sampler interface {
	ShouldSample(ctx context.Context, name string) bool
}

// alwaysOn samples every span.
type alwaysOn struct{}

// ShouldSample implements Sampler.
func (alwaysOn) ShouldSample(context.Context, string) bool { return true }

// neverOn samples no spans (useful for tests).
type neverOn struct{}

// ShouldSample implements Sampler.
func (neverOn) ShouldSample(context.Context, string) bool { return false }

// AlwaysOn returns the always-on sampler.
func AlwaysOn() Sampler { return alwaysOn{} }

// NeverOn returns the off sampler.
func NeverOn() Sampler { return neverOn{} }

// ProbabilitySampler returns a sampler that records spans with the
// given probability (0.0 .. 1.0). Decisions are deterministic per
// trace ID so child spans inherit the parent decision.
func ProbabilitySampler(p float64) Sampler {
	if p <= 0 {
		return neverOn{}
	}
	if p >= 1 {
		return alwaysOn{}
	}
	return &probabilitySampler{p: p}
}

type probabilitySampler struct{ p float64 }

func (s *probabilitySampler) ShouldSample(ctx context.Context, _ string) bool {
	sc, ok := SpanContextFromContext(ctx)
	if !ok {
		return false
	}
	// Deterministic decision: project the first 8 bytes of the trace
	// ID onto [0,1) and compare against p.
	if len(sc.TraceID) < 16 {
		return false
	}
	x, _ := hex.DecodeString(sc.TraceID[:16])
	if len(x) < 8 {
		return false
	}
	var n uint64
	for _, b := range x[:8] {
		n = n<<8 | uint64(b)
	}
	frac := float64(n) / float64(uint64(1)<<63)
	return frac/2 < s.p
}

// TracerConfig wires the global tracer.
type TracerConfig struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	Sampler        Sampler
	Exporter       Exporter
}

// Exporter accepts finished spans. Real deployments use an OTLP
// exporter; tests and the default no-op build use the InMemoryExporter.
type Exporter interface {
	ExportSpan(s SpanData)
}

// Tracer is the entry point for span creation. It is safe for
// concurrent use.
type Tracer struct {
	cfg TracerConfig
	mu  sync.RWMutex
}

// SpanData is the immutable representation of a finished span.
type SpanData struct {
	TraceID    string
	SpanID     string
	ParentID   string
	Name       string
	Service    string
	Start      time.Time
	End        time.Time
	Duration   time.Duration
	Attributes map[string]string
	Status     string
	Err        string
}

// Span is a live span; close it with End().
type Span struct {
	tracer    *Tracer
	data      SpanData
	startTime time.Time
	closed    bool
	mu        sync.Mutex
}

// SpanContext is the propagation-only view of a span. It is the data
// embedded in W3C traceparent headers.
type SpanContext struct {
	TraceID  string
	SpanID   string
	Sampled  bool
}

// NewTracer constructs a Tracer. A nil sampler defaults to AlwaysOn,
// and a nil exporter defaults to a no-op exporter.
func NewTracer(cfg TracerConfig) *Tracer {
	if cfg.Sampler == nil {
		cfg.Sampler = AlwaysOn()
	}
	if cfg.Exporter == nil {
		cfg.Exporter = NoopExporter{}
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "sn360-es"
	}
	return &Tracer{cfg: cfg}
}

// StartSpan starts a new span as a child of any existing SpanContext
// in ctx. The returned context contains the new SpanContext for
// downstream propagation.
func (t *Tracer) StartSpan(ctx context.Context, name string, attrs ...Attribute) (context.Context, *Span) {
	now := time.Now().UTC()
	parent, hasParent := SpanContextFromContext(ctx)
	spanID, _ := newID(8)
	traceID := parent.TraceID
	if !hasParent || traceID == "" {
		traceID, _ = newID(16)
	}
	sampled := hasParent && parent.Sampled || t.cfg.Sampler.ShouldSample(ctx, name)
	sc := SpanContext{TraceID: traceID, SpanID: spanID, Sampled: sampled}
	s := &Span{
		tracer: t,
		data: SpanData{
			TraceID:    traceID,
			SpanID:     spanID,
			ParentID:   parent.SpanID,
			Name:       name,
			Service:    t.cfg.ServiceName,
			Start:      now,
			Attributes: map[string]string{},
		},
		startTime: now,
	}
	for _, a := range attrs {
		s.data.Attributes[a.Key] = a.Value
	}
	return ContextWithSpanContext(ctx, sc), s
}

// SetAttribute attaches a key/value to the span.
func (s *Span) SetAttribute(key, value string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Attributes == nil {
		s.data.Attributes = map[string]string{}
	}
	s.data.Attributes[key] = value
}

// SetError marks the span as errored.
func (s *Span) SetError(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Status = "error"
	s.data.Err = err.Error()
}

// End closes the span and pushes it to the exporter.
func (s *Span) End() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.data.End = time.Now().UTC()
	s.data.Duration = s.data.End.Sub(s.startTime)
	if s.data.Status == "" {
		s.data.Status = "ok"
	}
	cp := s.data
	s.mu.Unlock()
	if s.tracer != nil && s.tracer.cfg.Exporter != nil {
		s.tracer.cfg.Exporter.ExportSpan(cp)
	}
}

// Context returns the live SpanContext for the span.
func (s *Span) Context() SpanContext {
	if s == nil {
		return SpanContext{}
	}
	return SpanContext{TraceID: s.data.TraceID, SpanID: s.data.SpanID, Sampled: true}
}

// Attribute is one key/value pair on a span.
type Attribute struct {
	Key   string
	Value string
}

// String returns a string-valued attribute.
func String(k, v string) Attribute { return Attribute{Key: k, Value: v} }

// Int returns an integer-valued attribute encoded as a decimal string.
func Int(k string, v int) Attribute { return Attribute{Key: k, Value: fmt.Sprintf("%d", v)} }

// --- Context plumbing -----------------------------------------------------

type spanContextKey struct{}

// ContextWithSpanContext returns a new context with sc attached.
func ContextWithSpanContext(ctx context.Context, sc SpanContext) context.Context {
	return context.WithValue(ctx, spanContextKey{}, sc)
}

// SpanContextFromContext retrieves any SpanContext attached to ctx.
func SpanContextFromContext(ctx context.Context) (SpanContext, bool) {
	if ctx == nil {
		return SpanContext{}, false
	}
	v, ok := ctx.Value(spanContextKey{}).(SpanContext)
	return v, ok
}

// --- W3C traceparent ------------------------------------------------------

// FormatTraceparent encodes sc as a W3C `traceparent` header value.
// Format: 00-<32hex>-<16hex>-<flags 2hex>
func FormatTraceparent(sc SpanContext) string {
	if sc.TraceID == "" || sc.SpanID == "" {
		return ""
	}
	flags := "00"
	if sc.Sampled {
		flags = "01"
	}
	return "00-" + sc.TraceID + "-" + sc.SpanID + "-" + flags
}

// ParseTraceparent decodes a W3C `traceparent` value.
func ParseTraceparent(v string) (SpanContext, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return SpanContext{}, fmt.Errorf("telemetry: empty traceparent")
	}
	parts := strings.Split(v, "-")
	if len(parts) != 4 {
		return SpanContext{}, fmt.Errorf("telemetry: malformed traceparent")
	}
	if len(parts[1]) != 32 {
		return SpanContext{}, fmt.Errorf("telemetry: trace_id length %d", len(parts[1]))
	}
	if len(parts[2]) != 16 {
		return SpanContext{}, fmt.Errorf("telemetry: span_id length %d", len(parts[2]))
	}
	sampled := false
	if len(parts[3]) >= 2 && parts[3][1] == '1' {
		sampled = true
	}
	return SpanContext{TraceID: parts[1], SpanID: parts[2], Sampled: sampled}, nil
}

// --- ID generation --------------------------------------------------------

func newID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- Exporters ------------------------------------------------------------

// NoopExporter discards spans. Used as the default when no exporter is wired.
type NoopExporter struct{}

// ExportSpan implements Exporter.
func (NoopExporter) ExportSpan(SpanData) {}

// InMemoryExporter retains every exported span for inspection in tests.
type InMemoryExporter struct {
	mu    sync.Mutex
	spans []SpanData
}

// NewInMemoryExporter constructs an empty exporter.
func NewInMemoryExporter() *InMemoryExporter { return &InMemoryExporter{} }

// ExportSpan implements Exporter.
func (e *InMemoryExporter) ExportSpan(s SpanData) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spans = append(e.spans, s)
}

// Spans returns a snapshot of the recorded spans.
func (e *InMemoryExporter) Spans() []SpanData {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]SpanData, len(e.spans))
	copy(out, e.spans)
	return out
}
