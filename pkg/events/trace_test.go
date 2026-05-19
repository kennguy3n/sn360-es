package events_test

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// TestWithTraceContext_RoundTrip wires the global TextMapPropagator to
// the W3C TraceContext propagator, then verifies that:
//   - WithTraceContext writes traceparent into PublishOptions.Headers
//     when called against a context carrying an active span.
//   - ExtractTraceContext rebuilds a remote span context on the
//     consumer side that has the same trace + span IDs.
//
// This exercises the real otel propagation path — no mocks — so a
// regression in either the publish-side WithTraceContext option or
// the consume-side ExtractTraceContext helper would be caught here.
func TestWithTraceContext_RoundTrip(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(propagation.TraceContext{}) })

	// Pin a known SpanContext on the producer side via a manually
	// constructed remote span. Real production traffic gets this from
	// the otel SDK; using a fixture lets us assert the precise IDs.
	traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	if err != nil {
		t.Fatalf("trace id: %v", err)
	}
	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	if err != nil {
		t.Fatalf("span id: %v", err)
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	parent := trace.ContextWithRemoteSpanContext(context.Background(), sc)

	opts := events.ResolvePublishOptions(events.PublishOptions{}, events.WithTraceContext(parent))
	tp, ok := opts.Headers[events.HeaderTraceparent]
	if !ok || tp == "" {
		t.Fatalf("expected %s header to be set after WithTraceContext; headers=%v", events.HeaderTraceparent, opts.Headers)
	}

	// Round-trip back through ExtractTraceContext on the consume side.
	rebuilt := events.ExtractTraceContext(context.Background(), opts.Headers)
	got := trace.SpanContextFromContext(rebuilt)
	if !got.IsValid() {
		t.Fatalf("extracted span context is invalid: %#v", got)
	}
	if got.TraceID() != traceID {
		t.Fatalf("trace id mismatch: got=%s want=%s", got.TraceID(), traceID)
	}
	if got.SpanID() != spanID {
		t.Fatalf("span id mismatch: got=%s want=%s", got.SpanID(), spanID)
	}
}

// TestWithTraceContext_NoOpWithoutSpan asserts that calling
// WithTraceContext against a context without any active span does
// not inject a malformed traceparent header — observability is
// best-effort, so a missing span is silently skipped rather than
// written as "00-00..-00..-00".
func TestWithTraceContext_NoOpWithoutSpan(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(propagation.TraceContext{}) })

	opts := events.ResolvePublishOptions(events.PublishOptions{}, events.WithTraceContext(context.Background()))
	if tp, ok := opts.Headers[events.HeaderTraceparent]; ok {
		t.Fatalf("did not expect traceparent header for bare context; got %q", tp)
	}
}

// TestContextHelpers verifies the bus-side context value bag. The
// helpers are dead simple but the test pins their wire contract so
// future refactors (e.g. switching keys, dropping a helper) trip a
// real test rather than silently breaking consumers that depend on
// the values being present.
func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	if events.CorrelationIDFromContext(ctx) != "" {
		t.Fatalf("expected empty correlation id on bare ctx")
	}
	ctx = events.WithCorrelationIDContext(ctx, "corr-1")
	ctx = events.WithTenantIDContext(ctx, "tenant-1")
	ctx = events.WithMessageIDContext(ctx, "msg-1")
	ctx = events.WithEventTypeContext(ctx, "es.evaluate.request")

	if got := events.CorrelationIDFromContext(ctx); got != "corr-1" {
		t.Fatalf("correlation id: got %q want corr-1", got)
	}
	if got := events.TenantIDFromContext(ctx); got != "tenant-1" {
		t.Fatalf("tenant id: got %q want tenant-1", got)
	}
	if got := events.MessageIDFromContext(ctx); got != "msg-1" {
		t.Fatalf("message id: got %q want msg-1", got)
	}
	if got := events.EventTypeFromContext(ctx); got != "es.evaluate.request" {
		t.Fatalf("event type: got %q want es.evaluate.request", got)
	}

	// Empty values are silently dropped so the helpers don't store
	// useless zero values that downstream code would have to filter.
	empty := events.WithCorrelationIDContext(context.Background(), "")
	if got := events.CorrelationIDFromContext(empty); got != "" {
		t.Fatalf("empty correlation id should not be stored; got %q", got)
	}
}
