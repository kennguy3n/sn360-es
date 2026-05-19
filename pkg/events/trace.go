package events

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// WithTraceContext injects the W3C Trace Context headers
// (traceparent and tracestate) extracted from ctx into the outbound
// publish so a consumer can reconstruct the span on the other side.
//
// The propagator is the global one configured via
// otel.SetTextMapPropagator. When nothing is configured (or the
// context has no active span), no headers are added — the option is
// effectively a no-op rather than an error, since trace propagation
// is best-effort observability.
func WithTraceContext(ctx context.Context) PublishOption {
	return func(o *PublishOptions) {
		prop := otel.GetTextMapPropagator()
		if prop == nil {
			return
		}
		if o.Headers == nil {
			o.Headers = map[string]string{}
		}
		carrier := mapCarrier(o.Headers)
		prop.Inject(ctx, carrier)
	}
}

// ExtractTraceContext returns a context derived from parent that
// carries the W3C Trace Context reconstructed from carrier. The
// resulting context's span is what subsequent spans should be
// attached to. When no traceparent header is present, parent is
// returned unchanged.
func ExtractTraceContext(parent context.Context, carrier map[string]string) context.Context {
	prop := otel.GetTextMapPropagator()
	if prop == nil || len(carrier) == 0 {
		return parent
	}
	return prop.Extract(parent, mapCarrier(carrier))
}

// mapCarrier adapts a plain map[string]string to the otel
// TextMapCarrier interface. It is the only carrier we need across
// the bus — header values are scalar strings.
type mapCarrier map[string]string

func (c mapCarrier) Get(key string) string { return c[key] }
func (c mapCarrier) Set(key, value string) { c[key] = value }
func (c mapCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	return keys
}

// Compile-time assertion that mapCarrier implements TextMapCarrier.
var _ propagation.TextMapCarrier = (mapCarrier)(nil)
