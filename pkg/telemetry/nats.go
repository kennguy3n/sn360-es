package telemetry

// NATSHeaders is an abstraction over the *nats.Header type used by the
// nats.go client. The telemetry package does not import the NATS SDK
// directly so it can compile in build configurations where the SDK
// isn't available; instead, callers wrap their nats.Header in this
// minimal interface.
type NATSHeaders interface {
	Get(key string) string
	Set(key, value string)
}

// InjectNATS writes the SpanContext into the NATS message headers
// using the W3C traceparent format. A nil headers value is a no-op so
// callers can plug this in without conditional checks.
func InjectNATS(h NATSHeaders, sc SpanContext) {
	if h == nil {
		return
	}
	tp := FormatTraceparent(sc)
	if tp == "" {
		return
	}
	h.Set(W3CTraceparentHeader, tp)
}

// ExtractNATS reads the SpanContext from incoming NATS message headers.
func ExtractNATS(h NATSHeaders) (SpanContext, bool) {
	if h == nil {
		return SpanContext{}, false
	}
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

// MapHeaders is a simple map-backed implementation of NATSHeaders used
// by tests and any caller that wants a portable headers container
// without depending on the NATS SDK.
type MapHeaders map[string]string

// Get implements NATSHeaders.
func (m MapHeaders) Get(key string) string {
	if m == nil {
		return ""
	}
	return m[key]
}

// Set implements NATSHeaders.
func (m MapHeaders) Set(key, value string) {
	if m == nil {
		return
	}
	m[key] = value
}
