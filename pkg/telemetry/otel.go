// Package telemetry: OTel SDK bridge.
//
// The core Tracer in tracer.go is dependency-free and speaks the W3C
// traceparent contract directly. That's intentional — it lets the
// service boot in any environment, including local dev and CI,
// without requiring an OTel collector.
//
// In production we DO want spans flowing to a collector (Jaeger,
// Tempo, Datadog, etc.) so SRE can hop between the dashboard and
// trace view. This file provides an OPTIONAL bridge: when the
// operator sets OTEL_EXPORTER_OTLP_ENDPOINT (the standard OTel env
// var), NewOTLPBridge constructs an Exporter that funnels every
// finished SpanData through a real OTel SDK BatchSpanProcessor
// and out the OTLP/HTTP wire to the configured collector.
//
// The bridge preserves trace IDs, span IDs, parent IDs and
// attributes 1:1 by using tracetest.SpanStub.Snapshot() to construct
// a ReadOnlySpan and handing it directly to the processor —
// short-circuiting the SDK's tracer (which would otherwise mint a
// new span ID and break SN360-ES → collector trace correlation).
//
// Wire-up:
//
//	cfg := telemetry.OTLPBridgeConfig{
//	  Endpoint:       os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
//	  ServiceName:    "sn360-es",
//	  ServiceVersion: build.Version,
//	  Environment:    os.Getenv("DEPLOY_ENV"),
//	}
//	exp, shutdown, err := telemetry.NewOTLPBridge(ctx, cfg)
//	if err != nil { return err }
//	defer shutdown(context.Background())
//	tr := telemetry.NewTracer(telemetry.TracerConfig{
//	  ServiceName: "sn360-es", Exporter: exp,
//	})
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is unset, the caller should NOT
// construct a bridge — it should pass the default NoopExporter (or
// the in-memory exporter for tests). The core tracer continues to
// work unchanged.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// OTLPBridgeConfig configures the OTel SDK bridge.
type OTLPBridgeConfig struct {
	// Endpoint is the OTLP/HTTP endpoint, e.g.
	// "http://otel-collector:4318" or
	// "https://otlp.example.com". Must include the scheme.
	Endpoint string
	// ServiceName, ServiceVersion, Environment populate the OTel
	// resource attributes (service.name, service.version,
	// deployment.environment). ServiceName defaults to "sn360-es".
	ServiceName    string
	ServiceVersion string
	Environment    string
	// Headers is an optional map of HTTP headers attached to every
	// OTLP/HTTP export request — used by hosted collectors that
	// expect an "Authorization" / "X-DD-API-KEY" / etc. header.
	Headers map[string]string
	// Insecure forces HTTP (no TLS). Defaults derived from the
	// Endpoint scheme; set explicitly only to override.
	Insecure bool
}

// ShutdownFunc gracefully drains the OTLP bridge — it calls
// ForceFlush on the SpanProcessor and Shutdown on the OTLP exporter
// so spans in flight are not dropped on a normal shutdown.
type ShutdownFunc func(ctx context.Context) error

// otlpBridgeExporter is the telemetry.Exporter that forwards
// SpanData to the OTel SDK BatchSpanProcessor.
type otlpBridgeExporter struct {
	processor sdktrace.SpanProcessor
	resource  *resource.Resource
}

// ExportSpan re-emits the finished SN360 span as an OTel SDK
// ReadOnlySpan via the bridge processor. Trace/span IDs and parent
// linkage are preserved 1:1 so the collector sees the same trace
// topology SN360-ES recorded internally.
func (e *otlpBridgeExporter) ExportSpan(s SpanData) {
	traceID, err := oteltrace.TraceIDFromHex(s.TraceID)
	if err != nil {
		// Corrupt trace ID — drop the span rather than emit a
		// trace fragment that won't correlate with anything.
		return
	}
	spanID, err := oteltrace.SpanIDFromHex(s.SpanID)
	if err != nil {
		return
	}
	var parentSpanID oteltrace.SpanID
	if s.ParentID != "" {
		if pid, err := oteltrace.SpanIDFromHex(s.ParentID); err == nil {
			parentSpanID = pid
		}
	}

	attrs := make([]attribute.KeyValue, 0, len(s.Attributes))
	for k, v := range s.Attributes {
		attrs = append(attrs, attribute.String(k, v))
	}

	status := sdktrace.Status{Code: codes.Unset}
	switch strings.ToLower(s.Status) {
	case "ok":
		status.Code = codes.Ok
	case "error":
		status.Code = codes.Error
		status.Description = s.Err
	}

	stub := tracetest.SpanStub{
		Name: s.Name,
		SpanContext: oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     spanID,
			TraceFlags: oteltrace.FlagsSampled,
		}),
		Parent: oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     parentSpanID,
			TraceFlags: oteltrace.FlagsSampled,
		}),
		SpanKind:   oteltrace.SpanKindInternal,
		StartTime:  s.Start,
		EndTime:    s.End,
		Attributes: attrs,
		Status:     status,
		Resource:   e.resource,
		// InstrumentationScope populated so the collector can
		// route on it (Datadog uses this to pick the service tag
		// path; Jaeger surfaces it in the span detail panel).
		InstrumentationScope: instrumentation.Scope{
			Name:    "github.com/kennguy3n/sn360-es/pkg/telemetry",
			Version: "v1",
		},
	}
	e.processor.OnEnd(stub.Snapshot())
}

// NewOTLPBridge constructs an Exporter that ships SpanData to the
// configured OTLP/HTTP endpoint. Returns (exporter, shutdown, nil)
// on success. The shutdown func MUST be called on graceful
// termination — without it, batched spans in the processor are
// lost.
func NewOTLPBridge(ctx context.Context, cfg OTLPBridgeConfig) (Exporter, ShutdownFunc, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, nil, errors.New("telemetry: OTLP bridge requires a non-empty Endpoint")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("telemetry: parse OTLP endpoint %q: %w", cfg.Endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil, fmt.Errorf("telemetry: OTLP endpoint %q must use http or https scheme", cfg.Endpoint)
	}
	insecure := cfg.Insecure || u.Scheme == "http"

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(cfg.Endpoint),
		// Block-on-startup gives clearer errors than discovering a
		// bad endpoint via dropped spans in production.
		otlptracehttp.WithTimeout(10 * time.Second),
	}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}

	client := otlptracehttp.NewClient(opts...)
	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, nil, fmt.Errorf("telemetry: init OTLP/HTTP exporter: %w", err)
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "sn360-es"
	}
	attrs := []attribute.KeyValue{semconv.ServiceName(serviceName)}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}
	if cfg.Environment != "" {
		attrs = append(attrs, semconv.DeploymentEnvironment(cfg.Environment))
	}
	res, err := resource.New(ctx, resource.WithAttributes(attrs...))
	if err != nil {
		return nil, nil, fmt.Errorf("telemetry: build OTel resource: %w", err)
	}

	processor := sdktrace.NewBatchSpanProcessor(exp,
		// 5s batch window — short enough that an outage surfaces
		// quickly in the collector, long enough to amortise the
		// OTLP/HTTP round-trip cost across high-throughput tier1
		// scoring.
		sdktrace.WithBatchTimeout(5*time.Second),
		// 2048 queued spans before backpressure / drop. Each span
		// is ~1 KB so this caps the in-memory buffer around 2 MB
		// per replica — well within request memory.
		sdktrace.WithMaxQueueSize(2048),
		sdktrace.WithMaxExportBatchSize(512),
	)

	bridge := &otlpBridgeExporter{processor: processor, resource: res}

	shutdown := func(sctx context.Context) error {
		// Flush in-flight spans BEFORE shutting down the exporter
		// — Shutdown calls underlying Close() on the HTTP client
		// which would otherwise drop the in-flight batch.
		var errs []error
		if ferr := processor.ForceFlush(sctx); ferr != nil {
			errs = append(errs, fmt.Errorf("flush bridge processor: %w", ferr))
		}
		if perr := processor.Shutdown(sctx); perr != nil {
			errs = append(errs, fmt.Errorf("shutdown bridge processor: %w", perr))
		}
		return errors.Join(errs...)
	}
	return bridge, shutdown, nil
}
