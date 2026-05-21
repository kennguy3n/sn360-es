package telemetry

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

// fakeOTLPCollector is an httptest server that decodes the
// OTLP/HTTP protobuf payload and records every span that the
// bridge exported. Used to verify the bridge actually serialises
// spans the way the OpenTelemetry collector expects.
type fakeOTLPCollector struct {
	mu     sync.Mutex
	spans  []recordedSpan
	server *httptest.Server
}

type recordedSpan struct {
	TraceID    string
	SpanID     string
	ParentID   string
	Name       string
	Attributes map[string]string
}

func newFakeOTLPCollector() *fakeOTLPCollector {
	f := &fakeOTLPCollector{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", f.handle)
	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeOTLPCollector) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req collectortrace.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "proto unmarshal: "+err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rs := range req.ResourceSpans {
		for _, sc := range rs.ScopeSpans {
			for _, sp := range sc.Spans {
				attrs := make(map[string]string, len(sp.Attributes))
				for _, a := range sp.Attributes {
					if a.Value == nil {
						continue
					}
					attrs[a.Key] = a.Value.GetStringValue()
				}
				f.spans = append(f.spans, recordedSpan{
					TraceID:    hex.EncodeToString(sp.TraceId),
					SpanID:     hex.EncodeToString(sp.SpanId),
					ParentID:   hex.EncodeToString(sp.ParentSpanId),
					Name:       sp.Name,
					Attributes: attrs,
				})
			}
		}
	}
	resp, _ := proto.Marshal(&collectortrace.ExportTraceServiceResponse{})
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func (f *fakeOTLPCollector) close() { f.server.Close() }

func (f *fakeOTLPCollector) recorded() []recordedSpan {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedSpan, len(f.spans))
	copy(out, f.spans)
	return out
}

func TestOTLPBridge_PreservesTraceTopology(t *testing.T) {
	t.Parallel()
	collector := newFakeOTLPCollector()
	defer collector.close()

	ctx := context.Background()
	exp, shutdown, err := NewOTLPBridge(ctx, OTLPBridgeConfig{
		Endpoint:       collector.server.URL,
		ServiceName:    "sn360-es-test",
		ServiceVersion: "v0.0.1",
		Environment:    "test",
	})
	if err != nil {
		t.Fatalf("NewOTLPBridge: %v", err)
	}
	// Deferred bail-out: only runs if the explicit shutdown below
	// never executes (e.g. an intermediate t.Fatalf). After the
	// explicit shutdown we nil the var so this defer is a no-op —
	// otherwise a future OTel SDK that returns ErrShutdown from a
	// second Shutdown call would flip the deferred t.Fatalf even
	// though the test had already passed.
	defer func() {
		if shutdown == nil {
			return
		}
		if cerr := shutdown(context.Background()); cerr != nil {
			t.Fatalf("shutdown: %v", cerr)
		}
	}()

	tr := NewTracer(TracerConfig{ServiceName: "sn360-es-test", Exporter: exp})
	pctx, parent := tr.StartSpan(ctx, "tier1.score")
	parent.SetAttribute("tenant_id", "acme")
	_, child := tr.StartSpan(pctx, "tier1.rspamd")
	child.SetAttribute("score", "9.4")
	child.End()
	parent.End()

	flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(flushCtx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	shutdown = nil

	got := collector.recorded()
	if len(got) != 2 {
		t.Fatalf("expected 2 spans exported, got %d", len(got))
	}
	byName := map[string]recordedSpan{}
	for _, s := range got {
		byName[s.Name] = s
	}
	root, ok := byName["tier1.score"]
	if !ok {
		t.Fatalf("missing tier1.score span; recorded names: %v", recordedNames(got))
	}
	if !strings.EqualFold(strings.Repeat("0", 32-len(root.TraceID))+root.TraceID, root.TraceID) && len(root.TraceID) != 32 {
		t.Fatalf("root trace id wrong length: %q", root.TraceID)
	}
	rspamd, ok := byName["tier1.rspamd"]
	if !ok {
		t.Fatalf("missing tier1.rspamd span; recorded names: %v", recordedNames(got))
	}
	if rspamd.TraceID != root.TraceID {
		t.Fatalf("child trace id %q does not match parent %q", rspamd.TraceID, root.TraceID)
	}
	if rspamd.ParentID != root.SpanID {
		t.Fatalf("child parent_span_id %q does not match root span_id %q", rspamd.ParentID, root.SpanID)
	}
	if rspamd.Attributes["score"] != "9.4" {
		t.Fatalf("rspamd score attribute lost: %v", rspamd.Attributes)
	}
	if root.Attributes["tenant_id"] != "acme" {
		t.Fatalf("root tenant_id attribute lost: %v", root.Attributes)
	}
}

func recordedNames(spans []recordedSpan) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.Name)
	}
	return out
}

func TestOTLPBridge_RejectsBadEndpoint(t *testing.T) {
	t.Parallel()
	if _, _, err := NewOTLPBridge(context.Background(), OTLPBridgeConfig{Endpoint: ""}); err == nil {
		t.Fatal("expected error on empty endpoint")
	}
	if _, _, err := NewOTLPBridge(context.Background(), OTLPBridgeConfig{Endpoint: "ftp://bad-scheme"}); err == nil {
		t.Fatal("expected error on non-http/https scheme")
	}
}
