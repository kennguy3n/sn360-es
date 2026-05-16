package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func newTestMetrics(t *testing.T) *Metrics {
	t.Helper()
	reg := prometheus.NewRegistry()
	return NewMetrics(MetricsConfig{Registerer: reg, Gatherer: reg, Namespace: "sn360", Subsystem: "es"})
}

func TestMetrics_DefaultsAndRegistration(t *testing.T) {
	m := newTestMetrics(t)
	if m.BannerRendered == nil || m.EvaluateLatency == nil {
		t.Fatal("expected core instruments to be initialised")
	}
	if m.Registerer() == nil || m.Gatherer() == nil {
		t.Fatal("expected registerer + gatherer wiring")
	}
}

func TestMetrics_HTTPHandlerExposesCounters(t *testing.T) {
	m := newTestMetrics(t)
	m.BannerRendered.WithLabelValues("Warning", "gws").Inc()
	m.EvaluateLatency.WithLabelValues("Caution").Observe(0.123)

	srv := httptest.NewServer(m.HTTPHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `sn360_es_banner_rendered_total{provider="gws",tier="Warning"}`) {
		t.Fatalf("missing banner counter: %s", string(body))
	}
	if !strings.Contains(string(body), "sn360_es_evaluate_latency_seconds_bucket") {
		t.Fatalf("missing evaluate latency histogram: %s", string(body))
	}
}

func TestMetrics_PipelineObserver(t *testing.T) {
	m := newTestMetrics(t)
	obs := m.PipelineObserver()
	obs.ObserveTier0("internal_trusted")
	obs.ObserveTier1("escalate", 12*time.Millisecond)
	obs.ObserveTier2("phishing", 250*time.Millisecond)
	obs.ObserveRspamd("ok", 5*time.Millisecond)
	obs.ObserveEvaluate("Warning", 300*time.Millisecond)
	obs.ObserveDegraded("tier2")

	// Round-trip through the HTTP handler so we exercise the gatherer.
	srv := httptest.NewServer(m.HTTPHandler())
	defer srv.Close()
	resp, _ := http.Get(srv.URL)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	expect := []string{
		`sn360_es_tier0_bypass_total{reason="internal_trusted"}`,
		`sn360_es_tier1_inferences_total{verdict="escalate"}`,
		`sn360_es_tier2_escalations_total{outcome="phishing"}`,
		`sn360_es_evaluate_outcome_total{tier="Warning"}`,
		`sn360_es_evaluate_degraded_total{service="tier2"}`,
		`sn360_es_evaluate_latency_seconds_bucket`,
	}
	for _, want := range expect {
		if !strings.Contains(string(body), want) {
			t.Fatalf("missing %q in metrics output:\n%s", want, body)
		}
	}
}

func TestMetrics_DoubleRegistrationSafe(t *testing.T) {
	reg := prometheus.NewRegistry()
	m1 := NewMetrics(MetricsConfig{Registerer: reg, Gatherer: reg})
	m2 := NewMetrics(MetricsConfig{Registerer: reg, Gatherer: reg})
	if m1 == nil || m2 == nil {
		t.Fatal("second construction must not panic or return nil")
	}
	m1.BannerAction.WithLabelValues("Warning", "report").Inc()
	m2.BannerAction.WithLabelValues("Warning", "report").Inc()
}

func TestNoopPipelineObserver(t *testing.T) {
	NoopPipelineObserver().ObserveTier0("x")
	NoopPipelineObserver().ObserveTier1("y", time.Second)
	NoopPipelineObserver().ObserveTier2("z", time.Second)
	NoopPipelineObserver().ObserveRspamd("w", time.Second)
	NoopPipelineObserver().ObserveEvaluate("Caution", time.Second)
	NoopPipelineObserver().ObserveDegraded("rspamd")
}

func TestDefaultMetricsSingleton(t *testing.T) {
	a := DefaultMetrics()
	b := DefaultMetrics()
	if a != b {
		t.Fatal("DefaultMetrics should be a singleton")
	}
}
