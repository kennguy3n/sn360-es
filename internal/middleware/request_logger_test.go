package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureLogger returns a logger that writes JSON records into buf so
// tests can inspect attributes without parsing slog's debug format.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h)
}

func TestRequestLogger_SkipsHealth(t *testing.T) {
	buf := &bytes.Buffer{}
	mw := NewRequestLogger(okHandler(), RequestLoggerConfig{Logger: captureLogger(buf)})
	for _, p := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		mw.ServeHTTP(httptest.NewRecorder(), req)
	}
	if strings.TrimSpace(buf.String()) != "" {
		t.Fatalf("expected no log lines, got %q", buf.String())
	}
}

func TestRequestLogger_LogsMethodPathStatus(t *testing.T) {
	buf := &bytes.Buffer{}
	calls := 0
	mw := NewRequestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}), RequestLoggerConfig{
		Logger: captureLogger(buf),
		Clock: func() time.Time {
			calls++
			return time.Unix(0, int64(calls)*int64(time.Millisecond))
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/predict/open", nil)
	req.Header.Set("X-Correlation-ID", "cid-1")
	mw.ServeHTTP(httptest.NewRecorder(), req)
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("log not json: %v\n%s", err, buf.String())
	}
	if rec["http.method"] != "POST" {
		t.Fatalf("method=%v", rec["http.method"])
	}
	if rec["http.path"] != "/v1/predict/open" {
		t.Fatalf("path=%v", rec["http.path"])
	}
	if rec["http.status"].(float64) != float64(http.StatusAccepted) {
		t.Fatalf("status=%v", rec["http.status"])
	}
	if rec["correlation_id"] != "cid-1" {
		t.Fatalf("correlation_id=%v", rec["correlation_id"])
	}
	if rec["http.latency_ms"].(float64) <= 0 {
		t.Fatalf("latency_ms=%v", rec["http.latency_ms"])
	}
}

func TestRequestLogger_LogsTenantFromContext(t *testing.T) {
	buf := &bytes.Buffer{}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := NewRequestLogger(inner, RequestLoggerConfig{Logger: captureLogger(buf)})
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/summary", nil).
		WithContext(context.WithValue(context.Background(), ctxKeyTenantID, "acme"))
	mw.ServeHTTP(httptest.NewRecorder(), req)
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("log not json: %v", err)
	}
	if rec["tenant_id"] != "acme" {
		t.Fatalf("tenant_id=%v", rec["tenant_id"])
	}
}

func TestRequestLogger_ServerErrorsLogAsError(t *testing.T) {
	buf := &bytes.Buffer{}
	mw := NewRequestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}), RequestLoggerConfig{Logger: captureLogger(buf)})
	mw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	var rec map[string]any
	_ = json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec)
	if rec["level"] != "ERROR" {
		t.Fatalf("level=%v", rec["level"])
	}
}
