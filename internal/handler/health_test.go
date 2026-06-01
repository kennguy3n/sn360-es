package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthHandler_Liveness(t *testing.T) {
	h := NewHealthHandler(HealthConfig{})
	rec := httptest.NewRecorder()
	h.Liveness(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestHealthHandler_ReadyNoCheckers(t *testing.T) {
	h := NewHealthHandler(HealthConfig{})
	rec := httptest.NewRecorder()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp readinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" || len(resp.Checks) != 0 {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}

func TestHealthHandler_AllChecksPass(t *testing.T) {
	h := NewHealthHandler(HealthConfig{
		Checkers: []HealthChecker{
			HealthCheckerFunc{N: "nats", F: func(context.Context) error { return nil }},
			HealthCheckerFunc{N: "redis", F: func(context.Context) error { return nil }},
		},
	})
	rec := httptest.NewRecorder()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp readinessResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "ok" || len(resp.Checks) != 2 {
		t.Fatalf("checks: %+v", resp)
	}
}

func TestHealthHandler_OneCheckFails(t *testing.T) {
	h := NewHealthHandler(HealthConfig{
		Checkers: []HealthChecker{
			HealthCheckerFunc{N: "nats", F: func(context.Context) error { return errors.New("boom") }},
			HealthCheckerFunc{N: "redis", F: func(context.Context) error { return nil }},
		},
		Timeout: 50 * time.Millisecond,
	})
	rec := httptest.NewRecorder()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp readinessResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "degraded" {
		t.Fatalf("expected degraded, got %s", resp.Status)
	}
	if resp.Checks["nats"].Status != "error" || resp.Checks["redis"].Status != "ok" {
		t.Fatalf("unexpected checks: %+v", resp.Checks)
	}
	if resp.Checks["nats"].Err == "" {
		t.Fatal("expected error string for failed check")
	}
}

// Advisory check failure must be reported in the JSON body
// but MUST NOT 503 /readyz. This is the WS-5A.6
// cross-repo-SOC-loop visibility contract: a dark loop should
// be observable but not pull the pod out of rotation.
func TestHealthHandler_AdvisoryCheckFailure_DoesNot503(t *testing.T) {
	h := NewHealthHandler(HealthConfig{
		Checkers: []HealthChecker{
			HealthCheckerFunc{N: "nats", F: func(context.Context) error { return nil }},
			HealthCheckerFunc{
				N:   "escalation_sync",
				Adv: true,
				F:   func(context.Context) error { return errors.New("subscribe failed") },
			},
		},
	})
	rec := httptest.NewRecorder()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d; want 200 (advisory failure must not 503)", rec.Code)
	}
	var resp readinessResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "advisory" {
		t.Errorf("Status=%q; want %q", resp.Status, "advisory")
	}
	if got := resp.Checks["escalation_sync"]; got.Status != "advisory_error" ||
		!got.Advisory || got.Err == "" {
		t.Errorf("escalation_sync check = %+v; want {Status:advisory_error Advisory:true Err:!=\"\"}", got)
	}
	if got := resp.Checks["nats"]; got.Status != "ok" {
		t.Errorf("nats check = %+v; want ok", got)
	}
}

// Mixed-failure: a hard check failing 503s the endpoint even
// when an advisory check also failed. Confirms the advisory
// flag does not weaken the hard-check semantics.
func TestHealthHandler_AdvisoryAndHardFailure_503s(t *testing.T) {
	h := NewHealthHandler(HealthConfig{
		Checkers: []HealthChecker{
			HealthCheckerFunc{N: "nats", F: func(context.Context) error { return errors.New("hard down") }},
			HealthCheckerFunc{
				N:   "escalation_sync",
				Adv: true,
				F:   func(context.Context) error { return errors.New("soft down") },
			},
		},
	})
	rec := httptest.NewRecorder()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d; want 503 (hard failure dominates)", rec.Code)
	}
}

func TestHealthHandler_RespectsTimeout(t *testing.T) {
	h := NewHealthHandler(HealthConfig{
		Timeout: 25 * time.Millisecond,
		Checkers: []HealthChecker{
			HealthCheckerFunc{N: "slow", F: func(ctx context.Context) error {
				select {
				case <-time.After(500 * time.Millisecond):
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}},
		},
	})
	rec := httptest.NewRecorder()
	start := time.Now()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("readiness check should have timed out fast, took %s", elapsed)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rec.Code)
	}
}
