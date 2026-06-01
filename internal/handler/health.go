package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// HealthChecker runs one dependency probe. Implementations must respect
// the context deadline and return nil for healthy or an error otherwise.
type HealthChecker interface {
	// Name is the stable identifier shown in /readyz output.
	Name() string
	// Check probes the dependency once. Implementations should be
	// cheap (single ping / version query) — readiness handlers run
	// them on every request.
	Check(ctx context.Context) error
}

// AdvisoryChecker is an optional extension of HealthChecker.
// A checker that returns true from Advisory() is reported in the
// /readyz response body but does NOT 503 the endpoint on failure.
// Used for dependencies whose outage is visible-but-not-fatal —
// e.g. WS-5A.6's cross-repo SOC escalation consumer: the email
// security hot path must keep serving even if the cross-repo
// reconciliation loop is dark, but operators MUST still see the
// degraded state in dashboards instead of having to grep boot
// logs for a one-shot WARN.
type AdvisoryChecker interface {
	Advisory() bool
}

// HealthCheckerFunc adapts a plain function to the HealthChecker
// interface. The first argument is the name reported in /readyz output.
//
// Set Adv=true to mark the check as advisory (see AdvisoryChecker):
// the result appears in the /readyz JSON body but does not 503 the
// endpoint on error.
type HealthCheckerFunc struct {
	N   string
	F   func(context.Context) error
	Adv bool
}

// Name implements HealthChecker.
func (f HealthCheckerFunc) Name() string { return f.N }

// Check implements HealthChecker.
func (f HealthCheckerFunc) Check(ctx context.Context) error {
	if f.F == nil {
		return nil
	}
	return f.F(ctx)
}

// Advisory implements AdvisoryChecker.
func (f HealthCheckerFunc) Advisory() bool { return f.Adv }

// HealthHandler serves /healthz and /readyz.
//
// /healthz is a constant-time liveness probe (200 ok).
// /readyz iterates configured checkers in parallel and returns a JSON
// summary; the HTTP status is 200 when every required checker reports
// healthy and 503 otherwise.
type HealthHandler struct {
	logger   *slog.Logger
	checkers []HealthChecker
	timeout  time.Duration
}

// HealthConfig wires the readiness handler.
type HealthConfig struct {
	Logger   *slog.Logger
	Checkers []HealthChecker
	// Timeout is the per-checker deadline applied via context.
	// Zero defaults to 2s, which is the longest you'd want a load
	// balancer probe to wait.
	Timeout time.Duration
}

// NewHealthHandler constructs the handler. Checkers may be empty; in
// that case /readyz always returns 200.
func NewHealthHandler(cfg HealthConfig) *HealthHandler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	return &HealthHandler{logger: cfg.Logger, checkers: cfg.Checkers, timeout: cfg.Timeout}
}

// Liveness is the http.Handler for /healthz.
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// Readiness is the http.Handler for /readyz.
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	resp := readinessResponse{
		Status: "ok",
		Checks: map[string]readinessCheck{},
	}
	if len(h.checkers) == 0 {
		resp.encode(w, http.StatusOK)
		return
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		failed    bool
		anyAdvErr bool
	)
	for _, c := range h.checkers {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
			defer cancel()
			start := time.Now()
			err := c.Check(ctx)
			advisory := false
			if adv, ok := c.(AdvisoryChecker); ok {
				advisory = adv.Advisory()
			}
			result := readinessCheck{LatencyMs: time.Since(start).Milliseconds(), Advisory: advisory}
			if err != nil {
				// "advisory_error" is a distinct status from
				// "error" so dashboards can filter on it
				// (visible-but-not-fatal degradation).
				if advisory {
					result.Status = "advisory_error"
				} else {
					result.Status = "error"
				}
				result.Err = err.Error()
				h.logger.WarnContext(ctx, "readyz: check failed",
					slog.String("check", c.Name()),
					slog.Bool("advisory", advisory),
					slog.Any("error", err))
			} else {
				result.Status = "ok"
			}
			mu.Lock()
			resp.Checks[c.Name()] = result
			if err != nil {
				if advisory {
					anyAdvErr = true
				} else {
					failed = true
				}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if failed {
		resp.Status = "degraded"
		resp.encode(w, http.StatusServiceUnavailable)
		return
	}
	// Advisory-only failures still flag the response body
	// with status="advisory" but return 200 so load
	// balancers don't pull the pod out — the hot path is
	// fine, only the visible-but-non-fatal probe failed.
	if anyAdvErr {
		resp.Status = "advisory"
	}
	resp.encode(w, http.StatusOK)
}

type readinessResponse struct {
	Status string                    `json:"status"`
	Checks map[string]readinessCheck `json:"checks"`
}

type readinessCheck struct {
	Status    string `json:"status"`
	Err       string `json:"error,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	// Advisory marks a check whose failure does not 503
	// /readyz. Surfaces in the JSON so dashboards can
	// distinguish "the binary is down" from "a non-fatal
	// dependency probe failed".
	Advisory bool `json:"advisory,omitempty"`
}

func (r readinessResponse) encode(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(r)
}
