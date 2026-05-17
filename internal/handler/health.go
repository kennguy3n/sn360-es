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

// HealthCheckerFunc adapts a plain function to the HealthChecker
// interface. The first argument is the name reported in /readyz output.
type HealthCheckerFunc struct {
	N string
	F func(context.Context) error
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
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed bool
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
			result := readinessCheck{LatencyMs: time.Since(start).Milliseconds()}
			if err != nil {
				result.Status = "error"
				result.Err = err.Error()
				h.logger.WarnContext(ctx, "readyz: check failed",
					slog.String("check", c.Name()),
					slog.Any("error", err))
			} else {
				result.Status = "ok"
			}
			mu.Lock()
			resp.Checks[c.Name()] = result
			if err != nil {
				failed = true
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
}

func (r readinessResponse) encode(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(r)
}
