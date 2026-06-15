package main

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/kennguy3n/sn360-es/internal/handler"
	"github.com/kennguy3n/sn360-es/internal/repository"
)

// buildInternalMux constructs the routing tree for the internal-only
// listener that backs the sme-dashboard portal's Email Security
// console. It is mounted on cfg.HTTP.InternalPort, which is never
// exposed on the tenant-facing plane, so the routes here read the
// tenant from the URL path (the trusted dashboard-proxy asserts it
// from the authenticated session) instead of a JWT claim.
//
// The handler still binds every read to the tenant via the shared
// TenantBinder, so Postgres row-level security stays authoritative.
// When INTERNAL_AUTH_TOKEN is configured the routes additionally
// require a matching X-SN360-Internal-Token header as defence in
// depth on top of the network isolation.
//
// Returns (nil, nil) when the internal surface has nothing to serve
// (no eval repository AND no dashboard generator AND no investigation
// service) so the caller can skip binding a socket no route would use.
func buildInternalMux(app *application) (http.Handler, error) {
	if app == nil {
		return nil, errors.New("buildInternalMux: app is required")
	}
	logger := app.logger

	var eval = evalRepoOrNil(app)
	if eval == nil && app.dashboardGen == nil && app.investigationSvc == nil {
		logger.Info("sn360-es: internal email-security surface has no backing dependencies; not mounting")
		return nil, nil
	}

	emailH, err := handler.NewEmailBFFHandler(
		logger,
		app.dashboardGen,
		app.investigationSvc,
		eval,
		quarantineTenantBinder(app),
	)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	// Liveness/readiness for the internal listener so its own kubelet
	// probes do not have to reach across to the public port.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	gate := internalAuthGate(app.cfg.HTTP.InternalAuthToken)
	mux.Handle("GET /internal/tenants/{tid}/email-security/summary", gate(http.HandlerFunc(emailH.ServeSummary)))
	mux.Handle("GET /internal/tenants/{tid}/email-security/messages", gate(http.HandlerFunc(emailH.ServeMessages)))
	mux.Handle("GET /internal/tenants/{tid}/email-security/messages/{mid}", gate(http.HandlerFunc(emailH.ServeMessageDetail)))

	return mux, nil
}

// evalRepoOrNil returns the evaluation-results repository when the
// registry is wired, or nil otherwise. Centralised so both the mount
// decision and the handler wiring read the same value.
func evalRepoOrNil(app *application) repository.EvaluationResultRepository {
	if app == nil || app.repos == nil || app.repos.EvaluationResults == nil {
		return nil
	}
	return app.repos.EvaluationResults
}

// internalAuthGate returns a middleware that enforces the shared
// internal token when one is configured, and is a transparent
// pass-through when it is empty. The comparison is constant-time so a
// caller cannot time-probe the secret.
func internalAuthGate(token string) func(http.Handler) http.Handler {
	if token == "" {
		return func(next http.Handler) http.Handler { return next }
	}
	want := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := []byte(r.Header.Get("X-SN360-Internal-Token"))
			if subtle.ConstantTimeEq(int32(len(got)), int32(len(want))) != 1 ||
				subtle.ConstantTimeCompare(got, want) != 1 {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"internal authentication required"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
