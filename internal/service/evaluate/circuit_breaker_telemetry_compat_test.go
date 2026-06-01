package evaluate_test

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/pkg/telemetry"
)

// TestCircuitBreakerStateOrdinalsMatchTelemetry pins the numeric mapping
// between evaluate.State and the mirrored constants in pkg/telemetry.
// The app wires the breaker into telemetry via int(cb.State()) (see
// cmd/sn360-es/app.go), so a silent re-ordering of the State iota in
// evaluate would cause dashboards to mis-render Closed as Open (or
// worse, Open as HalfOpen) without any compile-time signal because
// telemetry deliberately does NOT import evaluate (the comment in
// pkg/telemetry/metrics.go explains why — circular dependency).
//
// This test exists as the missing compile-time-style cross-check: any
// re-ordering of either side will fail it loudly in `make test` long
// before reaching production.
func TestCircuitBreakerStateOrdinalsMatchTelemetry(t *testing.T) {
	cases := []struct {
		name    string
		evalVal evaluate.State
		teleVal int
	}{
		{"Closed", evaluate.StateClosed, telemetry.CircuitBreakerStateClosed},
		{"Open", evaluate.StateOpen, telemetry.CircuitBreakerStateOpen},
		{"HalfOpen", evaluate.StateHalfOpen, telemetry.CircuitBreakerStateHalfOpen},
	}
	for _, c := range cases {
		if int(c.evalVal) != c.teleVal {
			t.Errorf("%s ordinal drift: evaluate.State%s=%d, telemetry.CircuitBreakerState%s=%d — these MUST stay in lockstep (see app.go wiring via int(cb.State()))",
				c.name, c.name, int(c.evalVal), c.name, c.teleVal)
		}
	}
}
