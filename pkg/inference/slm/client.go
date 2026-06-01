// Package slm defines the Tier 2 small-language-model inference
// abstraction used by the email-security evaluator.
//
// The package was carved out of internal/service/evaluate so the
// orchestrator can pick a Tier 2 provider at runtime (env-driven or
// per-tenant) without recompiling. Providers register themselves by
// name at process init; the evaluator constructs them via the
// registry instead of calling the HTTP client directly.
//
// The interface contract — Evaluate(ctx, req, hint) (Outcome, error) —
// matches the original evaluate.Tier2Client to make the swap a
// drop-in. A type alias in internal/service/evaluate preserves the
// old type name so existing call sites keep compiling.
//
// Implementations live in pkg/inference/slm/providers/. Each
// subpackage registers itself in its init() and is wired into the
// binary via a blank import in pkg/inference/slm/all (see
// cmd/sn360-es/app.go). New providers (vLLM, Bedrock, etc.) only
// need to add a new subpackage + register; no orchestrator changes
// required.
package slm

import (
	"context"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Client is the Tier 2 inference contract.
//
// Implementations MUST be safe for concurrent use across many
// goroutines: the evaluator dispatches Evaluate from the per-message
// hot path and from the BatchOrchestrator concurrently, with no
// per-call locking on the caller side.
//
// Evaluate is given the original evaluate request plus the Tier 1
// encoder hint. The implementation is free to fold (or ignore) the
// hint when building its prompt, but MUST return a structured
// Outcome on success — partial-text answers must be parsed into the
// fields of dto.Tier2Outcome before returning, and the LatencyMs
// field MUST be populated with the wall-clock duration of the
// underlying inference call so the evaluator can fold it into
// pipeline telemetry.
//
// On error, Evaluate MUST NOT silently substitute a zero outcome —
// callers (and the Tier 2 fallback circuit breaker) rely on a
// non-nil error to drive retries and fallback dispatch.
type Client interface {
	Evaluate(ctx context.Context, req dto.EvaluateRequest, hint dto.Tier1Outcome) (dto.Tier2Outcome, error)
}
