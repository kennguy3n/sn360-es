package evaluate

import (
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// TestBackfillRoutingFields_PopulatesEmpty verifies the per-message
// handleEvaluateRequest parity invariant: a result emitted by the batch
// orchestrator carries the same routing/identity envelope the
// per-message path would have produced for an identical request,
// including Recipient. Without the Recipient backfill, every action
// signal fanned out by handleIngestionAction lands with "email": ""
// and every action handler silently no-ops on the empty-email guard.
// The helper itself lives in `internal/dto` so both the per-message
// handleEvaluateRequest path and BatchOrchestrator.processOnce share
// a single implementation — this test guards the orchestrator's use
// of that shared helper.
func TestBackfillRoutingFields_PopulatesEmpty(t *testing.T) {
	t.Parallel()
	req := dto.EvaluateRequest{
		TenantID:      "tenant-1",
		MessageID:     "msg-1",
		CorrelationID: "corr-1",
		Recipient:     "alice@example.com",
	}
	res := dto.EvaluateResult{}

	before := time.Now().UTC()
	dto.BackfillRoutingFields(&res, req)
	after := time.Now().UTC()

	if res.MessageID != "msg-1" {
		t.Errorf("MessageID = %q, want msg-1", res.MessageID)
	}
	if res.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q, want tenant-1", res.TenantID)
	}
	if res.CorrelationID != "corr-1" {
		t.Errorf("CorrelationID = %q, want corr-1", res.CorrelationID)
	}
	if res.Recipient != "alice@example.com" {
		t.Errorf("Recipient = %q, want alice@example.com", res.Recipient)
	}
	if res.EvaluatedAt.Before(before) || res.EvaluatedAt.After(after) {
		t.Errorf("EvaluatedAt = %v, want in [%v, %v]", res.EvaluatedAt, before, after)
	}
}

// TestBackfillRoutingFields_DoesNotOverwriteSet confirms the backfill
// is conditional. A result that already carries a non-empty field
// (typically because the slow-path Evaluator stamped it) must not be
// clobbered — otherwise an evaluator that intentionally rewrites
// EvaluatedAt at fallback exit, or that produces a routing recipient
// distinct from the request (e.g. for forwarded mail), would lose
// that value.
func TestBackfillRoutingFields_DoesNotOverwriteSet(t *testing.T) {
	t.Parallel()
	evaluatedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	req := dto.EvaluateRequest{
		TenantID:      "tenant-req",
		MessageID:     "msg-req",
		CorrelationID: "corr-req",
		Recipient:     "from-req@example.com",
	}
	res := dto.EvaluateResult{
		TenantID:      "tenant-pre",
		MessageID:     "msg-pre",
		CorrelationID: "corr-pre",
		Recipient:     "from-pre@example.com",
		EvaluatedAt:   evaluatedAt,
	}

	dto.BackfillRoutingFields(&res, req)

	if res.MessageID != "msg-pre" {
		t.Errorf("MessageID overwritten: got %q, want msg-pre", res.MessageID)
	}
	if res.TenantID != "tenant-pre" {
		t.Errorf("TenantID overwritten: got %q, want tenant-pre", res.TenantID)
	}
	if res.CorrelationID != "corr-pre" {
		t.Errorf("CorrelationID overwritten: got %q, want corr-pre", res.CorrelationID)
	}
	if res.Recipient != "from-pre@example.com" {
		t.Errorf("Recipient overwritten: got %q, want from-pre@example.com", res.Recipient)
	}
	if !res.EvaluatedAt.Equal(evaluatedAt) {
		t.Errorf("EvaluatedAt overwritten: got %v, want %v", res.EvaluatedAt, evaluatedAt)
	}
}

// TestBackfillRoutingFields_EmptyRequestRecipient ensures the helper
// does not invent data. When the request itself carries no Recipient
// (a perf-harness BatchMessage with only Subject + Body), the result
// stays empty rather than picking up a zero-value or default. The
// downstream action layer's empty-email guard remains the
// authoritative drop-point in that scenario.
func TestBackfillRoutingFields_EmptyRequestRecipient(t *testing.T) {
	t.Parallel()
	req := dto.EvaluateRequest{
		TenantID:  "tenant-1",
		MessageID: "msg-1",
	}
	res := dto.EvaluateResult{}

	dto.BackfillRoutingFields(&res, req)

	if res.Recipient != "" {
		t.Errorf("Recipient = %q, want empty (request had no Recipient)", res.Recipient)
	}
	// MessageID + TenantID + EvaluatedAt should still be populated
	// from the non-Recipient fields of the request.
	if res.MessageID != "msg-1" {
		t.Errorf("MessageID = %q, want msg-1", res.MessageID)
	}
	if res.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q, want tenant-1", res.TenantID)
	}
	if res.EvaluatedAt.IsZero() {
		t.Error("EvaluatedAt is zero, want non-zero")
	}
}
