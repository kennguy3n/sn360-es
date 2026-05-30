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

// TestDecodeEvaluatePayload_CanonicalBatchMessage exercises the happy
// path: a BatchMessage{Request, Signals} wrapper round-trips through
// the decoder and is reported as non-legacy.
func TestDecodeEvaluatePayload_CanonicalBatchMessage(t *testing.T) {
	t.Parallel()
	payload := []byte(`{
		"request": {
			"message_id": "msg-canonical",
			"tenant_id": "tenant-1",
			"correlation_id": "corr-1",
			"sender": "alice@example.com",
			"recipient": "bob@example.com",
			"body": "hello"
		},
		"signals": {
			"sender_domain": "example.com",
			"is_external": true
		}
	}`)
	bm, legacy, err := decodeEvaluatePayload(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if legacy {
		t.Errorf("legacy = true; want false for canonical BatchMessage")
	}
	if bm.Request.MessageID != "msg-canonical" {
		t.Errorf("Request.MessageID = %q, want msg-canonical", bm.Request.MessageID)
	}
	if bm.Signals.SenderDomain != "example.com" {
		t.Errorf("Signals.SenderDomain = %q, want example.com", bm.Signals.SenderDomain)
	}
}

// TestDecodeEvaluatePayload_LegacyFlatShape verifies the wire-format
// tolerance: a publisher that still emits a flat dto.EvaluateRequest
// (the historical shape used by handleEvaluateRequest) is wrapped
// transparently and reported as legacy so the composition root can
// emit tier1_batch_legacy_payload_total.
func TestDecodeEvaluatePayload_LegacyFlatShape(t *testing.T) {
	t.Parallel()
	payload := []byte(`{
		"message_id": "msg-legacy",
		"tenant_id": "tenant-2",
		"correlation_id": "corr-2",
		"sender": "alice@example.com",
		"recipient": "bob@example.com",
		"body": "hi",
		"signals": {
			"sender_domain": "example.com",
			"is_external": true
		}
	}`)
	bm, legacy, err := decodeEvaluatePayload(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !legacy {
		t.Errorf("legacy = false; want true for flat dto.EvaluateRequest")
	}
	if bm.Request.MessageID != "msg-legacy" {
		t.Errorf("Request.MessageID = %q, want msg-legacy", bm.Request.MessageID)
	}
	if bm.Request.TenantID != "tenant-2" {
		t.Errorf("Request.TenantID = %q, want tenant-2", bm.Request.TenantID)
	}
	if bm.Signals.SenderDomain != "example.com" {
		t.Errorf("Signals.SenderDomain = %q, want example.com (mirrored from Request.Signals)", bm.Signals.SenderDomain)
	}
	if !bm.Signals.IsExternal {
		t.Errorf("Signals.IsExternal = false; want true (mirrored from Request.Signals)")
	}
}

// TestDecodeEvaluatePayload_MalformedReturnsError asserts that a
// payload that fails both decode attempts surfaces an error so the
// orchestrator NAKs the message instead of silently processing an
// empty request.
func TestDecodeEvaluatePayload_MalformedReturnsError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		payload []byte
	}{
		{"invalid json", []byte(`{not json`)},
		{"empty object", []byte(`{}`)},
		{"missing message_id", []byte(`{"tenant_id": "x"}`)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := decodeEvaluatePayload(tc.payload)
			if err == nil {
				t.Fatalf("decode succeeded; want error for malformed payload %q", string(tc.payload))
			}
		})
	}
}

// TestDecodeEvaluatePayload_WrappedShapeHonoursOwnSignals confirms
// that when both BatchMessage.Signals and BatchMessage.Request.Signals
// are present, the explicit top-level Signals wins (it's the producer's
// canonical signal envelope; Request.Signals may be empty or stale).
func TestDecodeEvaluatePayload_WrappedShapeHonoursOwnSignals(t *testing.T) {
	t.Parallel()
	payload := []byte(`{
		"request": {
			"message_id": "msg-1",
			"tenant_id": "tenant-1",
			"signals": { "sender_domain": "stale.example" }
		},
		"signals": { "sender_domain": "canonical.example" }
	}`)
	bm, legacy, err := decodeEvaluatePayload(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if legacy {
		t.Errorf("legacy = true; want false")
	}
	if bm.Signals.SenderDomain != "canonical.example" {
		t.Errorf("Signals.SenderDomain = %q, want canonical.example (wrapper signals win)", bm.Signals.SenderDomain)
	}
}
