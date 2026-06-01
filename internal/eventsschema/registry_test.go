package eventsschema_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/eventsschema"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/pkg/events/schema"
)

// TestRegistryCoversCanonicalSubjects asserts every subject the
// binary publishes or subscribes to is bound on the registry.
// A subject family that the validator does not know about
// silently passes — this guard catches the case where someone
// added a new subject to the wiring but forgot to register a
// shape for it.
func TestRegistryCoversCanonicalSubjects(t *testing.T) {
	t.Parallel()
	v := eventsschema.MustRegister()
	for _, subj := range []string{
		eventsschema.SubjectEvaluateRequest,
		eventsschema.SubjectEvaluateResult,
		eventsschema.SubjectActionFeedbackPrefix + ".report",
		eventsschema.SubjectActionFeedbackPrefix + ".confirm",
		eventsschema.SubjectActionClawback,
		eventsschema.SubjectActionLabel,
		eventsschema.SubjectActionBanner,
		eventsschema.SubjectActionURLRewrite,
		eventsschema.SubjectActionQuarantine,
		eventsschema.SubjectCommHistoryUpdate,
		eventsschema.SubjectDashboardSummary,
		eventsschema.SubjectEscalationCreated,
		eventsschema.SubjectEscalationResolved,
		eventsschema.SubjectEducationInteraction + ".clicked",
		eventsschema.SubjectEducationSimulation + ".result",
		eventsschema.SubjectBridgeEnvelopePrefix + ".t-42.phishing",
	} {
		family := v.SubjectFamily(subj)
		if family == "" {
			t.Errorf("subject %q has no registered family — every canonical subject must be bound", subj)
		}
	}
}

// TestBackwardCompat_NoSchemaVersionAcceptedAsV1 is the core
// WS-7c backward-compat contract: a payload from a pre-WS-7c
// publisher (no `schema_version` field) is accepted as v1
// and processed normally. The validator surfaces
// ReasonMissingVersion so the operator dashboard can see the
// legacy publisher, but Result.IsMismatch() returns false
// and the message is NOT routed to the schema DLQ.
func TestBackwardCompat_NoSchemaVersionAcceptedAsV1(t *testing.T) {
	t.Parallel()
	v := eventsschema.MustRegister()

	// EvaluateResult without `schema_version`.
	payload := mustJSON(t, map[string]any{
		"tenant_id":  "t-1",
		"message_id": "m-1",
	})
	result := v.Validate(eventsschema.SubjectEvaluateResult, payload)
	if result.Reason != schema.ReasonMissingVersion {
		t.Fatalf("expected ReasonMissingVersion for unversioned payload, got %q (err=%v)", result.Reason, result.Err)
	}
	if result.IsMismatch() {
		t.Fatalf("ReasonMissingVersion must NOT be a mismatch — legacy publishers must pass through")
	}
	if result.ResolvedVersion != schema.SchemaVersionV1 {
		t.Fatalf("expected ResolvedVersion=%q, got %q", schema.SchemaVersionV1, result.ResolvedVersion)
	}
}

// TestForwardCompat_UnknownVersionRoutesToDLQ is the core
// WS-7c forward-compat contract: a payload claiming a
// `schema_version` we do NOT know about is a mismatch, NOT a
// passthrough. The publish path returns a ValidationError;
// the subscribe path routes the message to the schema DLQ.
func TestForwardCompat_UnknownVersionRoutesToDLQ(t *testing.T) {
	t.Parallel()
	v := eventsschema.MustRegister()

	payload := mustJSON(t, map[string]any{
		"schema_version": "v999",
		"tenant_id":      "t-1",
		"message_id":     "m-1",
	})
	result := v.Validate(eventsschema.SubjectEvaluateResult, payload)
	if result.Reason != schema.ReasonUnknownVersion {
		t.Fatalf("expected ReasonUnknownVersion for v999 payload, got %q (err=%v)", result.Reason, result.Err)
	}
	if !result.IsMismatch() {
		t.Fatalf("ReasonUnknownVersion MUST be a mismatch — forward-compat trap")
	}
	if got := schema.DLQSubject(eventsschema.SubjectEvaluateResult); got != "sn360.dlq.schema.es.evaluate.result" {
		t.Fatalf("DLQSubject contract violated: got %q", got)
	}

	// And the publisher-side wrapper should produce a
	// structured *ValidationError.
	if err := v.ValidateOrError(eventsschema.SubjectEvaluateResult, payload); err == nil {
		t.Fatalf("expected ValidateOrError to return error, got nil")
	} else {
		var target *schema.ValidationError
		if !errors.As(err, &target) {
			t.Fatalf("expected *schema.ValidationError, got %T (%v)", err, err)
		}
		if target.Reason != schema.ReasonUnknownVersion {
			t.Fatalf("expected target.Reason=%q, got %q", schema.ReasonUnknownVersion, target.Reason)
		}
	}
}

// TestPayloadValidationFailure asserts a payload claiming a
// registered version but with a missing required field surfaces
// as ReasonPayloadInvalid. The DLQ-routing behaviour at
// subscribe time is identical to the unknown-version case.
func TestPayloadValidationFailure(t *testing.T) {
	t.Parallel()
	v := eventsschema.MustRegister()

	// EvaluateResult with v1 set but missing tenant_id.
	payload := mustJSON(t, map[string]any{
		"schema_version": schema.SchemaVersionV1,
		"message_id":     "m-1",
	})
	result := v.Validate(eventsschema.SubjectEvaluateResult, payload)
	if result.Reason != schema.ReasonPayloadInvalid {
		t.Fatalf("expected ReasonPayloadInvalid for missing tenant_id, got %q (err=%v)", result.Reason, result.Err)
	}
	if !result.IsMismatch() {
		t.Fatalf("ReasonPayloadInvalid MUST be a mismatch")
	}
}

// TestEvaluateRequestAcceptsBothShapes is the
// ARCHITECTURE.md §3 tolerance contract. The validator MUST
// accept both the canonical BatchMessage wrapper AND the
// legacy flat dto.EvaluateRequest shape on
// `es.evaluate.request` (so a still-in-rollout legacy
// publisher does not trip the schema-DLQ on every message).
func TestEvaluateRequestAcceptsBothShapes(t *testing.T) {
	t.Parallel()
	v := eventsschema.MustRegister()

	// Canonical wrapped shape.
	wrapped := mustJSON(t, evaluate.BatchMessage{
		SchemaVersion: schema.SchemaVersionV1,
		Request: dto.EvaluateRequest{
			TenantID:  "t-1",
			MessageID: "m-1",
		},
	})
	if result := v.Validate(eventsschema.SubjectEvaluateRequest, wrapped); result.IsMismatch() {
		t.Fatalf("canonical BatchMessage must pass validation, got %q (err=%v)", result.Reason, result.Err)
	}

	// Legacy flat shape (no wrapper at all).
	flat := mustJSON(t, map[string]any{
		"schema_version": schema.SchemaVersionV1,
		"tenant_id":      "t-1",
		"message_id":     "m-1",
		"subject":        "Hello",
	})
	if result := v.Validate(eventsschema.SubjectEvaluateRequest, flat); result.IsMismatch() {
		t.Fatalf("legacy flat EvaluateRequest must pass validation, got %q (err=%v)", result.Reason, result.Err)
	}

	// Malformed: empty payload struct, neither shape carries a
	// message_id. Must fail.
	malformed := mustJSON(t, map[string]any{
		"schema_version": schema.SchemaVersionV1,
		"tenant_id":      "t-1",
	})
	result := v.Validate(eventsschema.SubjectEvaluateRequest, malformed)
	if !result.IsMismatch() {
		t.Fatalf("payload missing message_id MUST fail validation")
	}
	if !strings.Contains(result.Err.Error(), "message_id") {
		t.Fatalf("expected validator error to call out message_id, got %v", result.Err)
	}
}

// TestBridgeEnvelopePrefixBinding asserts the bridge envelope
// prefix registration covers every concrete subject the
// bridge publishes on (per-tenant + per-kind variants).
func TestBridgeEnvelopePrefixBinding(t *testing.T) {
	t.Parallel()
	v := eventsschema.MustRegister()

	for _, subj := range []string{
		"sn360.events.email.t-1.phishing",
		"sn360.events.email.t-2.bec",
		"sn360.events.email.t-3.quarantine",
		"sn360.events.email.t-4.escalation",
	} {
		payload := mustJSON(t, map[string]any{
			"schema_version": schema.SchemaVersionV1,
			"@timestamp":     "2024-01-02T03:04:05Z",
			"rule":           map[string]any{"id": "1", "level": 9},
			"agent":          map[string]any{"id": "agent-1"},
		})
		if result := v.Validate(subj, payload); result.IsMismatch() {
			t.Fatalf("bridge envelope on %q must pass validation, got %q (err=%v)", subj, result.Reason, result.Err)
		}
	}
}

// TestFeedbackEventPrefixBinding asserts the action.feedback
// prefix registration covers the .report / .confirm / .clear
// variants the action service emits.
func TestFeedbackEventPrefixBinding(t *testing.T) {
	t.Parallel()
	v := eventsschema.MustRegister()
	ev := action.FeedbackEvent{
		SchemaVersion:        schema.SchemaVersionV1,
		TenantID:             "t-1",
		PseudonymizedMessage: "m-1",
		Action:               action.FeedbackReportPhishing,
	}
	payload := mustJSON(t, ev)
	for _, subj := range []string{
		"es.action.feedback.report",
		"es.action.feedback.confirm",
		"es.action.feedback.clear",
	} {
		if result := v.Validate(subj, payload); result.IsMismatch() {
			t.Fatalf("feedback event on %q must pass validation, got %q (err=%v)", subj, result.Reason, result.Err)
		}
	}
}

// TestDLQSubjectIdempotent asserts DLQSubject does not nest
// recursively when the input is already a DLQ subject.
func TestDLQSubjectIdempotent(t *testing.T) {
	t.Parallel()
	first := schema.DLQSubject("es.evaluate.result")
	if first != "sn360.dlq.schema.es.evaluate.result" {
		t.Fatalf("unexpected first-pass DLQ subject %q", first)
	}
	second := schema.DLQSubject(first)
	if second != first {
		t.Fatalf("DLQSubject must be idempotent: %q -> %q", first, second)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
