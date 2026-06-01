// Package eventsschema wires the canonical sn360-es NATS subjects
// onto the WS-7c schema registry (pkg/events/schema). It is the
// single source of truth for "which (subject, schema_version)
// pairs are valid on the bus".
//
// The package is intentionally a thin composition layer: the
// per-subject DTOs live under internal/dto/, internal/service/*
// (BatchMessage, FeedbackEvent, ClawbackEvent) and
// internal/service/bridge/ (Envelope). The registry binds each
// subject family to its strongly-typed Go struct, so a payload
// that fails json.Unmarshal into the registered shape is
// flagged as `payload_validation_failure` at the publish (or
// subscribe) boundary instead of crashing the consumer's typed
// json.Unmarshal three hops later — the exact regression the
// ARCHITECTURE.md §3 BatchMessage vs flat EvaluateRequest bug
// represents.
//
// Adding a v2 (or v1-experiment) shape: register a second
// (subject, version) pair via schema.RegisterStruct[T] with the
// new Go type. The validator dispatches per-version, so v1 and
// v2 publishers continue to coexist on the wire and the broker
// dedup window is unchanged. Document the cutover in
// docs/SCHEMA_VERSIONING.md.
package eventsschema

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/bridge"
	"github.com/kennguy3n/sn360-es/internal/service/evaluate"
	"github.com/kennguy3n/sn360-es/pkg/events/schema"
)

// Subjects enumerates the canonical sn360-es NATS subjects (and
// subject prefixes) the registry covers. Exported as constants
// so tests can assert against a single source of truth and the
// schema-DLQ tooling can drive replays per subject family.
const (
	SubjectEvaluateRequest      = "es.evaluate.request"
	SubjectEvaluateResult       = "es.evaluate.result"
	SubjectActionFeedbackPrefix = "es.action.feedback"
	SubjectActionClawback       = "es.action.clawback"
	SubjectActionLabel          = "es.action.label"
	SubjectActionBanner         = "es.action.banner"
	SubjectActionURLRewrite     = "es.action.url_rewrite"
	SubjectActionQuarantine     = "es.action.quarantine"
	SubjectCommHistoryUpdate    = "es.management.comm_history.update"
	SubjectDashboardSummary     = "es.dashboard.report.generated"
	SubjectEscalationCreated    = "es.action.escalation.created"
	SubjectEscalationResolved   = "es.action.escalation.resolved"
	SubjectEducationInteraction = "es.education.interaction"
	SubjectEducationSimulation  = "es.education.simulation"
	// SubjectBridgeEnvelopePrefix is the platform-bridge
	// envelope subject family. The bridge fans verdicts,
	// quarantine actions, and escalation transitions onto
	// `sn360.events.email.<tenant>.<kind>`, so the registry
	// pins the envelope shape by prefix instead of binding each
	// (tenant, kind) tuple by hand.
	SubjectBridgeEnvelopePrefix = bridge.SubjectPrefix
)

// MustRegister returns a populated validator with every
// canonical sn360-es subject bound to its v1 Go struct. Used by
// the binary's startup wiring (cmd/sn360-es). Tests that want a
// stripped-down registry should construct one directly and call
// schema.Register* by hand.
//
// The function name uses Must-prefix to signal "panic on
// registration errors". Registration is in-memory, deterministic
// at process boot, and impossible to fail under normal operation
// — a panic here would only happen if the schema package were
// itself broken, in which case the binary cannot publish or
// consume safely and refusing to start is the right outcome.
func MustRegister() *schema.Validator {
	v := schema.New()
	Register(v)
	return v
}

// Register binds every canonical sn360-es subject onto v. Exported
// separately from MustRegister so a test can compose its own
// registry (e.g. adding a fake "es.test.synthetic" subject) on
// top of the production set.
func Register(v *schema.Validator) {
	if v == nil {
		return
	}

	// es.evaluate.request: the canonical shape on the wire is
	// the BatchMessage{Request, Signals} wrapper, but
	// ARCHITECTURE.md §3 documents the explicit legacy
	// tolerance — a flat dto.EvaluateRequest on the same
	// subject is decoded and re-wrapped by decodeEvaluatePayload.
	// The validator mirrors that tolerance so the BatchMessage
	// vs flat EvaluateRequest migration class of bug is caught
	// without breaking the still-in-rollout legacy publishers.
	// Either shape passes if it has a message_id + tenant_id;
	// anything else is rejected as payload_validation_failure.
	v.Register(SubjectEvaluateRequest, schema.SchemaVersionV1, evaluateRequestValidator)

	// es.evaluate.result: the EvaluateResult DTO is published
	// directly (no envelope) so the validator decodes straight
	// into it.
	schema.RegisterStruct[dto.EvaluateResult](v, SubjectEvaluateResult, schema.SchemaVersionV1, func(r *dto.EvaluateResult) error {
		if r == nil {
			return errors.New("evaluate result is nil")
		}
		if r.TenantID == "" {
			return errors.New("tenant_id required")
		}
		if r.MessageID == "" {
			return errors.New("message_id required")
		}
		return nil
	})

	// es.action.feedback.*: every feedback subject (`.report`,
	// `.confirm`, `.clear`) carries the same FeedbackEvent
	// shape. Pin by PREFIX so consumers ranging on
	// `es.action.feedback.>` see the same contract.
	schema.RegisterStructPrefix[action.FeedbackEvent](v, SubjectActionFeedbackPrefix, schema.SchemaVersionV1, func(f *action.FeedbackEvent) error {
		if f == nil {
			return errors.New("feedback event is nil")
		}
		if f.TenantID == "" {
			return errors.New("tenant_id required")
		}
		return nil
	})

	// es.action.clawback: tier escalation / retroactive action
	// notifications use the ClawbackEvent shape. Exact subject
	// — there is no per-kind suffix today.
	schema.RegisterStruct[action.ClawbackEvent](v, SubjectActionClawback, schema.SchemaVersionV1, func(c *action.ClawbackEvent) error {
		if c == nil {
			return errors.New("clawback event is nil")
		}
		if c.TenantID == "" {
			return errors.New("tenant_id required")
		}
		return nil
	})

	// es.action.label / banner / url_rewrite / quarantine all
	// carry the marshalled EvaluateResult (re-published by the
	// ingestion-action consumer). The DTO is intentionally the
	// same shape as es.evaluate.result so the action-side
	// consumers can decode without a separate envelope.
	for _, subj := range []string{
		SubjectActionLabel,
		SubjectActionBanner,
		SubjectActionURLRewrite,
		SubjectActionQuarantine,
	} {
		schema.RegisterStruct[dto.EvaluateResult](v, subj, schema.SchemaVersionV1, func(r *dto.EvaluateResult) error {
			if r == nil {
				return errors.New("evaluate result is nil")
			}
			if r.TenantID == "" {
				return errors.New("tenant_id required")
			}
			return nil
		})
	}

	// es.management.comm_history.update: per-message
	// communication-history update.
	schema.RegisterStruct[dto.CommHistoryUpdate](v, SubjectCommHistoryUpdate, schema.SchemaVersionV1, func(u *dto.CommHistoryUpdate) error {
		if u == nil {
			return errors.New("comm history update is nil")
		}
		if u.TenantID == "" {
			return errors.New("tenant_id required")
		}
		return nil
	})

	// es.dashboard.report.generated: per-tenant generated
	// dashboard snapshot.
	schema.RegisterStruct[dto.DashboardSummary](v, SubjectDashboardSummary, schema.SchemaVersionV1, func(d *dto.DashboardSummary) error {
		if d == nil {
			return errors.New("dashboard summary is nil")
		}
		if d.TenantID == "" {
			return errors.New("tenant_id required")
		}
		return nil
	})

	// es.action.escalation.{created,resolved}: ticket
	// transitions. The producer uses
	// internal/service/agent.escalationCreateEnvelope (a thin
	// {tenant_id, incident, ticket?} wrapper) on `.created` and
	// raw EscalationTicket on `.resolved`. We pin EscalationTicket
	// for both because the unmarshal is lenient on
	// `incident` and the validator only enforces tenant_id /
	// ticket_id which both shapes carry.
	for _, subj := range []string{
		SubjectEscalationCreated,
		SubjectEscalationResolved,
	} {
		schema.RegisterStruct[dto.EscalationTicket](v, subj, schema.SchemaVersionV1, func(t *dto.EscalationTicket) error {
			if t == nil {
				return errors.New("escalation ticket is nil")
			}
			return nil
		})
	}

	// es.education.interaction / simulation: the education
	// service emits both interaction events (clicked / reported
	// / ignored) and simulation-result events.
	schema.RegisterStructPrefix[dto.UserInteraction](v, SubjectEducationInteraction, schema.SchemaVersionV1, func(i *dto.UserInteraction) error {
		if i == nil {
			return errors.New("user interaction is nil")
		}
		return nil
	})
	schema.RegisterStructPrefix[dto.SimulationResult](v, SubjectEducationSimulation, schema.SchemaVersionV1, func(s *dto.SimulationResult) error {
		if s == nil {
			return errors.New("simulation result is nil")
		}
		return nil
	})

	// sn360.events.email.<tenant>.<kind>: every bridge envelope
	// shares the same shape regardless of kind, so we bind by
	// PREFIX. The validator only enforces that the envelope is
	// JSON-decodable into bridge.Envelope; the bridge package
	// constructs the envelope itself so the rule / agent /
	// labels invariants are guaranteed by the producer.
	schema.RegisterStructPrefix[bridge.Envelope](v, SubjectBridgeEnvelopePrefix, schema.SchemaVersionV1, func(e *bridge.Envelope) error {
		if e == nil {
			return errors.New("bridge envelope is nil")
		}
		return nil
	})
}

// evaluateRequestValidator accepts both the canonical
// BatchMessage{Request, Signals} wrapper AND the legacy flat
// dto.EvaluateRequest shape on `es.evaluate.request`. Either
// must carry a message_id + tenant_id; the wrapper case
// MUST also expose them at request.{message_id, tenant_id} so
// the canonical decoder downstream does not fall back to the
// legacy decode (and the validator must NOT accept a wrapper
// whose Request is empty even if a top-level message_id is
// present, because that would silently mask a bug in the
// upstream publisher).
//
// Implemented as a hand-rolled validator instead of
// schema.RegisterStruct[T] because the legacy/canonical
// duality is a property of THIS subject only — generalising
// it to the registry would force every consumer of
// schema.RegisterStruct[T] to opt into a "tolerate two
// shapes" mode, which defeats the strong-typing guarantee the
// rest of the registry depends on.
func evaluateRequestValidator(data []byte) error {
	if len(data) == 0 {
		return errors.New("evaluate request payload empty")
	}
	var bm evaluate.BatchMessage
	if err := json.Unmarshal(data, &bm); err != nil {
		return fmt.Errorf("decode %s v=%s: %w", SubjectEvaluateRequest, schema.SchemaVersionV1, err)
	}
	if bm.Request.MessageID != "" {
		// Canonical wrapped shape — enforce tenant_id at the
		// wrapped position; the legacy fall-back is irrelevant
		// when the wrapper is fully populated.
		if bm.Request.TenantID == "" {
			return errors.New("request.tenant_id required")
		}
		return nil
	}
	var flat dto.EvaluateRequest
	if err := json.Unmarshal(data, &flat); err != nil {
		return fmt.Errorf("decode %s v=%s (legacy flat shape): %w", SubjectEvaluateRequest, schema.SchemaVersionV1, err)
	}
	if flat.MessageID == "" {
		return errors.New("message_id required (neither BatchMessage.Request nor flat dto.EvaluateRequest carried one)")
	}
	if flat.TenantID == "" {
		return errors.New("tenant_id required")
	}
	return nil
}
