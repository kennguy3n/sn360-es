package dto

// SchemaVersionV1 is the canonical first version every NATS message
// DTO defined under internal/dto/ ships with on the WS-7c rollout.
//
// Wire shape (top-level, NOT nested):
//
//	{ "schema_version": "v1", "tenant_id": "...", ... }
//
// Every DTO that crosses a NATS subject boundary carries this value
// in its `schema_version` JSON field. Producers SHOULD set the
// field explicitly at construction, e.g.
//
//	req := dto.EvaluateRequest{
//	    SchemaVersion: dto.SchemaVersionV1,
//	    MessageID:     "...",
//	    ...
//	}
//
// The publish-side validator (pkg/events/schema) auto-stamps the
// same value as a backstop when a legacy producer forgot, so the
// wire format is always self-describing regardless of which call
// site sent it.
//
// The string type is deliberate: rolling a `"v2"` shape only
// requires registering a new validator entry; the underlying field
// type does not change, and every downstream consumer that has
// already been taught about `"v2"` keeps validating against the
// versions it knows about. Cutover details are documented in
// docs/SCHEMA_VERSIONING.md.
const SchemaVersionV1 = "v1"
