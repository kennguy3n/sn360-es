# NATS Message Schema Versioning

This document is the load-bearing reference for the schema versioning
subsystem. It covers:

1. Why the gate exists ([§1](#1-why))
2. The wire-format contract ([§2](#2-wire-format))
3. The validator surface and its behaviours ([§3](#3-validator))
4. The schema-mismatch DLQ ([§4](#4-schema-dlq))
5. Backward and forward compatibility ([§5](#5-compat))
6. How to ship a `v2` shape ([§6](#6-v2-howto))
7. Cross-repo cutover with `sn360-security-platform` ([§7](#7-platform-cutover))
8. Observability and metrics ([§8](#8-observability))

If you change the validator, the DLQ contract, or the wire
format, update this doc in the same PR — the validator
package's doc comments link back here as the source of truth.

## <a id="1-why"></a>1. Why schema versioning?

ARCHITECTURE.md §3 documents the migration class of bug that
killed productivity for two days: a publisher rolled the
canonical `BatchMessage{Request, Signals}` wrapper on
`es.evaluate.request` before the consumer side had landed the
matching decoder. JetStream cheerfully dedup'd and shipped the
message; the consumer's typed `json.Unmarshal` threw `unknown
field` and the broker entered an infinite redeliver loop
because every retry hit the same shape mismatch. The shape
mismatch was undetectable at publish time because nothing in
the broker cared about the payload shape — only the consumer
did, and only at message-handler time.

Schema versioning closes that gap. The wire format now carries an
explicit `schema_version` field, the publish path enforces
the registered `(subject, schema_version) -> Go-type` contract
before the broker call, and the subscribe path repeats the
same check before invoking the handler. A version mismatch is
a structured error at publish and a routed message on the
schema-mismatch DLQ at subscribe — never an infinite redeliver
loop, never a typed-unmarshal panic in production.

## <a id="2-wire-format"></a>2. Wire format

Every NATS DTO under `internal/dto/` plus the three wrapper
types (`internal/service/evaluate.BatchMessage`,
`internal/service/action.FeedbackEvent`,
`internal/service/action.ClawbackEvent`) and the bridge envelope
(`internal/service/bridge.Envelope`) carries a top-level
`schema_version` string field:

```json
{
  "schema_version": "v1",
  "tenant_id": "...",
  "message_id": "...",
  ...
}
```

The field is **top-level**, not nested. Nesting it (e.g. on the
inner `Request` of a `BatchMessage`) would force the validator
to know which sub-document to look at before it had decided
which shape the payload was — defeating the whole point of
versioning. The schema field's wire name is the package-level
constant `pkg/events/schema.SchemaVersionField` (= `"schema_version"`).

The header `schema-version` MIRRORS the in-payload field. A
passive observer running `nats consume sn360-events --headers-only`
sees the version without parsing the body. The header is set by
the publish path (`pkg/events/nats.Publisher.Publish`) and the
platform bridge (`internal/service/bridge.platform_publisher.publish`)
from the in-payload value after the v1-stamp pass — i.e. the
header always agrees with what is on the wire.

### Version value semantics

- `"v1"` is the canonical first version every DTO ships with on
  the initial schema versioning rollout. `pkg/events/schema.SchemaVersionV1` is the
  load-bearing constant; producer code does not hardcode the
  literal.
- The field is a `string` (not an `int`) so we can land
  breaking changes like `"v2"` or experimental forks like
  `"v1-experiment"` without changing the wire representation.
- An ABSENT `schema_version` is treated as `"v1"` — see
  [§5](#5-compat).

## <a id="3-validator"></a>3. Validator surface

The validator lives in [`pkg/events/schema`](../pkg/events/schema/).
Public API:

| Function | Purpose |
|---|---|
| `schema.New()` | Empty registry. |
| `schema.Register(subject, version, fn)` | Bind exact subject. |
| `schema.RegisterPrefix(prefix, version, fn)` | Bind subject prefix. |
| `schema.RegisterStruct[T](v, subj, ver, extra)` | Decode into `T`, optional semantic check. |
| `schema.RegisterStructPrefix[T](v, prefix, ver, extra)` | Prefix variant. |
| `v.Validate(subject, data) -> Result` | Run validation. |
| `v.ValidateOrError(subject, data) -> error` | Publisher convenience wrapper. |
| `schema.PeekVersion(data) -> string` | Cheap JSON peek, no full unmarshal. |
| `schema.Stamp(data, version) -> (data, stamped, err)` | Insert missing `schema_version` first-field. |
| `schema.DLQSubject(origin) -> string` | Map a subject to its schema-mismatch DLQ subject. |

The canonical sn360-es registry lives in
[`internal/eventsschema`](../eventsschema/registry.go). Every
subject the binary publishes or subscribes to is bound there;
unregistered subjects pass through (the validator is opt-in).

### Result classifications

`schema.MismatchReason` is a small enum the validator returns:

| Reason | Mismatch? | DLQ? | Meaning |
|---|---|---|---|
| `""` (`ReasonNone`) | no | no | Either no schema registered, or the payload satisfied the registered version's shape check. |
| `missing_version` | no | no | Payload omitted `schema_version`; defaulted to `v1` and the v1 validator accepted it. Emitted to the metric for dashboard visibility only. |
| `unknown_version` | yes | yes | Payload claims an explicit version the registry does NOT cover for this subject. Forward-compat trap (e.g. producer rolled `"v2"` before the consumer registry was updated). |
| `payload_validation_failure` | yes | yes | Payload claims a version we know, but the shape check returned an error. |

`Result.IsMismatch()` returns `true` for the latter two and
`false` for the former two. `IsMismatch()` is the DLQ-routing
gate at publish and subscribe time.

## <a id="4-schema-dlq"></a>4. Schema-mismatch DLQ

A mismatch on the subscribe path routes the original payload
to:

```
sn360.dlq.schema.<original_subject>
```

So a mismatched delivery on `es.evaluate.request.t-42` lands on
`sn360.dlq.schema.es.evaluate.request.t-42`. Header
preservation:

| Original header | DLQ header | Purpose |
|---|---|---|
| `Nats-Msg-Id` | `Nats-Msg-Id = "schema-" + original` | Idempotency on retry. |
| `correlation-id` | preserved | Tracing. |
| `tenant-id` | preserved | RLS / per-tenant replay tooling. |
| `event-type` | preserved | Classifier on the DLQ side. |
| `schema-version` | preserved | What the producer claimed. |
| — | `origin-subject = <orig>` | Replay tooling reads this back. |
| — | `schema-mismatch-reason = <enum>` | `unknown_version` or `payload_validation_failure`. |
| — | `error = "schema mismatch: <reason>[: <validator err>]"` | Human-readable. |

The schema-DLQ stream `SN360_SCHEMA_DLQ`
([`pkg/events/nats/streams.go`](../pkg/events/nats/streams.go))
binds the `sn360.dlq.schema.>` wildcard, retains messages for
30 days, and applies the same 600s dedup window every other
DLQ stream uses (FU-B contract). The namespace is
intentionally disjoint from `es.dlq.>` (the handler-failure
DLQ) so an operator scanning the DLQ stream can tell "this
failed the handler" from "this had the wrong version" at the
subject level, without parsing headers.

### Publish-side enforcement is FATAL

A mismatch at publish time returns a `*schema.ValidationError`
from `pkg/events/nats.Publisher.Publish`. The broker call is
NOT made. The error carries `Subject`, `ResolvedVersion`,
`Reason`, and `Cause` so callers can branch programmatically
via `errors.As(err, &target)`.

The platform-bridge publisher
([`internal/service/bridge/platform_publisher.go`](../service/bridge/platform_publisher.go))
is the one exception: a mismatch logs a warn, increments the
metric, and STILL publishes the payload. The bridge cannot
afford to drop a verdict because a hot-rolled `v2` envelope
hits the validator before the consumer side has caught up —
the SOC outage would be worse than a one-off shape drift.

### Subscribe-side enforcement is NON-FATAL

A mismatch at subscribe time
([`cmd/sn360-es/consumers_schema.go`](../cmd/sn360-es/consumers_schema.go))
republishes the payload onto the schema-mismatch DLQ and Acks
the original delivery. The handler is NOT invoked. The wrapper
returns `nil` so the underlying JetStream consumer does not
NAK. This is the load-bearing difference from the
ARCHITECTURE.md §3 bug: an "unknown version" payload no longer
loops forever — it lands on the DLQ within one delivery.

## <a id="5-compat"></a>5. Backward and forward compatibility

### Backward compat (pre-versioning publishers)

A payload with NO `schema_version` field is treated as `"v1"`.
The validator defaults the version, runs the v1 validator, and
the message processes normally. The
`ReasonMissingVersion` flag is emitted on `Result.Reason` so
the operator dashboard can see "legacy publisher X is still in
the field" without routing those messages anywhere.

### Forward compat (post-versioning bumps)

A payload with `schema_version: "v999"` is treated as a
forward-compat trap. The validator returns
`Reason=ReasonUnknownVersion` and the subscribe path routes
it to the schema-mismatch DLQ. The publish path rejects it
with `*schema.ValidationError`. This is the design that
prevents the ARCHITECTURE.md §3 bug from recurring: a producer
rolling a new shape before its corresponding consumer is
registered is rejected at the publish boundary, not at the
consumer's typed unmarshal three hops later.

### Lock-step rollouts are NOT required

`v1` and `v2` consumers can coexist on the same subject. The
validator dispatches per-version, so a `v1` payload runs the
v1 shape check and a `v2` payload runs the v2 shape check.
Producers and consumers can roll independently as long as the
consumer side registers the new version BEFORE the producer
side starts emitting it.

## <a id="6-v2-howto"></a>6. Shipping a `v2` shape

1. **Author the new struct.** Add `MyEventV2` next to
   `MyEvent` (do NOT mutate the v1 struct). Carry
   `schema_version` as a top-level field.

2. **Register the new shape.** Add a second registration in
   `internal/eventsschema/registry.go`:
   ```go
   schema.RegisterStruct[dto.MyEventV2](v, "es.my.subject", "v2", validateV2)
   ```

3. **Ship the consumer first.** Deploy the consumer-side
   binary with both `v1` and `v2` registrations before any
   producer emits `v2`. A premature producer would otherwise
   trip the schema-mismatch DLQ on every delivery.

4. **Roll the producer.** Once the consumer is live and the
   `nats_schema_mismatch_total{reason="unknown_version"}`
   metric is clean for a full release window, flip the
   producer to publish `MyEventV2` with `SchemaVersion: "v2"`.

5. **Decommission v1.** When the
   `nats_schema_mismatch_total{reason="missing_version"}`
   counter has been zero for one full release window, drop
   the v1 registration. Do NOT remove the v1 struct itself —
   the schema-DLQ replay tooling may still need to decode
   historical messages.

The cutover plan is documented in PR descriptions, not in
code, so the validator's behaviour stays orthogonal to the
deployment timeline.

## <a id="7-platform-cutover"></a>7. Cross-repo cutover with `sn360-security-platform`

The platform consumes the bridge envelope
(`sn360.events.email.<tenant>.<kind>`) and the
correlation/playbook engines unmarshal it into their own Go
shapes. The platform side mirrors the
schema versioning contract:

- `services/correlation-engine` and `services/playbook-engine`
  carry their own `_schemaversion` shared package + a
  `SchemaVersion` field on `Event`.
- The platform's subscribe path runs the same `(subject, version)`
  registry; unknown versions are terminated.
- Pre-versioning payloads (no `schema_version` field) are accepted
  as v1 on the platform side, so sn360-es can ship v1-tagged
  events before the platform side is updated without a
  lockstep flip.

The recommended deployment order is:

1. Land the platform-side mirror first. With backward-compat
   on, the platform accepts both the legacy unversioned events
   and the new v1-tagged events.
2. Land the sn360-es side second. The bridge publisher
   stamps `v1` on every envelope, so platform consumers see
   versioned events from the moment sn360-es rolls.
3. There is no version bump required on the platform during
   the rollout — the contract is to accept v1, not enforce
   v1 strictly. Strict mode (term unknown versions) is the
   long-term steady state.

## <a id="8-observability"></a>8. Observability

The Prometheus counter
`nats_schema_mismatch_total{subject_family, reason, side}`
is the operator-visible signal:

| Label | Values |
|---|---|
| `subject_family` | The registry-matched key — e.g. `es.evaluate.request`, NOT the per-message subject suffix `.t-42` (high-cardinality). |
| `reason` | `missing_version`, `unknown_version`, `payload_validation_failure`, or `unknown` (defensive fallback). |
| `side` | `publish` (publisher-side enforcement) or `subscribe` (consumer-side enforcement). |

A non-zero rate on `reason=missing_version` means at least one
upstream publisher is still emitting the pre-versioning shape;
a non-zero rate on `reason=unknown_version` or
`payload_validation_failure` is an active outage — a producer
just rolled a shape the consumer side does not understand and
is filling the schema-mismatch DLQ.

Recommended alerts:

- `rate(nats_schema_mismatch_total{reason="unknown_version"}[5m]) > 0`
  — page on any sustained forward-compat trap.
- `rate(nats_schema_mismatch_total{reason="payload_validation_failure"}[5m]) > 0`
  — page on any sustained shape failure.
- `sum by (subject_family) (rate(nats_schema_mismatch_total{reason="missing_version"}[1h])) > 0`
  — non-paging dashboard tile so the operator can see which
  publishers have not migrated yet.
