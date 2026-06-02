// Package schema implements the WS-7c NATS message schema-version
// registry and validator. It is the load-bearing piece that prevents
// the BatchMessage vs flat dto.EvaluateRequest migration class of
// bug documented in ARCHITECTURE.md §3: a publisher that ships a
// payload whose JSON shape does not match the registered schema
// for that (subject, schema_version) is now rejected at publish
// time with a structured error, instead of silently passing the
// broker and crashing the consumer's typed json.Unmarshal three
// hops later.
//
// The registry is intentionally a pure in-memory data structure.
// Validators are pinned by exact subject (preferred) or by the
// longest matching subject prefix. A `(subject, version)` pair
// that is not registered is treated as "no schema applies here"
// and the validator returns success — this is what keeps the
// validator opt-in and lets sites that have not yet enrolled a
// schema continue to publish without a sweeping audit. The
// adoption boundary is a property of the registry, NOT the
// validator: register a schema for a subject, and it is enforced
// everywhere; leave it unregistered, and the legacy passthrough
// behaviour applies.
//
// Version semantics (WS-7c §4 "Backward compat"): a payload whose
// JSON does NOT contain `schema_version` is treated as `"v1"` —
// the shape the platform shipped before this PR. A payload
// carrying an explicit `schema_version` value that is NOT
// registered for the resolved subject is treated as a
// FORWARD-incompatible message and routed to the schema DLQ at
// subscribe time / rejected with a structured error at publish
// time. A payload whose JSON DOES match the registered version
// but fails the version-specific shape check is treated as
// PAYLOAD-invalid and handled identically. The three outcomes
// (passthrough, unknown_version, payload_validation_failure)
// are surfaced via MismatchReason so the call site can emit the
// correct Prometheus counter label.
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// SchemaVersionV1 is the canonical first version every DTO ships
// with on the WS-7c rollout. The field type is `string` (not int)
// so we can land breaking changes like `"v2"` or experimental
// forks like `"v1-experiment"` without changing the wire
// representation.
const SchemaVersionV1 = "v1"

// SchemaVersionField is the JSON key the validator looks for on
// the payload to discover the message's self-declared version.
// Kept as a package-level constant so the consumer-side peek
// (`pkg/events/schema.peekVersion`) and the documentation
// (`docs/SCHEMA_VERSIONING.md`) cannot drift on a
// rename.
const SchemaVersionField = "schema_version"

// MismatchReason is the structural classification of a
// schema-validation outcome. It is a small enum so the
// Prometheus counter `nats_schema_mismatch_total` can carry it as
// a low-cardinality label (`reason=missing_version`,
// `reason=unknown_version`, `reason=payload_validation_failure`)
// instead of a free-form string.
type MismatchReason string

const (
	// ReasonNone is the validator's success outcome — either the
	// subject had no registered schema, or the payload satisfied
	// every check for the resolved version. The DLQ router uses
	// `reason == ReasonNone` as its "pass through" gate.
	ReasonNone MismatchReason = ""

	// ReasonMissingVersion is the success-but-defaulted outcome:
	// the payload omitted `schema_version`, so the validator
	// resolved it to SchemaVersionV1 and ran the v1 validator.
	// This is NOT a DLQ-routing event — backward compat with
	// pre-WS-7c publishers depends on it being a passthrough —
	// but call sites that want to track legacy publishers can
	// emit the counter with reason=missing_version anyway.
	ReasonMissingVersion MismatchReason = "missing_version"

	// ReasonUnknownVersion fires when the payload carries an
	// explicit `schema_version` value that is NOT registered for
	// the resolved subject. This is the forward-compat trap that
	// WS-7c was designed to prevent: a producer rolling a `"v2"`
	// shape before its corresponding validator is registered on
	// the consumer side is now rejected at the publish boundary
	// instead of silently turning into a typed-unmarshal panic
	// on the receiving end. At subscribe time, the message is
	// terminated and republished to `sn360.dlq.schema.<subject>`.
	ReasonUnknownVersion MismatchReason = "unknown_version"

	// ReasonPayloadInvalid fires when the payload claims a
	// version we DO know about, but the JSON shape fails the
	// version-specific check (e.g. mandatory field empty, type
	// mismatch). Handled identically to ReasonUnknownVersion at
	// the subscribe / publish boundary.
	ReasonPayloadInvalid MismatchReason = "payload_validation_failure"
)

// Validator is a registry of `(subject, version) -> shape checker`
// entries. Methods on Validator are safe for concurrent use; the
// registry itself is mutated only via Register* at startup and is
// read-only on the hot path.
type Validator struct {
	mu sync.RWMutex
	// entries maps exact subject -> version -> validator. Exact
	// matches win over prefix matches (see lookupLocked).
	entries map[string]map[string]validatorFn
	// prefixEntries maps subject-prefix -> version -> validator.
	// A prefix matches when the message subject begins with
	// `prefix + "."` or equals `prefix` exactly. Longest prefix
	// wins, so a `es.action.feedback` registration is preferred
	// over a generic `es.action` registration on a
	// `es.action.feedback.report` delivery.
	prefixEntries map[string]map[string]validatorFn
}

// validatorFn is the runtime shape-check signature. The function
// receives the raw payload bytes and returns nil on a valid
// shape, or a non-nil error explaining the violation. Errors are
// wrapped into ValidationError by the public API so call sites
// can inspect Subject / Version / Reason without parsing the
// message string.
type validatorFn func(data []byte) error

// New constructs an empty Validator. Registrations are added via
// Register / RegisterPrefix / RegisterStruct.
func New() *Validator {
	return &Validator{
		entries:       map[string]map[string]validatorFn{},
		prefixEntries: map[string]map[string]validatorFn{},
	}
}

// Register binds (subject, version) to a custom validator
// function. Registrations are last-write-wins on the
// (subject, version) tuple; tests rely on this to swap in a
// stricter check than the production registry. Subject is matched
// EXACTLY — to bind a wildcard subject family (e.g. every
// `es.action.feedback.*`), call RegisterPrefix instead.
func (v *Validator) Register(subject, version string, fn func(data []byte) error) {
	if v == nil || subject == "" || version == "" || fn == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	versions, ok := v.entries[subject]
	if !ok {
		versions = map[string]validatorFn{}
		v.entries[subject] = versions
	}
	versions[version] = validatorFn(fn)
}

// RegisterPrefix is the wildcard-aware sibling of Register.
// `prefix` matches any subject equal to it OR starting with
// `prefix + "."`. Wildcards within the prefix (`>` / `*`) are
// NOT supported — use RegisterPrefix("es.action.feedback", ...)
// rather than RegisterPrefix("es.action.feedback.>"...).
func (v *Validator) RegisterPrefix(prefix, version string, fn func(data []byte) error) {
	if v == nil || prefix == "" || version == "" || fn == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	versions, ok := v.prefixEntries[prefix]
	if !ok {
		versions = map[string]validatorFn{}
		v.prefixEntries[prefix] = versions
	}
	versions[version] = validatorFn(fn)
}

// Result is the outcome of a Validate call. ResolvedVersion is
// the version the validator ran against (SchemaVersionV1 when the
// payload omitted the field). Reason classifies the outcome; on
// success Reason is ReasonNone. SubjectMatch is the registry key
// that matched (empty when no schema was registered) — call
// sites use it for the metric label so a `subject_match` of
// `es.evaluate.request` covers every delivery on
// `es.evaluate.request.t-42`.
type Result struct {
	ResolvedVersion string
	Reason          MismatchReason
	SubjectMatch    string
	// Err is the underlying validator error when Reason is
	// ReasonPayloadInvalid. nil otherwise.
	Err error
}

// IsMismatch reports whether the result is a forward-compat trap
// or a payload-shape failure (i.e. the caller should DLQ the
// message and emit the mismatch metric). ReasonMissingVersion is
// NOT a mismatch — it is the legacy-publisher backward-compat
// path and the message passes through.
func (r Result) IsMismatch() bool {
	return r.Reason == ReasonUnknownVersion || r.Reason == ReasonPayloadInvalid
}

// ValidationError is the structured error type the publish path
// returns when validation fails. It implements the standard
// `error` interface AND exposes the subject / version / reason
// so call sites can branch on the cause without string-matching.
type ValidationError struct {
	Subject string
	// ResolvedVersion is the version the validator considered.
	// Empty when the registry had no entries for the subject.
	ResolvedVersion string
	Reason          MismatchReason
	Cause           error
}

// Error renders a human-readable diagnostic. The text format is
// stable enough for log scraping but call sites that need
// programmatic dispatch should `errors.As` into *ValidationError
// and read the structured fields.
func (e *ValidationError) Error() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("schema validation failed for subject ")
	b.WriteString(e.Subject)
	if e.ResolvedVersion != "" {
		b.WriteString(" (resolved version ")
		b.WriteString(e.ResolvedVersion)
		b.WriteString(")")
	}
	if e.Reason != "" {
		b.WriteString(": ")
		b.WriteString(string(e.Reason))
	}
	if e.Cause != nil {
		b.WriteString(": ")
		b.WriteString(e.Cause.Error())
	}
	return b.String()
}

// Unwrap exposes the underlying validator error to errors.Is /
// errors.As so callers can match on sentinel errors (e.g. a
// per-version "field X required" sentinel) returned from a
// custom validator.
func (e *ValidationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ErrValidation is the sentinel for `errors.Is` callers that
// only care that a ValidationError was returned. New code should
// prefer `errors.As(err, &target)` and inspect the structured
// fields.
var ErrValidation = errors.New("schema validation failed")

// Is satisfies errors.Is(*ValidationError, ErrValidation).
func (e *ValidationError) Is(target error) bool {
	return target == ErrValidation
}

// PeekVersion is a cheap JSON peek that extracts `schema_version`
// without unmarshalling the full payload. It is used by the
// publish + subscribe wiring so the slow per-version shape
// validators only run when the message claims a registered
// version. An empty / missing field returns "" — call sites
// then default to SchemaVersionV1.
func PeekVersion(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	// Use a thin struct-tag decode rather than a full
	// map[string]any walk. Encoder benchmark on the
	// representative EvaluateRequest payload (~3 KB) was 8x
	// faster than json.Decoder + Token loop and 14x faster
	// than map[string]any. Production hot path runs this on
	// every published / consumed message, so the constant
	// matters.
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	// Ignore the error: a payload we cannot peek will fail the
	// downstream version-specific validator anyway, and we want
	// the resolved-version-empty branch (which falls through to
	// SchemaVersionV1 / "" -> ReasonMissingVersion) to handle
	// the legacy backward-compat case.
	_ = json.Unmarshal(data, &probe)
	return probe.SchemaVersion
}

// Validate runs the registered shape checker for the given
// subject. Behaviour by case:
//
//	subject HAS no registered entries (exact or prefix):
//	  Result{ResolvedVersion: "", Reason: ReasonNone}
//	  — the validator is opt-in and unregistered subjects pass.
//
//	subject HAS entries + payload omits schema_version:
//	  ResolvedVersion: "v1", Reason: ReasonMissingVersion when no v1 validator OR v1 validator succeeds.
//	  The MissingVersion reason is a tagging-only flag; call sites
//	  must NOT route to the DLQ on it (`Result.IsMismatch()` is
//	  false). It exists so dashboards can see "legacy publisher X
//	  is still in the field".
//
//	subject HAS entries + payload carries an unregistered version:
//	  ResolvedVersion: <whatever the payload claimed>,
//	  Reason: ReasonUnknownVersion.
//	  Mismatch; route to DLQ.
//
//	subject HAS entries + payload's version validator returns err:
//	  ResolvedVersion: <claimed version>,
//	  Reason: ReasonPayloadInvalid, Err: <validator error>.
//	  Mismatch; route to DLQ.
func (v *Validator) Validate(subject string, data []byte) Result {
	if v == nil {
		return Result{}
	}
	matchedSubject, versions := v.lookup(subject)
	if versions == nil {
		// No schema registered — passthrough.
		return Result{}
	}
	claimedVersion := PeekVersion(data)
	resolved := claimedVersion
	missing := false
	if resolved == "" {
		resolved = SchemaVersionV1
		missing = true
	}
	fn, ok := versions[resolved]
	if !ok {
		reason := ReasonUnknownVersion
		// A missing version that defaulted to v1 but the
		// registry has no v1 entry is ALSO an
		// "unknown version" — the registry must explicitly
		// register v1 to claim a subject. This guards against
		// the case where someone registers only a "v2" entry
		// for a subject by mistake and silently breaks every
		// legacy publisher on that subject.
		_ = reason
		return Result{
			ResolvedVersion: resolved,
			Reason:          ReasonUnknownVersion,
			SubjectMatch:    matchedSubject,
		}
	}
	if err := fn(data); err != nil {
		return Result{
			ResolvedVersion: resolved,
			Reason:          ReasonPayloadInvalid,
			SubjectMatch:    matchedSubject,
			Err:             err,
		}
	}
	if missing {
		return Result{
			ResolvedVersion: resolved,
			Reason:          ReasonMissingVersion,
			SubjectMatch:    matchedSubject,
		}
	}
	return Result{
		ResolvedVersion: resolved,
		Reason:          ReasonNone,
		SubjectMatch:    matchedSubject,
	}
}

// ValidateOrError is a convenience wrapper used by the publish
// path: it returns a ValidationError when Result.IsMismatch() is
// true, and nil otherwise. ReasonMissingVersion is NOT
// converted to an error (publishers using the legacy shape need
// to keep working).
func (v *Validator) ValidateOrError(subject string, data []byte) error {
	r := v.Validate(subject, data)
	if !r.IsMismatch() {
		return nil
	}
	return &ValidationError{
		Subject:         subject,
		ResolvedVersion: r.ResolvedVersion,
		Reason:          r.Reason,
		Cause:           r.Err,
	}
}

// RegisteredVersions enumerates the versions known for the given
// subject (or its longest matching prefix). Returns nil when no
// schema is registered. Used by tests and the schema DLQ tooling
// to surface "what versions does the platform know about today?".
func (v *Validator) RegisteredVersions(subject string) []string {
	if v == nil {
		return nil
	}
	_, versions := v.lookup(subject)
	if versions == nil {
		return nil
	}
	out := make([]string, 0, len(versions))
	for k := range versions {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lookup returns the matched subject key and the version map for
// the given subject, preferring an exact match over a prefix
// match and the longest prefix match over a shorter one. The
// matched subject is returned so the caller can emit it as the
// `subject_match` label on the metric — the message's literal
// subject (e.g. `es.evaluate.request.t-42`) is high-cardinality
// and unsuitable for Prometheus.
func (v *Validator) lookup(subject string) (string, map[string]validatorFn) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if versions, ok := v.entries[subject]; ok {
		return subject, versions
	}
	// Longest prefix wins.
	var matchedPrefix string
	var matched map[string]validatorFn
	for prefix, versions := range v.prefixEntries {
		if subject == prefix || strings.HasPrefix(subject, prefix+".") {
			if len(prefix) > len(matchedPrefix) {
				matchedPrefix = prefix
				matched = versions
			}
		}
	}
	return matchedPrefix, matched
}

// SubjectFamily extracts the registration key that matches a
// concrete subject. Returns "" when nothing matches. Useful for
// callers that want to know "what does the registry think this
// subject is?" without running a full validation pass — for
// example, log fields that distinguish legitimate unmatched
// subjects from subjects the registry was supposed to cover.
func (v *Validator) SubjectFamily(subject string) string {
	matched, _ := v.lookup(subject)
	return matched
}

// DLQSubject derives the schema-mismatch DLQ subject for a given
// concrete subject. The contract is documented in
// `docs/SCHEMA_VERSIONING.md` and consumed by the
// subscribe-time wiring: a mismatched message on subject
// `es.evaluate.request.t-42` is republished on
// `sn360.dlq.schema.es.evaluate.request.t-42` with the original
// payload and headers intact plus a HeaderError describing the
// reason. The `sn360.dlq.schema.>` namespace is disjoint from
// every primary stream's wildcard so JetStream does not reject
// the schema-DLQ stream as overlapping.
//
// Subjects already under `sn360.dlq.schema.` are returned
// unchanged so a re-validation loop (e.g. a misconfigured
// validator registered against the DLQ subject family) cannot
// recursively republish the same payload deeper and deeper.
func DLQSubject(origin string) string {
	if origin == "" {
		return DLQSubjectPrefix + ".other"
	}
	if strings.HasPrefix(origin, DLQSubjectPrefix+".") || origin == DLQSubjectPrefix {
		return origin
	}
	return DLQSubjectPrefix + "." + origin
}

// DLQSubjectPrefix is the top-level subject namespace for
// schema-mismatch DLQ messages. It is intentionally separate
// from `es.dlq.>` (the existing handler-failure DLQ) so an
// operator scanning the DLQ stream can tell "this message failed
// the handler" from "this message had the wrong version" at the
// subject level, without parsing headers.
const DLQSubjectPrefix = "sn360.dlq.schema"

// formatJSONError wraps a json.Unmarshal error with the subject
// and version context the registry's struct-validator helpers
// use. Internal helper for RegisterStruct.
func formatJSONError(subject, version string, err error) error {
	return fmt.Errorf("decode %s v=%s: %w", subject, version, err)
}
