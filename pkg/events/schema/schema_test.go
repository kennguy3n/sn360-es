package schema_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/events/schema"
)

// payload is the in-test DTO every (subject, version) registration
// in this file targets. It carries SchemaVersion at the top level
// — the same shape the WS-7c rollout requires of every NATS DTO
// on the production side — so the test exercises the registry
// against the real JSON layout instead of a synthetic one.
type payload struct {
	SchemaVersion string `json:"schema_version"`
	TenantID      string `json:"tenant_id"`
	MessageID     string `json:"message_id"`
}

func TestValidator_NoRegistration_Passthrough(t *testing.T) {
	t.Parallel()
	v := schema.New()
	r := v.Validate("es.unregistered.subject", []byte(`{}`))
	if r.Reason != schema.ReasonNone {
		t.Fatalf("unregistered subject should pass, got reason=%q", r.Reason)
	}
	if r.IsMismatch() {
		t.Fatalf("unregistered subject must not be classified as mismatch")
	}
}

func TestValidator_MissingVersion_TreatedAsV1(t *testing.T) {
	t.Parallel()
	v := schema.New()
	schema.RegisterStruct[payload](v, "es.evaluate.request", schema.SchemaVersionV1, func(p *payload) error {
		if p.TenantID == "" {
			return errors.New("tenant_id required")
		}
		return nil
	})

	// Missing schema_version → resolved to v1, runs v1 validator.
	data := []byte(`{"tenant_id":"t-1","message_id":"m-1"}`)
	r := v.Validate("es.evaluate.request", data)
	if r.Reason != schema.ReasonMissingVersion {
		t.Fatalf("missing version should yield ReasonMissingVersion, got %q", r.Reason)
	}
	if r.IsMismatch() {
		t.Fatalf("missing version is not a mismatch — backward compat")
	}
	if r.ResolvedVersion != schema.SchemaVersionV1 {
		t.Fatalf("resolved version = %q, want v1", r.ResolvedVersion)
	}
}

func TestValidator_UnknownVersion_FlaggedAsMismatch(t *testing.T) {
	t.Parallel()
	v := schema.New()
	schema.RegisterStruct[payload](v, "es.evaluate.request", schema.SchemaVersionV1, nil)

	data := []byte(`{"schema_version":"v999","tenant_id":"t-1"}`)
	r := v.Validate("es.evaluate.request", data)
	if !r.IsMismatch() {
		t.Fatalf("v999 should be a mismatch")
	}
	if r.Reason != schema.ReasonUnknownVersion {
		t.Fatalf("got reason=%q, want unknown_version", r.Reason)
	}
	if r.ResolvedVersion != "v999" {
		t.Fatalf("resolved version = %q, want v999", r.ResolvedVersion)
	}
}

func TestValidator_PayloadInvalid_FlaggedAsMismatch(t *testing.T) {
	t.Parallel()
	v := schema.New()
	schema.RegisterStruct[payload](v, "es.evaluate.request", schema.SchemaVersionV1, func(p *payload) error {
		if p.TenantID == "" {
			return errors.New("tenant_id required")
		}
		return nil
	})

	data := []byte(`{"schema_version":"v1","message_id":"m-1"}`)
	r := v.Validate("es.evaluate.request", data)
	if !r.IsMismatch() {
		t.Fatalf("missing tenant should be a mismatch")
	}
	if r.Reason != schema.ReasonPayloadInvalid {
		t.Fatalf("got reason=%q, want payload_validation_failure", r.Reason)
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "tenant_id required") {
		t.Fatalf("Err missing or wrong: %v", r.Err)
	}
}

func TestValidator_ValidateOrError_StructuredError(t *testing.T) {
	t.Parallel()
	v := schema.New()
	schema.RegisterStruct[payload](v, "es.evaluate.request", schema.SchemaVersionV1, nil)

	err := v.ValidateOrError("es.evaluate.request", []byte(`{"schema_version":"v2"}`))
	if err == nil {
		t.Fatalf("unknown version should produce error")
	}
	var ve *schema.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Subject != "es.evaluate.request" {
		t.Fatalf("subject = %q, want es.evaluate.request", ve.Subject)
	}
	if ve.Reason != schema.ReasonUnknownVersion {
		t.Fatalf("reason = %q, want unknown_version", ve.Reason)
	}
	if !errors.Is(err, schema.ErrValidation) {
		t.Fatalf("errors.Is(err, ErrValidation) = false")
	}
}

func TestValidator_ValidateOrError_NilOnHappyPath(t *testing.T) {
	t.Parallel()
	v := schema.New()
	schema.RegisterStruct[payload](v, "es.evaluate.request", schema.SchemaVersionV1, nil)

	if err := v.ValidateOrError("es.evaluate.request", []byte(`{"schema_version":"v1","tenant_id":"t-1"}`)); err != nil {
		t.Fatalf("v1 happy path returned error: %v", err)
	}
	// Missing version (legacy) also OK because it resolves to v1.
	if err := v.ValidateOrError("es.evaluate.request", []byte(`{"tenant_id":"t-1"}`)); err != nil {
		t.Fatalf("missing version (legacy) returned error: %v", err)
	}
}

func TestValidator_RegisterPrefix_LongestWins(t *testing.T) {
	t.Parallel()
	v := schema.New()
	schema.RegisterStructPrefix[payload](v, "es.action", schema.SchemaVersionV1, func(p *payload) error {
		return errors.New("generic es.action validator")
	})
	schema.RegisterStructPrefix[payload](v, "es.action.feedback", schema.SchemaVersionV1, nil)

	// es.action.feedback.report → longest match is es.action.feedback, which passes.
	r := v.Validate("es.action.feedback.report", []byte(`{"schema_version":"v1"}`))
	if r.IsMismatch() {
		t.Fatalf("longest prefix match should win; got reason=%q err=%v", r.Reason, r.Err)
	}
	if r.SubjectMatch != "es.action.feedback" {
		t.Fatalf("subject_match = %q, want es.action.feedback", r.SubjectMatch)
	}

	// es.action.banner → only the generic match applies, which always fails.
	r = v.Validate("es.action.banner", []byte(`{"schema_version":"v1"}`))
	if !r.IsMismatch() {
		t.Fatalf("generic es.action validator should mismatch on banner")
	}
	if r.SubjectMatch != "es.action" {
		t.Fatalf("subject_match = %q, want es.action", r.SubjectMatch)
	}
}

func TestValidator_ExactMatchBeatsPrefix(t *testing.T) {
	t.Parallel()
	v := schema.New()
	schema.RegisterStructPrefix[payload](v, "es.action", schema.SchemaVersionV1, func(p *payload) error {
		return errors.New("prefix rejects")
	})
	schema.RegisterStruct[payload](v, "es.action.label", schema.SchemaVersionV1, nil)

	r := v.Validate("es.action.label", []byte(`{"schema_version":"v1"}`))
	if r.IsMismatch() {
		t.Fatalf("exact match should beat prefix; got reason=%q", r.Reason)
	}
	if r.SubjectMatch != "es.action.label" {
		t.Fatalf("subject_match = %q, want es.action.label", r.SubjectMatch)
	}
}

func TestPeekVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"missing", `{"foo":"bar"}`, ""},
		{"present_v1", `{"schema_version":"v1","foo":"bar"}`, "v1"},
		{"present_v2", `{"schema_version":"v2"}`, "v2"},
		{"empty_payload", ``, ""},
		{"malformed_json", `{not_json`, ""},
		{"nested_unaffected", `{"data":{"schema_version":"v9"},"schema_version":"v1"}`, "v1"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := schema.PeekVersion([]byte(tc.in)); got != tc.want {
				t.Fatalf("PeekVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDLQSubject(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"es.evaluate.request", "sn360.dlq.schema.es.evaluate.request"},
		{"es.evaluate.request.t-42", "sn360.dlq.schema.es.evaluate.request.t-42"},
		{"", "sn360.dlq.schema.other"},
		{"sn360.dlq.schema.es.evaluate.request", "sn360.dlq.schema.es.evaluate.request"},
		{"sn360.dlq.schema", "sn360.dlq.schema"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := schema.DLQSubject(tc.in); got != tc.want {
				t.Fatalf("DLQSubject(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidator_SubjectFamilyAndRegisteredVersions(t *testing.T) {
	t.Parallel()
	v := schema.New()
	schema.RegisterStruct[payload](v, "es.evaluate.request", schema.SchemaVersionV1, nil)
	schema.RegisterStructPrefix[payload](v, "es.action.feedback", schema.SchemaVersionV1, nil)

	if got := v.SubjectFamily("es.evaluate.request"); got != "es.evaluate.request" {
		t.Fatalf("SubjectFamily exact = %q", got)
	}
	if got := v.SubjectFamily("es.action.feedback.report"); got != "es.action.feedback" {
		t.Fatalf("SubjectFamily prefix = %q", got)
	}
	if got := v.SubjectFamily("es.nope"); got != "" {
		t.Fatalf("SubjectFamily unmatched = %q, want empty", got)
	}
	if got := v.RegisteredVersions("es.evaluate.request"); len(got) != 1 || got[0] != schema.SchemaVersionV1 {
		t.Fatalf("RegisteredVersions = %v", got)
	}
}

func TestValidator_NilSafe(t *testing.T) {
	t.Parallel()
	var v *schema.Validator
	// Methods on nil receiver must not panic — call sites
	// frequently pass nil when running in single-binary tests
	// without registering any schema.
	if r := v.Validate("es.foo", []byte(`{}`)); r.IsMismatch() {
		t.Fatalf("nil validator should pass everything")
	}
	if err := v.ValidateOrError("es.foo", []byte(`{}`)); err != nil {
		t.Fatalf("nil validator ValidateOrError = %v", err)
	}
}
