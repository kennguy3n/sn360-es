package schema_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/events/schema"
)

func TestStamp_AddsMissingVersion(t *testing.T) {
	t.Parallel()
	in := []byte(`{"tenant_id":"t-1","message_id":"m-1"}`)
	out, changed, err := schema.Stamp(in, schema.SchemaVersionV1)
	if err != nil {
		t.Fatalf("Stamp returned err: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if v := schema.PeekVersion(out); v != schema.SchemaVersionV1 {
		t.Fatalf("PeekVersion(out) = %q, want v1", v)
	}
	// Original keys must round-trip through the stamp.
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if parsed["tenant_id"] != "t-1" {
		t.Fatalf("tenant_id lost: %v", parsed["tenant_id"])
	}
	if parsed["message_id"] != "m-1" {
		t.Fatalf("message_id lost: %v", parsed["message_id"])
	}
	// schema_version must be the first key on the wire so
	// `nats consume` dumps are immediately self-describing.
	if !strings.HasPrefix(string(out), `{"schema_version":"v1",`) {
		t.Fatalf("schema_version not prepended: %s", string(out))
	}
}

func TestStamp_NoOpWhenVersionPresent(t *testing.T) {
	t.Parallel()
	in := []byte(`{"schema_version":"v2","tenant_id":"t-1"}`)
	out, changed, err := schema.Stamp(in, schema.SchemaVersionV1)
	if err != nil {
		t.Fatalf("Stamp returned err: %v", err)
	}
	if changed {
		t.Fatalf("changed should be false")
	}
	if string(out) != string(in) {
		t.Fatalf("payload mutated: %s", string(out))
	}
	if v := schema.PeekVersion(out); v != "v2" {
		t.Fatalf("PeekVersion(out) = %q, want v2 (caller version honoured)", v)
	}
}

func TestStamp_EmptyPayload(t *testing.T) {
	t.Parallel()
	out, changed, err := schema.Stamp(nil, schema.SchemaVersionV1)
	if err != nil {
		t.Fatalf("Stamp(nil) returned err: %v", err)
	}
	if !changed {
		t.Fatalf("changed should be true for nil payload")
	}
	if string(out) != `{"schema_version":"v1"}` {
		t.Fatalf("Stamp(nil) = %q", string(out))
	}
}

func TestStamp_NonJSONReturnsError(t *testing.T) {
	t.Parallel()
	in := []byte(`not json`)
	out, changed, err := schema.Stamp(in, schema.SchemaVersionV1)
	if err == nil {
		t.Fatalf("expected ErrPayloadNotJSONObject, got nil")
	}
	if changed {
		t.Fatalf("changed should be false on error")
	}
	if string(out) != string(in) {
		t.Fatalf("payload should round-trip unchanged on error")
	}
}

func TestStamp_PreservesNumericPrecision(t *testing.T) {
	t.Parallel()
	in := []byte(`{"big":12345678901234567,"small":1.23456789}`)
	out, changed, err := schema.Stamp(in, schema.SchemaVersionV1)
	if err != nil {
		t.Fatalf("Stamp returned err: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	// json.RawMessage round-tripping preserves the exact byte
	// representation of numbers, including int64 values that
	// would lose precision through a float64 conversion.
	if !strings.Contains(string(out), `"big":12345678901234567`) {
		t.Fatalf("big int lost precision: %s", string(out))
	}
	if !strings.Contains(string(out), `"small":1.23456789`) {
		t.Fatalf("small float reformatted: %s", string(out))
	}
}

func TestStamp_PreservesNestedStructures(t *testing.T) {
	t.Parallel()
	in := []byte(`{"nested":{"a":1,"b":[1,2,3]},"empty":{}}`)
	out, changed, err := schema.Stamp(in, schema.SchemaVersionV1)
	if err != nil {
		t.Fatalf("Stamp returned err: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if !strings.Contains(string(out), `"nested":{"a":1,"b":[1,2,3]}`) {
		t.Fatalf("nested struct mangled: %s", string(out))
	}
	if !strings.Contains(string(out), `"empty":{}`) {
		t.Fatalf("empty object dropped: %s", string(out))
	}
}

func TestStamp_RejectsEmptyVersion(t *testing.T) {
	t.Parallel()
	_, _, err := schema.Stamp([]byte(`{}`), "")
	if err == nil {
		t.Fatalf("Stamp with empty version should error")
	}
}
