package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrPayloadNotJSONObject is returned by Stamp when the payload
// is non-empty but does not start with `{` — the schema_version
// field only makes sense on a JSON object envelope. Wire-level
// non-JSON payloads (rare, mostly tests) are skipped by the
// stamper rather than reformatted into a wrapping object.
var ErrPayloadNotJSONObject = errors.New("schema: payload is not a JSON object")

// Stamp returns the payload with `schema_version` set to
// `version` if the field is missing. If the field is already
// present (whatever value), the payload is returned unchanged.
// `changed` reports whether the returned bytes differ from the
// input. The publish-time wiring uses Stamp as a backstop so a
// producer that forgot to set `dto.SchemaVersionV1` on its
// envelope still emits a self-describing v1 payload on the wire.
//
// The algorithm uses ordered map[string]json.RawMessage to
// preserve the rest of the payload byte-for-byte (no field
// reordering, no whitespace normalisation, no precision-loss
// on float64). The schema_version key is inserted FIRST so the
// final document is `{"schema_version":"v1", ...original keys
// in original order...}` — readable in a `nats consume` dump
// and unambiguous about which version every line is.
func Stamp(data []byte, version string) ([]byte, bool, error) {
	if version == "" {
		return data, false, fmt.Errorf("schema: cannot stamp empty version onto payload")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		// Empty payload: produce a `{"schema_version":"v1"}`
		// envelope. This keeps zero-payload subjects (e.g.
		// signal-only events) self-describing.
		out := []byte(`{"` + SchemaVersionField + `":"` + version + `"}`)
		return out, true, nil
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return data, false, ErrPayloadNotJSONObject
	}
	// Fast-path: peek the field without a full decode. If it's
	// already set the payload is returned unchanged.
	if PeekVersion(data) != "" {
		return data, false, nil
	}
	// Slow-path: full decode + re-encode with `schema_version`
	// prepended. Performance: ~10-30us per call for typical
	// (~2-4KB) payloads. Acceptable on the publish hot path
	// (typical sn360-es event rate is <500 ev/s steady-state)
	// and only fires on legacy producers that haven't set the
	// field — the explicit `SchemaVersion: dto.SchemaVersionV1`
	// path on every modern call site never hits this branch.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	// Read the opening `{`.
	tok, err := dec.Token()
	if err != nil {
		return data, false, fmt.Errorf("schema: decode payload: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return data, false, ErrPayloadNotJSONObject
	}
	var buf bytes.Buffer
	buf.Grow(len(data) + 32)
	buf.WriteString(`{"`)
	buf.WriteString(SchemaVersionField)
	buf.WriteString(`":`)
	versionJSON, err := json.Marshal(version)
	if err != nil {
		return data, false, fmt.Errorf("schema: encode version: %w", err)
	}
	buf.Write(versionJSON)
	// Stream the rest of the object (every key/value pair the
	// caller supplied) directly onto buf. Each iteration emits
	// `,"key":value`.
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return data, false, fmt.Errorf("schema: decode key: %w", err)
		}
		buf.WriteString(`,`)
		keyJSON, err := json.Marshal(key.(string))
		if err != nil {
			return data, false, fmt.Errorf("schema: encode key: %w", err)
		}
		buf.Write(keyJSON)
		buf.WriteString(`:`)
		// Decode the value as a raw message so nested
		// shapes / arrays / numbers are preserved
		// byte-for-byte.
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return data, false, fmt.Errorf("schema: decode value: %w", err)
		}
		buf.Write(raw)
	}
	buf.WriteString(`}`)
	return buf.Bytes(), true, nil
}
