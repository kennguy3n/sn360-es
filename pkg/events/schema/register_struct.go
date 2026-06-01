package schema

import (
	"encoding/json"
)

// RegisterStruct binds a strongly-typed Go struct to
// (subject, version). The validator decodes the payload into a
// fresh T and, if `extra` is non-nil, runs the optional semantic
// check the producer wants enforced (e.g. "tenant_id must be
// non-empty"). Returning a non-nil error from extra surfaces as
// Reason=payload_validation_failure on the publish/subscribe
// side.
//
// Two registration shapes are available because the bridge
// envelope and the email-bridge family of subjects (e.g.
// `sn360.events.email.<tenant>.<kind>`) share one shape across
// many concrete subjects, while the canonical
// `es.evaluate.request` / `es.evaluate.result` subjects bind
// exactly. The generic helper avoids forcing callers to wire
// the json.Unmarshal + nil-check + extra() boilerplate by hand
// at every registration site (eight subjects on sn360-es alone
// pre-WS-7c).
//
// RegisterStruct is the EXACT-subject sibling; RegisterStructPrefix
// is the wildcard sibling that binds (subject_prefix, version).
func RegisterStruct[T any](v *Validator, subject, version string, extra func(*T) error) {
	if v == nil {
		return
	}
	fn := makeStructValidator[T](subject, version, extra)
	v.Register(subject, version, fn)
}

// RegisterStructPrefix is the prefix-matching variant of
// RegisterStruct. The supplied prefix matches any subject equal
// to it or starting with `prefix + "."` — sufficient for the
// hybrid-envelope family (`sn360.events.email`) that uses
// per-tenant + per-kind sub-subjects.
func RegisterStructPrefix[T any](v *Validator, prefix, version string, extra func(*T) error) {
	if v == nil {
		return
	}
	fn := makeStructValidator[T](prefix, version, extra)
	v.RegisterPrefix(prefix, version, fn)
}

// makeStructValidator is the shared closure factory used by
// RegisterStruct / RegisterStructPrefix. Extracted so the two
// variants share a single decode + extra-check implementation
// and cannot drift on a future bug fix (e.g. the json.Decoder
// strict-mode rollout in v2).
func makeStructValidator[T any](subjectOrPrefix, version string, extra func(*T) error) validatorFn {
	return func(data []byte) error {
		var v T
		if err := json.Unmarshal(data, &v); err != nil {
			return formatJSONError(subjectOrPrefix, version, err)
		}
		if extra != nil {
			if err := extra(&v); err != nil {
				return err
			}
		}
		return nil
	}
}
