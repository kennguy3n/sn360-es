package action

import "errors"

// Sentinel errors returned by services in this package so HTTP and
// bus handlers can map failures to deterministic response codes / DLQ
// classifications without inspecting error message strings. Always
// wrap these via fmt.Errorf("...: %w", err) so callers can recover
// them with errors.Is.
var (
	// ErrInvalidInput indicates the caller supplied a malformed or
	// incomplete request (missing required field, bad token claims,
	// etc.). HTTP callers should map this to 400; bus consumers
	// should treat it as terminal and not retry.
	ErrInvalidInput = errors.New("action: invalid input")

	// ErrNotFound indicates the referenced record does not exist in
	// the durable store. Typically maps to HTTP 404. Distinct from
	// ReleaseNotFound, which is a successful release outcome
	// (i.e. "the record is gone, nothing to release") rather than
	// an error.
	ErrNotFound = errors.New("action: not found")

	// ErrProviderUnavailable indicates the downstream provider
	// (Gmail, Microsoft Graph, Redis, Postgres, etc.) failed in a
	// way that may succeed on retry — transient API errors, network
	// hiccups, rate-limit responses, etc. HTTP callers should map
	// this to 503; bus consumers should NAK for re-delivery.
	ErrProviderUnavailable = errors.New("action: provider unavailable")
)
