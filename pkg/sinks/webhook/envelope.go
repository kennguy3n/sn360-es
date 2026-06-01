package webhook

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// DLQEnvelope is the JSON shape published to
// `sn360.dlq.webhook.<tenant>.<sink>` when a publish fails with a
// retriable outcome. The DLQ consumer
// (cmd/sn360-es/consumers_webhook_dlq.go) deserialises this, looks
// up the sink to re-derive the HMAC key, and retries the POST.
//
// Wire contract: Body is replayed VERBATIM in its captured Format
// for every retry. The DLQ consumer never re-encodes the body, so
// a sink-format flip on the live row between attempts does NOT
// change the in-flight envelope — that retry stream rides out its
// captured format until MaxDeliver. Only the HMAC signature may
// change between attempts (when the operator rotates hmac_secret);
// the consumer re-signs the original Body bytes with the current
// per-sink key and Content-Type on the wire continues to track
// envelope.Format. See resignDLQEnvelope for rationale.
type DLQEnvelope struct {
	SchemaVersion int                          `json:"schema_version"`
	SinkID        string                       `json:"sink_id"`
	TenantID      string                       `json:"tenant_id"`
	SinkName      string                       `json:"sink_name"`
	URL           string                       `json:"url"`
	Format        repository.WebhookSinkFormat `json:"format"`
	EventType     string                       `json:"event_type"`
	EventID       string                       `json:"event_id"`
	OccurredAt    time.Time                    `json:"occurred_at"`
	Body          []byte                       `json:"body"`
	Signature     string                       `json:"signature"`
	Attempt       int                          `json:"attempt"`
	FirstFailedAt time.Time                    `json:"first_failed_at"`
	LastCause     string                       `json:"last_cause"`
	LastStatus    int                          `json:"last_status,omitempty"`
}

// DLQEnvelopeSchemaVersion pins the wire shape so a future shape
// change ships behind a `schema_version` bump and the consumer can
// reject envelopes it doesn't understand instead of silently
// mishandling them.
const DLQEnvelopeSchemaVersion = 1

// Marshal returns the canonical JSON for the envelope. Pinned
// here (instead of being inlined at the publish site) so the DLQ
// consumer and the publish path stay byte-for-byte aligned.
func (e *DLQEnvelope) Marshal() ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("webhook: nil envelope")
	}
	if e.SchemaVersion == 0 {
		e.SchemaVersion = DLQEnvelopeSchemaVersion
	}
	return json.Marshal(e)
}

// ParseDLQEnvelope is the inverse of Marshal. It validates the
// schema_version up front so a future shape change can refuse old
// envelopes cleanly.
func ParseDLQEnvelope(data []byte) (*DLQEnvelope, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("webhook: empty dlq envelope")
	}
	env := &DLQEnvelope{}
	if err := json.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("webhook: decode dlq envelope: %w", err)
	}
	if env.SchemaVersion == 0 || env.SchemaVersion > DLQEnvelopeSchemaVersion {
		return nil, fmt.Errorf("webhook: unsupported dlq envelope schema_version %d", env.SchemaVersion)
	}
	if env.SinkID == "" || env.TenantID == "" {
		return nil, fmt.Errorf("webhook: dlq envelope missing sink/tenant id")
	}
	return env, nil
}
