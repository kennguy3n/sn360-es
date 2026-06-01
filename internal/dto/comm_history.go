package dto

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"time"
)

// CommHistoryUpdateSubject is the canonical NATS subject for
// incremental `communication_histories` sightings produced by the
// signal-enricher hot path (WS-4a).
//
// Wire shape: a CommHistoryUpdate JSON document published with the
// dedup ID (see CommHistoryUpdate.DedupID) bound to the
// per-(tenant, sender, recipient, message_id) tuple. The subject
// lives under the `es.management.*` namespace because the event
// writes directly into the management Postgres layer; downstream
// consumers of relationship state read from Postgres, not from this
// stream.
const CommHistoryUpdateSubject = "es.management.comm_history.update"

// CommHistoryUpdate is the per-message sighting that the
// signal-enricher post-Enrich publish path records onto the
// es.management.comm_history.update subject. The consumer applies it
// to the `communication_histories` row for (TenantID, SenderHash,
// RecipientHash) via the repository's RecordSighting method, which
// atomically increments the rolling counters and bumps last_seen_at.
//
// Wire contract:
//
//   - All fields except SenderDomain are mandatory. SenderDomain is
//     populated when the bridge surfaced a parseable sender domain
//     (the normal path) and left empty when the bridge couldn't
//     extract one (e.g. malformed `From:` header on a Tier-0 spam
//     reject). The consumer treats empty SenderDomain as "do not
//     overwrite the persisted domain string" rather than as "blank
//     it out".
//
//   - SentAt is the message's externally-observed receive time, NOT
//     the publish time of this event. Idempotency depends on it
//     being deterministic per (tenant, message-id), so reading-then-
//     re-publishing the same envelope must produce the same SentAt.
//
//   - MessageID is the bridge-surfaced PseudoMessageID (the Blake2b
//     hash of the underlying envelope's Message-ID header). It is
//     used ONLY as part of the JetStream dedup key; the consumer
//     does NOT persist it. Keeping it on the wire means a redelivery
//     of the same evaluate.request through the JetStream redelivery
//     window collapses into a single sighting at the broker rather
//     than a double-count at the consumer.
//
// The DedupID() helper derives the Nats-Msg-Id header value so
// publishers and tests share one definition.
type CommHistoryUpdate struct {
	// SchemaVersion is the WS-7c wire-format version tag. Producers
	// SHOULD set SchemaVersion=SchemaVersionV1 on construction;
	// the publish-side validator stamps the same value as a
	// backstop. Consumers that receive a payload without this
	// field treat it as v1 (pre-WS-7c publishers remain
	// compatible).
	SchemaVersion    string    `json:"schema_version,omitempty"`
	TenantID         string    `json:"tenant_id"`
	MessageID        string    `json:"message_id"`
	SenderHash       []byte    `json:"sender_hash"`
	RecipientHash    []byte    `json:"recipient_hash"`
	SenderDomainHash []byte    `json:"sender_domain_hash,omitempty"`
	SenderDomain     string    `json:"sender_domain,omitempty"`
	SentAt           time.Time `json:"sent_at"`
}

// ErrCommHistoryUpdateIncomplete is returned by Validate when any
// required field is missing. The consumer treats this as a
// terminal-bad-message error (NAK without retry) because no amount
// of retry will populate the fields.
var ErrCommHistoryUpdateIncomplete = errors.New("dto: CommHistoryUpdate is incomplete (tenant_id, sender_hash, recipient_hash, message_id, sent_at all required)")

// Validate reports whether the event has the minimum fields the
// consumer needs to drive RecordSighting. The consumer MUST call
// Validate before dispatching to the repository.
func (u CommHistoryUpdate) Validate() error {
	if u.TenantID == "" {
		return ErrCommHistoryUpdateIncomplete
	}
	if len(u.SenderHash) == 0 || len(u.RecipientHash) == 0 {
		return ErrCommHistoryUpdateIncomplete
	}
	if u.MessageID == "" {
		return ErrCommHistoryUpdateIncomplete
	}
	if u.SentAt.IsZero() {
		return ErrCommHistoryUpdateIncomplete
	}
	return nil
}

// DedupID returns the deterministic JetStream message-id for this
// sighting. The id is bound to the tuple
// (tenant, sender_hash, recipient_hash, message_id), so any redelivery
// of the same envelope within the stream's dedup window collapses to
// a single sighting at the broker.
//
// Including SentAt in the hash would defeat at-least-once semantics
// because a clock skew at the publisher between two retries would
// otherwise generate distinct dedup ids for the same logical sighting.
// MessageID is the natural per-sighting unique key and is the only
// field the consumer needs to dedupe on. The SHA-256-base64url form
// is short enough to fit comfortably in the Nats-Msg-Id header.
func (u CommHistoryUpdate) DedupID() string {
	h := sha256.New()
	// Length-prefix every field so adjacent fields cannot collide
	// (e.g. sender_hash = "ab" + recipient_hash = "cd" vs
	// sender_hash = "abc" + recipient_hash = "d" — both produce
	// the same flat byte stream without length prefixes).
	writeLenPrefixed(h, []byte(u.TenantID))
	writeLenPrefixed(h, u.SenderHash)
	writeLenPrefixed(h, u.RecipientHash)
	writeLenPrefixed(h, []byte(u.MessageID))
	sum := h.Sum(nil)
	return "ch:" + base64.RawURLEncoding.EncodeToString(sum)
}

func writeLenPrefixed(h hashWriter, b []byte) {
	var lenBuf [12]byte
	n := strconv.AppendInt(lenBuf[:0], int64(len(b)), 10)
	_, _ = h.Write(n)
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write(b)
	_, _ = h.Write([]byte{','})
}

// hashWriter is the minimal subset of hash.Hash this file needs.
// Keeping it local avoids dragging hash.Hash through the dto package
// signatures.
type hashWriter interface {
	Write(p []byte) (int, error)
}
