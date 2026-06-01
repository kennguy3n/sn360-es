// Package webhook provides the standalone-deployment SIEM export
// pipeline (WS-5B.2). It serialises sn360-es email verdicts into
// industry-standard SIEM-ingestion formats (ECS for Elastic / Splunk
// / Sentinel, CEF for ArcSight / NetWitness / legacy collectors),
// HMAC-SHA256-signs the body with a per-tenant secret, and POSTs
// the result to a customer-configured HTTPS endpoint.
//
// The fan-out is best-effort: a sink that 5xx's, times out, or
// network-errors gets requeued onto a NATS DLQ subject for the
// durable retry consumer in cmd/sn360-es/consumers_webhook_dlq.go;
// a 4xx is recorded as a permanent failure (audit + metric) and
// dropped. Sink failures do NOT fail the originating evaluation.
//
// The sn360-security-platform SOC continues to receive verdicts via
// the WS-5A.1 NATS bridge; this package supplies the equivalent
// egress path for customers running sn360-es WITHOUT the SOC
// (standalone mode).
package webhook

import (
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Event is the wire-format-agnostic snapshot of a single email
// evaluation verdict.
//
// The fields are intentionally pseudonymised: PseudoMessageID is the
// privacy.PseudoMessageID stamp produced by the producer (hex-encoded
// length-prefixed sha256 — NEVER the provider's plaintext message
// id), SenderHash / RecipientHash are HashPII(tenantID, lower(trim))
// of the addresses (never plaintext). The webhook sink writes
// exactly the same shape sn360-security-platform sees on the
// WS-5A.1 NATS bridge; downstream SIEM analysts can correlate
// across the two transports by the (TenantID, PseudoMessageID)
// pair.
//
// CorrelationID is an opaque trace identifier propagated end-to-end
// through the evaluation pipeline (privacy.IDStore mints it). It is
// safe to log and safe to surface to the customer.
type Event struct {
	// EventID is a sink-publish unique identifier. Distinct from
	// MessageID because a single email can be republished to the
	// same sink on retry; the sink-side dedup key for the DLQ
	// consumer is sha256(EventID|sink_id|attempt).
	EventID       string
	OccurredAt    time.Time
	TenantID      string
	MessageID     string
	CorrelationID string

	Score            int
	Tier             constant.Tier
	Primary          constant.Category
	Secondary        []constant.Category
	ReasonCodes      []string
	Degraded         bool
	DegradedServices []string
	FinalVerdict     string // analyst override; empty when not set
	SenderHashHex    string
	RecipientHashHex string

	// Test indicates that this is a synthetic event produced by
	// the POST /webhook-sinks/{id}/test handler. ECS / CEF
	// formatters surface this so SIEM operators can spot it.
	Test bool
}

// EventFromEvaluateResult projects an EvaluateResult into the
// wire-format-agnostic Event the formatters consume. Callers stamp
// EventID + OccurredAt themselves so test fixtures and dispatch
// retries can hold them stable.
func EventFromEvaluateResult(res *dto.EvaluateResult) *Event {
	if res == nil {
		return nil
	}
	ev := &Event{
		TenantID:         res.TenantID,
		MessageID:        res.MessageID,
		CorrelationID:    res.CorrelationID,
		OccurredAt:       res.EvaluatedAt,
		Score:            res.Score,
		Tier:             res.Tier,
		Primary:          res.Primary,
		Secondary:        append([]constant.Category(nil), res.Secondary...),
		ReasonCodes:      append([]string(nil), res.ReasonCodes...),
		Degraded:         res.Degraded,
		DegradedServices: append([]string(nil), res.DegradedServices...),
		SenderHashHex:    hex.EncodeToString(res.SenderHash),
		RecipientHashHex: hex.EncodeToString(res.RecipientHash),
	}
	return ev
}

// Validate reports whether the event has enough material to format.
// The dispatcher calls this before signing so a malformed envelope
// can't be POSTed to the customer endpoint.
func (e *Event) Validate() error {
	if e == nil {
		return errors.New("webhook: nil event")
	}
	if strings.TrimSpace(e.TenantID) == "" {
		return errors.New("webhook: event missing tenant_id")
	}
	if strings.TrimSpace(e.MessageID) == "" {
		return errors.New("webhook: event missing message_id")
	}
	if !e.Tier.Valid() {
		return errors.New("webhook: event tier invalid")
	}
	return nil
}

// Verdict maps the (Tier, FinalVerdict) pair to the canonical
// disposition surfaced to SIEM consumers. The analyst override wins:
// SOCs build dashboards on "what did the analyst conclude", not on
// "what did the automation pick" — see ARCHITECTURE.md §8.4.
func (e *Event) Verdict() string {
	if e == nil {
		return ""
	}
	if v := strings.ToLower(strings.TrimSpace(e.FinalVerdict)); v != "" {
		return v
	}
	switch e.Tier {
	case constant.TierBlocked:
		return "malicious"
	case constant.TierHighRisk:
		return "malicious"
	case constant.TierWarning:
		return "suspicious"
	case constant.TierCaution:
		return "suspicious"
	case constant.TierInformational:
		return "benign"
	case constant.TierTrusted:
		return "benign"
	default:
		return "unknown"
	}
}
