package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// ecsDocVersion is the ECS major.minor that the sn360-es webhook
// sink targets. Pinned at 8.11 because that's the version the
// `email.*` field set we depend on (Elastic added email.from.address
// in 8.6; the `attempt_count` field in our extension is not in ECS).
//
// Reference: https://www.elastic.co/guide/en/ecs/8.11/ecs-email.html
const ecsDocVersion = "8.11.0"

// ecsCategory / ecsType / ecsKind are the closed-set ECS field
// values for the `email.evaluation` event. They are pinned constants
// so a code change can't accidentally drift them off the schema.
const (
	ecsKindAlert      = "alert"
	ecsCategoryEmail  = "email"
	ecsTypeInfo       = "info"
	ecsTypeDenied     = "denied"
	ecsActionDelivery = "email-evaluation"
	ecsModule         = "sn360-es"
	ecsProvider       = "sn360"
)

// formatECS renders the Event in Elastic Common Schema 8.11 shape.
// Output is a single JSON object — the standard newline-delimited
// JSON shape used by Splunk HEC's "/services/collector/event" and
// Elastic webhook input.
//
// The schema is deliberately conservative: every field the formatter
// emits lives under a documented ECS namespace (`@timestamp`,
// `event.*`, `email.*`, `labels.*`, `tags`, `observer.*`,
// `organization.id`, `message`). Custom fields go under the
// vendor-namespaced `sn360.*` key so downstream Elastic ingest
// pipelines can identify them as non-ECS additions.
func formatECS(e *Event) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	verdict := e.Verdict()

	doc := map[string]any{}
	doc["@timestamp"] = e.OccurredAt.UTC().Format("2006-01-02T15:04:05.000Z")
	doc["ecs"] = map[string]any{"version": ecsDocVersion}
	doc["organization"] = map[string]any{"id": e.TenantID}

	event := map[string]any{
		"kind":       ecsKindAlert,
		"category":   []string{ecsCategoryEmail},
		"type":       []string{ecsTypeForVerdict(verdict)},
		"action":     ecsActionDelivery,
		"id":         nonEmpty(e.EventID, e.MessageID),
		"module":     ecsModule,
		"provider":   ecsProvider,
		"dataset":    "sn360.email.evaluation",
		"severity":   severityForTier(e.Tier),
		"risk_score": e.Score,
	}
	if e.CorrelationID != "" {
		event["sequence"] = e.CorrelationID
	}
	if e.Test {
		event["reason"] = "synthetic test event"
	}
	doc["event"] = event

	email := map[string]any{
		// ECS treats `email.message_id` as the RFC 5322 Message-ID.
		// We carry the pseudonymised stamp instead — see the doc
		// note above; the sn360.* sub-namespace below records that
		// this is a pseudo, not a plaintext Message-ID.
		"message_id": e.MessageID,
		"direction":  "inbound",
	}
	if e.SenderHashHex != "" {
		email["from"] = map[string]any{"address": []string{senderPlaceholder(e.SenderHashHex)}}
	}
	if e.RecipientHashHex != "" {
		email["to"] = map[string]any{"address": []string{recipientPlaceholder(e.RecipientHashHex)}}
	}
	doc["email"] = email

	// Tags carry the ECS-compatible quick-filter strings. We
	// emit one tag for the disposition (verdict) and one per
	// reason code so SIEM dashboards can `tags: phishing` etc.
	tags := []string{verdict, "sn360-es", "tier:" + string(e.Tier)}
	if e.Test {
		tags = append(tags, "synthetic-test")
	}
	if e.Degraded {
		tags = append(tags, "degraded")
	}
	for _, rc := range e.ReasonCodes {
		if rc != "" {
			tags = append(tags, "reason:"+rc)
		}
	}
	sort.Strings(tags)
	doc["tags"] = tags

	// Per-tier vendor namespace. We do NOT collapse this into
	// `labels.*` because ECS recommends labels for
	// "user-defined key/value pairs" — vendor-shipped structured
	// data belongs in a vendor sub-namespace per the ECS
	// custom-field guidance.
	sn360 := map[string]any{
		"verdict":        verdict,
		"tier":           string(e.Tier),
		"score":          e.Score,
		"correlation_id": e.CorrelationID,
		"primary":        string(e.Primary),
	}
	if len(e.Secondary) > 0 {
		secondary := make([]string, 0, len(e.Secondary))
		for _, c := range e.Secondary {
			secondary = append(secondary, string(c))
		}
		sn360["secondary"] = secondary
	}
	if len(e.ReasonCodes) > 0 {
		sn360["reason_codes"] = append([]string(nil), e.ReasonCodes...)
	}
	if e.Degraded {
		sn360["degraded"] = true
		if len(e.DegradedServices) > 0 {
			sn360["degraded_services"] = append([]string(nil), e.DegradedServices...)
		}
	}
	if e.FinalVerdict != "" {
		sn360["final_verdict"] = strings.ToLower(strings.TrimSpace(e.FinalVerdict))
	}
	if e.SenderHashHex != "" {
		sn360["sender_hash"] = e.SenderHashHex
	}
	if e.RecipientHashHex != "" {
		sn360["recipient_hash"] = e.RecipientHashHex
	}
	if e.Test {
		sn360["synthetic_test"] = true
	}
	doc["sn360"] = sn360

	doc["message"] = humanMessage(e, verdict)

	// Use a stable-key encoder so golden-file tests are
	// deterministic. encoding/json doesn't sort by default, but
	// it does emit map keys in lexical order.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("ecs: encode: %w", err)
	}
	// json.Encoder.Encode appends a trailing newline. Trim it so
	// the body length is predictable for HMAC tests.
	out := bytes.TrimRight(buf.Bytes(), "\n")
	return out, nil
}

// ecsTypeForVerdict maps the canonical verdict label to the ECS
// `event.type` value. ECS allows the closed set { creation,
// deletion, info, error, access, change, denied, ... }; for
// email-evaluation we use `denied` for malicious (the verdict
// would have been quarantined / blocked downstream) and `info`
// otherwise.
func ecsTypeForVerdict(v string) string {
	switch v {
	case "malicious":
		return ecsTypeDenied
	default:
		return ecsTypeInfo
	}
}

// severityForTier projects a Tier severity onto the ECS recommended
// 1..7 numeric range, where 7 = critical and 1 = informational.
func severityForTier(t constant.Tier) int {
	switch t {
	case constant.TierBlocked:
		return 7
	case constant.TierHighRisk:
		return 6
	case constant.TierWarning:
		return 4
	case constant.TierCaution:
		return 3
	case constant.TierInformational:
		return 2
	case constant.TierTrusted:
		return 1
	default:
		return 0
	}
}

// senderPlaceholder formats the BLAKE2b sender hash as the local
// part of a synthetic mailbox at the sn360 vendor domain. ECS
// requires `email.from.address` to be RFC-822-ish; we don't have a
// real sender address (pseudonymised), so we emit the hash inside a
// reserved `pseudo.sn360` namespace so downstream pipelines can
// detect that it's a pseudo-identifier rather than a leaked real
// address.
func senderPlaceholder(hashHex string) string {
	return hashHex + "@pseudo.sn360"
}

func recipientPlaceholder(hashHex string) string {
	return hashHex + "@pseudo.sn360"
}

// humanMessage is the one-line description for the ECS `message`
// field. SIEM analysts skim this column; it should answer "what
// happened, to which message, in which tenant" in one glance.
// Treat as advisory — no machinable consumer reads it.
func humanMessage(e *Event, verdict string) string {
	prefix := "sn360-es:"
	if e.Test {
		prefix = "sn360-es-test:"
	}
	return fmt.Sprintf("%s verdict=%s tier=%s score=%d tenant=%s msg=%s",
		prefix, verdict, e.Tier, e.Score, e.TenantID, e.MessageID)
}

// nonEmpty returns first if non-empty, else second. Avoids the
// pattern of `if x != "" { ... } else { ... }` at every ECS-field
// site that wants to fall back to the message id when an explicit
// event id wasn't stamped.
func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
