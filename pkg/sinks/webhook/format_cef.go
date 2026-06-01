package webhook

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// CEF (ArcSight Common Event Format) — version 0 — wire shape:
//
//   CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
//
// All seven header fields are mandatory and pipe-delimited. Pipes
// inside a header field must be backslash-escaped; backslashes
// double-escaped. Extensions are space-separated key=value pairs
// where the value (NOT the key) may contain quoted spaces, with
// `=` escaped as `\=` and `\` escaped as `\\`.
//
// Reference: https://docs.microsoft.com/en-us/azure/sentinel/connect-common-event-format
//            https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/cef-implementation/

// cefVendor / cefProduct / cefVersion are the vendor-shipped
// header fields. These MUST match what the customer's CEF
// connector is configured to accept (CEF receivers typically
// allow-list by Vendor + Product).
const (
	cefVendor    = "SN360"
	cefProduct   = "EmailSecurity"
	cefVersion   = "1.0"
	cefSigPrefix = "email-evaluation"
	cefHeaderSep = "|"
)

// formatCEF renders the Event in ArcSight CEF v0 shape.
func formatCEF(e *Event) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	verdict := e.Verdict()

	// SignatureID is the action.verdict pair — gives the
	// downstream CEF receiver a stable, machine-readable signal
	// to bucket on. Name is the human-readable variant.
	signature := cefSigPrefix + "." + verdict
	name := "sn360-es email " + verdict
	if e.Test {
		name = "sn360-es email " + verdict + " (synthetic test)"
	}
	severity := cefSeverityForTier(e.Tier)

	header := strings.Join([]string{
		"CEF:0",
		cefEscapeHeader(cefVendor),
		cefEscapeHeader(cefProduct),
		cefEscapeHeader(cefVersion),
		cefEscapeHeader(signature),
		cefEscapeHeader(name),
		fmt.Sprintf("%d", severity),
	}, cefHeaderSep)

	// Extensions: canonical CEF/ArcSight keys where they exist
	// (msg, externalId, suid, src, duser, deviceCustomString*),
	// and `cs1Label=...` style label/value pairs for custom
	// fields with no canonical CEF mapping (tier, reason codes,
	// degraded services).
	exts := []cefExt{
		{"externalId", e.EventID},
		{"msg", oneLineMessage(e, verdict)},
		{"rt", fmt.Sprintf("%d", e.OccurredAt.UTC().UnixMilli())},
		{"deviceFacility", "sn360-es"},
		{"act", cefSigPrefix},
		{"outcome", verdict},
		{"cn1Label", "score"},
		{"cn1", fmt.Sprintf("%d", e.Score)},
		{"cs1Label", "tier"},
		{"cs1", string(e.Tier)},
		{"cs2Label", "primary_category"},
		{"cs2", string(e.Primary)},
		{"cs3Label", "tenant_id"},
		{"cs3", e.TenantID},
		{"cs4Label", "correlation_id"},
		{"cs4", e.CorrelationID},
		{"cs5Label", "reason_codes"},
		{"cs5", strings.Join(e.ReasonCodes, ",")},
	}
	if len(e.Secondary) > 0 {
		sec := make([]string, 0, len(e.Secondary))
		for _, c := range e.Secondary {
			sec = append(sec, string(c))
		}
		exts = append(exts,
			cefExt{"cs6Label", "secondary_categories"},
			cefExt{"cs6", strings.Join(sec, ",")},
		)
	}
	if e.SenderHashHex != "" {
		exts = append(exts, cefExt{"suid", e.SenderHashHex})
	}
	if e.RecipientHashHex != "" {
		exts = append(exts, cefExt{"duid", e.RecipientHashHex})
	}
	if e.FinalVerdict != "" {
		exts = append(exts,
			cefExt{"cfp1Label", "final_verdict_present"},
			cefExt{"cfp1", "1"},
			cefExt{"cs7Label", "final_verdict"},
			cefExt{"cs7", strings.ToLower(strings.TrimSpace(e.FinalVerdict))},
		)
	}
	if e.Degraded {
		exts = append(exts,
			cefExt{"flexString1Label", "degraded"},
			cefExt{"flexString1", "1"},
		)
		if len(e.DegradedServices) > 0 {
			exts = append(exts,
				cefExt{"flexString2Label", "degraded_services"},
				cefExt{"flexString2", strings.Join(e.DegradedServices, ",")},
			)
		}
	}
	if e.Test {
		exts = append(exts,
			cefExt{"flexNumber1Label", "synthetic_test"},
			cefExt{"flexNumber1", "1"},
		)
	}

	// Stable key order. Some CEF consumers care; others don't.
	// Sorting makes golden-file tests trivial.
	sort.Slice(exts, func(i, j int) bool { return exts[i].Key < exts[j].Key })

	var buf bytes.Buffer
	buf.WriteString(header)
	for _, kv := range exts {
		if kv.Value == "" {
			continue
		}
		buf.WriteString(" ")
		buf.WriteString(kv.Key)
		buf.WriteString("=")
		buf.WriteString(cefEscapeExtension(kv.Value))
	}
	return buf.Bytes(), nil
}

type cefExt struct {
	Key, Value string
}

// cefSeverityForTier projects a Tier onto the CEF severity range
// (0-10). 10 = highest. Spec is loose; we follow the ArcSight
// recommended bucketing for "critical" / "high" / "medium" / "low".
func cefSeverityForTier(t constant.Tier) int {
	switch t {
	case constant.TierBlocked:
		return 10
	case constant.TierHighRisk:
		return 8
	case constant.TierWarning:
		return 6
	case constant.TierCaution:
		return 4
	case constant.TierInformational:
		return 2
	case constant.TierTrusted:
		return 1
	default:
		return 0
	}
}

// cefEscapeHeader escapes a header field per the CEF spec:
//
//	`\` → `\\`
//	`|` → `\|`
//	`\n` / `\r` are not allowed in headers; replaced with space.
func cefEscapeHeader(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '|':
			b.WriteString(`\|`)
		case '\n', '\r':
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cefEscapeExtension escapes an extension VALUE per the CEF spec:
//
//	`\` → `\\`
//	`=` → `\=`
//	`\n` → `\n` (literal two-char escape)
//	`\r` → `\r` (literal two-char escape)
//
// Pipes are NOT escaped in extension values per the spec — extension
// parsing is key-aware, not pipe-aware.
func cefEscapeExtension(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '=':
			b.WriteString(`\=`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// oneLineMessage renders the short summary used as the CEF `msg=`
// extension. Same shape as the ECS `message` field for cross-
// format consistency.
func oneLineMessage(e *Event, verdict string) string {
	prefix := "sn360-es:"
	if e.Test {
		prefix = "sn360-es-test:"
	}
	return fmt.Sprintf("%s verdict=%s tier=%s score=%d tenant=%s msg=%s",
		prefix, verdict, e.Tier, e.Score, e.TenantID, e.MessageID)
}
