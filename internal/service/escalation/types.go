// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

// Package escalation implements the WS-5A.6 consumer-side
// reconciliation pipeline: receive an IncidentResolved envelope
// from sn360-security-platform (services/soc-triage), look up
// the matching EvaluationResult, decide a verdict-flip +
// banner-reopen outcome, and persist one audit row per
// invocation.
//
// The wire shape mirrors the producer-side
// services/soc-triage/internal/events.IncidentResolved struct
// byte-for-byte (json tags, field order is not significant for
// JSON). Keeping the structs in lockstep is a load-bearing
// invariant — both repos test the round-trip independently;
// drift would silently break the cross-repo loop.
package escalation

import (
	"time"
)

// Resolution enumerates the four analyst dispositions the
// producer emits. The values are intentionally the wire strings
// — both sides serialise to / parse from these tokens directly.
const (
	ResolutionConfirmedThreat = "confirmed_threat"
	ResolutionFalsePositive   = "false_positive"
	ResolutionBenign          = "benign"
	ResolutionInconclusive    = "inconclusive"
)

// IsValidResolution reports whether r is one of the four
// declared resolutions. Used at the consumer's wire-parse
// boundary to drop off-spec payloads before they reach the
// reconciler.
func IsValidResolution(r string) bool {
	switch r {
	case ResolutionConfirmedThreat,
		ResolutionFalsePositive,
		ResolutionBenign,
		ResolutionInconclusive:
		return true
	}
	return false
}

// IncidentResolved is the consumer-side mirror of the
// producer's wire envelope. The JSON tags MUST match the
// producer's exactly; the package-isolation here is a
// boundary-isolation convenience, not an information-hiding
// barrier. Two test layers pin the contract: the streams_test
// covers subject routing, the resolver_test covers the field
// values.
type IncidentResolved struct {
	IncidentID   string     `json:"incident_id"`
	TenantID     string     `json:"tenant_id"`
	Resolution   string     `json:"resolution"`
	ResolvedAt   time.Time  `json:"resolved_at"`
	ResolvedBy   string     `json:"resolved_by"`
	AnalystNotes string     `json:"analyst_notes,omitempty"`
	RelatedEmail *EmailLink `json:"related_email,omitempty"`
	// DedupID is the producer-stamped
	// sha256(incident_id|resolved_at_unix_nano) under
	// length-prefixed framing. The consumer keys
	// (tenant_id, dedup_id) into email_verdict_audit to
	// defend against double-delivery beyond the broker's
	// 600s dedup window.
	DedupID string `json:"dedup_id"`
}

// EmailLink carries the pseudonymised identifiers the
// reconciler needs to find the matching EvaluationResult.
// Producer guarantees: at least one of PseudoMessageID /
// CorrelationID is populated when the incident has email
// evidence, otherwise the producer suppresses the field
// entirely (HasIdentifier() == false).
type EmailLink struct {
	PseudoMessageID string `json:"pseudo_message_id,omitempty"`
	SenderHash      string `json:"sender_hash,omitempty"`
	CorrelationID   string `json:"correlation_id,omitempty"`
}

// HasIdentifier reports whether the EmailLink carries enough
// information for the resolver to locate the matching
// EvaluationResult — at least one of pseudo_message_id /
// correlation_id must be non-empty. Senders without an
// identifier are intentionally not surfaced to the resolver:
// the SenderHash alone cannot uniquely identify the matching
// row, and the producer suppresses the field entirely when
// neither identifier is available (the link itself is the
// `omitempty` field on IncidentResolved).
func (e *EmailLink) HasIdentifier() bool {
	if e == nil {
		return false
	}
	return e.PseudoMessageID != "" || e.CorrelationID != ""
}

// OutcomeKind enumerates the audit-trail-visible
// reconciliation paths the resolver may take. Returned to the
// consumer so its DEBUG log can record what happened without
// re-deriving from the audit row.
type OutcomeKind string

const (
	// OutcomeFlipped — analyst disagreed with the platform's
	// automated verdict; final_verdict UPDATE landed. Banner
	// reopen MAY also have fired (see BannerReopened).
	OutcomeFlipped OutcomeKind = "flipped"
	// OutcomeNoop — analyst's resolution matched the
	// platform's automated verdict. Telemetry-only path:
	// audit row persists with new_verdict == "" so ops can
	// see the SOC analyst confirmed the call.
	OutcomeNoop OutcomeKind = "noop"
	// OutcomeSkipped — resolver could not reconcile (no
	// matching row, cross-tenant, inconclusive). Audit row
	// persists with a `reason` so the skip is observable.
	OutcomeSkipped OutcomeKind = "skipped"
	// OutcomeDuplicate — the (tenant_id, dedup_id) tuple was
	// already persisted on a prior invocation. The current
	// invocation is a no-op; no DB writes beyond the
	// INSERT-ON-CONFLICT that detected the dup.
	OutcomeDuplicate OutcomeKind = "duplicate"
)

// Outcome is the typed return of Reconcile. Exposes both the
// kind taxonomy (for DEBUG logs / metrics) and the underlying
// audit row that landed in the DB (so tests can assert against
// the persisted disposition without a separate fetch).
type Outcome struct {
	Kind OutcomeKind
	// AuditID is the email_verdict_audit.id of the row this
	// invocation produced (or the existing row on
	// OutcomeDuplicate). Empty only on pre-DB validation
	// failures (which surface as errors, not Outcomes).
	AuditID string
	// OriginalVerdict is the platform's automated verdict at
	// the time of reconciliation. Empty when no row was
	// found (Skipped).
	OriginalVerdict string
	// NewVerdict is the analyst-driven verdict the resolver
	// stamped. Empty on OutcomeNoop / OutcomeSkipped /
	// OutcomeDuplicate.
	NewVerdict string
	// BannerReopened is true when the resolver fired a
	// banner-reopen because banner_state.delivered_at IS NOT
	// NULL AND the analyst's resolution promoted the verdict
	// from non-malicious to malicious.
	BannerReopened bool
	// Reason is the free-text rationale persisted on the
	// audit row. Carries analyst notes on the happy path,
	// the skip rationale on the unhappy path.
	Reason string
}
