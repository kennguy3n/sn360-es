// Package dto holds data-transfer objects shared between handlers,
// services, and the event bus. These types are deliberately simple
// (struct-with-primitives) so they can be serialised over JetStream
// payloads, HTTP, or PG columns without bespoke marshalling.
package dto

// RelationshipCategory describes the sender-recipient relationship as
// determined by the relationship aggregator. It feeds Tier 0 gating
// decisions and category selection.
type RelationshipCategory string

const (
	RelationshipUnknown           RelationshipCategory = ""
	RelationshipPartner           RelationshipCategory = "Partner"
	RelationshipCustomer          RelationshipCategory = "Customer"
	RelationshipFirstTimeExternal RelationshipCategory = "FirstTimeExternal"
	RelationshipLapsedContact     RelationshipCategory = "LapsedContact"
	RelationshipRecurringService  RelationshipCategory = "RecurringService"
)

// Valid reports whether r is one of the known relationship categories.
func (r RelationshipCategory) Valid() bool {
	switch r {
	case RelationshipUnknown,
		RelationshipPartner,
		RelationshipCustomer,
		RelationshipFirstTimeExternal,
		RelationshipLapsedContact,
		RelationshipRecurringService:
		return true
	}
	return false
}

// RiskSignals carries the structured signals computed in the prefilter
// stage. Each field is a hint — none alone determines the verdict, but
// taken together they feed both the Tier 0 gates and the scorer.
//
// Field semantics:
//
//   - IsInternal: sender is in the same tenant as the recipient (e.g. same
//     domain or known internal directory).
//   - IsExternal: convenience boolean = !IsInternal.
//   - IsFromVendor: sender is on the tenant's vendor allowlist.
//   - IsFreeDomain: sender uses a public webmail provider (gmail.com,
//     outlook.com, yahoo.com, ...).
//   - IsDisposableDomain: sender uses a temporary email service.
//   - RecipientIsFreeDomain: recipient uses a public webmail provider.
//   - RecipientIsDisposableDomain: recipient uses a temporary email service.
//   - IsHighVolumeSender: sender has been observed sending >N messages /
//     hour to this tenant.
//   - IsRecurringService: sender is `noreply@`, `mailer-daemon@`, etc.
//   - HasAttachment: message includes a non-inline attachment.
//   - HasSuspiciousURL: at least one URL flagged by Tier 0 heuristics.
//   - HasLookalikeDomain: sender domain is a near-miss of a known brand.
//   - HasFailedAuth: SPF, DKIM, or DMARC failed.
//   - HasQuotaSpike: sender's send rate exceeds historical baseline.
type RiskSignals struct {
	IsExternal                  bool `json:"is_external"`
	IsInternal                  bool `json:"is_internal"`
	IsFromVendor                bool `json:"is_from_vendor"`
	IsFreeDomain                bool `json:"is_free_domain"`
	IsDisposableDomain          bool `json:"is_disposable_domain"`
	RecipientIsFreeDomain       bool `json:"recipient_is_free_domain"`
	RecipientIsDisposableDomain bool `json:"recipient_is_disposable_domain"`
	IsHighVolumeSender          bool `json:"is_high_volume_sender"`
	IsRecurringService          bool `json:"is_recurring_service"`
	HasAttachment               bool `json:"has_attachment"`
	HasSuspiciousURL            bool `json:"has_suspicious_url"`
	HasSuspiciousAttachment     bool `json:"has_suspicious_attachment"`
	HasLookalikeDomain          bool `json:"has_lookalike_domain"`
	HasFailedAuth               bool `json:"has_failed_auth"`
	HasQuotaSpike               bool `json:"has_quota_spike"`

	// Set by Tier 0 / prefilter when specific content classes are detected.
	HasQRCode        bool `json:"has_qr_code,omitempty"`
	HasInvoiceHint   bool `json:"has_invoice_hint,omitempty"`
	HasCredentialLex bool `json:"has_credential_lex,omitempty"`

	// Higher-level behavioural verdicts surfaced by the relationship
	// aggregator. They feed the categoriser and the support agent.
	AuthFailed                bool `json:"auth_failed,omitempty"`
	LooksLikeAccountTakeover  bool `json:"looks_like_ato,omitempty"`
	LooksLikeVendorCompromise bool `json:"looks_like_vendor_compromise,omitempty"`

	RelationshipCategory RelationshipCategory `json:"relationship_category,omitempty"`

	// SPF / DKIM / DMARC raw verdicts ("pass", "fail", "softfail", "none",
	// "neutral"). Populated by Rspamd; consumed by the auth-chip renderer.
	SPFResult   string `json:"spf_result,omitempty"`
	DKIMResult  string `json:"dkim_result,omitempty"`
	DMARCResult string `json:"dmarc_result,omitempty"`

	// SenderDomain and RecipientDomain are pseudonymised in production logs
	// but kept in plaintext while the message is in-flight so detection
	// heuristics can match against them.
	SenderDomain    string `json:"sender_domain,omitempty"`
	RecipientDomain string `json:"recipient_domain,omitempty"`

	// Directory-context signals populated by normalizer when repos available.
	SenderSensitivity      string `json:"sender_sensitivity,omitempty"`
	RecipientSensitivity   string `json:"recipient_sensitivity,omitempty"`
	RecipientDepartment    string `json:"recipient_department,omitempty"`
	SenderKnownTitle       string `json:"sender_known_title,omitempty"`
	CommunicationFrequency int    `json:"communication_frequency,omitempty"`
	// TypicalSendHour is the modal hour-of-day (UTC, 0..23) the
	// signal builder copied from communication_histories.typical_hour.
	// A value outside [0, 24) is the "no baseline yet" sentinel that
	// matches repository.TypicalHourUnset (-1) and the migration-0007
	// column default. `omitempty` is deliberately omitted so the
	// distinction between "midnight UTC" (valid hour 0) and "field
	// not populated" (Go zero-value 0) is explicit on the wire —
	// otherwise an absent JSON field would deserialise to 0
	// (midnight) and the downstream ATO heuristic, despite its
	// `< 0 || >= 24` sentinel guard, would still be fed a hour the
	// producer never actually computed. Producers that lack a
	// baseline MUST emit -1 explicitly; producers that observed
	// midnight emit 0.
	TypicalSendHour int  `json:"typical_send_hour"`
	CurrentHourUTC  int  `json:"current_hour_utc,omitempty"`
	IsFirstContact  bool `json:"is_first_contact,omitempty"`
}

// AnyAuthFailed reports whether at least one of SPF/DKIM/DMARC failed.
func (r RiskSignals) AnyAuthFailed() bool {
	return r.HasFailedAuth ||
		r.SPFResult == "fail" ||
		r.DKIMResult == "fail" ||
		r.DMARCResult == "fail"
}

// AuthVerdict returns the consolidated authentication verdict used by the
// banner chip. Possible return values: "verified", "failed", "unverified".
//
// Rules:
//
//   - "verified" when DMARC == pass AND (SPF == pass OR DKIM == pass)
//   - "failed" when DMARC == fail OR HasFailedAuth is true
//   - "unverified" otherwise (no DMARC record, neutral, none, …)
func (r RiskSignals) AuthVerdict() string {
	if r.DMARCResult == "fail" || r.HasFailedAuth {
		return "failed"
	}
	if r.DMARCResult == "pass" && (r.SPFResult == "pass" || r.DKIMResult == "pass") {
		return "verified"
	}
	return "unverified"
}

// EvaluateBypass reports whether the signals dictate that ML evaluation
// should be skipped entirely (i.e. send the message through with the
// trusted disposition).
func (r RiskSignals) EvaluateBypass() bool {
	return r.IsInternal || r.IsFromVendor || r.IsRecurringService
}

// ForceEscalate reports whether the relationship category dictates that
// the message must reach Tier 2 (LLM) regardless of Tier 1 score.
//
// FirstTimeExternal is always escalated because the model has no prior
// communication context. LapsedContact is escalated because re-emerging
// senders after long silence are a classic account-takeover (ATO)
// vector (PROPOSAL.md §7).
func (r RiskSignals) ForceEscalate() bool {
	return r.RelationshipCategory == RelationshipFirstTimeExternal ||
		r.RelationshipCategory == RelationshipLapsedContact
}

// LowerTier1Threshold reports whether the relationship category should
// lower the Tier 1 PASS threshold (partner / customer relationships get
// a more permissive ML pass band).
func (r RiskSignals) LowerTier1Threshold() bool {
	return r.RelationshipCategory == RelationshipPartner ||
		r.RelationshipCategory == RelationshipCustomer
}
