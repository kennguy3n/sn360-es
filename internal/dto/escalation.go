package dto

import "time"

// EscalationReason describes why the SecOps agent was paged.
type EscalationReason string

const (
	EscalationReasonConfirmedBreach   EscalationReason = "confirmed_breach"
	EscalationReasonAccountCompromise EscalationReason = "account_compromise"
	EscalationReasonZeroDayAttachment EscalationReason = "zero_day_attachment"
	EscalationReasonLowConfidence     EscalationReason = "ai_low_confidence"
	EscalationReasonUserRequested     EscalationReason = "user_requested"
	// EscalationReasonOpsAlert is used by the autonomous-ops alert
	// router when an Alertmanager webhook reaches the
	// ActionEscalate branch (i.e. an infrastructure incident with
	// no automated remediation). Keeping infra incidents under their
	// own reason keeps downstream consumers — the FeedbackSink
	// training pipeline + SOC dashboards filtering by reason —
	// from conflating infrastructure incidents with genuine
	// AI-confidence escalations on the email pipeline.
	EscalationReasonOpsAlert EscalationReason = "ops_alert"
)

// Valid reports whether r is a known escalation reason.
func (r EscalationReason) Valid() bool {
	switch r {
	case EscalationReasonConfirmedBreach,
		EscalationReasonAccountCompromise,
		EscalationReasonZeroDayAttachment,
		EscalationReasonLowConfidence,
		EscalationReasonUserRequested,
		EscalationReasonOpsAlert:
		return true
	}
	return false
}

// EscalationOutcome is the SecOps response recorded against a ticket.
type EscalationOutcome string

const (
	OutcomePending           EscalationOutcome = ""
	OutcomeConfirmedPhishing EscalationOutcome = "confirmed_phishing"
	OutcomeFalsePositive     EscalationOutcome = "false_positive"
	OutcomeRequiresHunting   EscalationOutcome = "requires_hunting"
	OutcomeClosedNoAction    EscalationOutcome = "closed_no_action"
)

// Valid reports whether o is one of the recognised outcomes.
func (o EscalationOutcome) Valid() bool {
	switch o {
	case OutcomeConfirmedPhishing, OutcomeFalsePositive, OutcomeRequiresHunting, OutcomeClosedNoAction:
		return true
	}
	return false
}

// EscalationIncident is the structured incident shape supplied by the
// caller. It carries pseudonymised metadata only — no raw subject,
// sender, or body content.
type EscalationIncident struct {
	PseudoMessageID   string           `json:"pseudo_message_id"`
	Tier              string           `json:"tier"`
	Category          string           `json:"category"`
	Reason            EscalationReason `json:"reason"`
	Score             float64          `json:"score"`
	AffectedUserCount int              `json:"affected_user_count"`
	AISummary         string           `json:"ai_summary,omitempty"`
	Indicators        []string         `json:"indicators,omitempty"`
	DetectedAt        time.Time        `json:"detected_at"`
}

// EscalationTicket is the package handed off to SecOps.
type EscalationTicket struct {
	// SchemaVersion is the WS-7c wire-format version tag. See
	// internal/dto/schema_version.go for the contract.
	SchemaVersion   string             `json:"schema_version,omitempty"`
	TicketID        string             `json:"ticket_id"`
	TenantID        string             `json:"tenant_id"`
	CreatedAt       time.Time          `json:"created_at"`
	Reason          EscalationReason   `json:"reason"`
	Incident        EscalationIncident `json:"incident"`
	Timeline        []EscalationStep   `json:"timeline,omitempty"`
	Outcome         EscalationOutcome  `json:"outcome,omitempty"`
	ResolvedAt      time.Time          `json:"resolved_at,omitempty"`
	ResolverHash    string             `json:"resolver_hash,omitempty"`
	ResolutionNotes string             `json:"resolution_notes,omitempty"`
}

// EscalationStep is one entry on the incident timeline.
type EscalationStep struct {
	OccurredAt time.Time `json:"occurred_at"`
	Step       string    `json:"step"`
	Detail     string    `json:"detail,omitempty"`
}
