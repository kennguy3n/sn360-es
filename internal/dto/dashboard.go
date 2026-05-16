package dto

import "time"

// TimeRange is a closed-open interval [Start, End) used to scope
// dashboard aggregations.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// TierCount pairs a banner tier with a count.
type TierCount struct {
	Tier  string `json:"tier"`
	Count int    `json:"count"`
}

// CategoryCount pairs a threat category with a count.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// FeedbackStats summarises user feedback button presses.
type FeedbackStats struct {
	ReportedPhishing int `json:"reported_phishing"`
	MarkedSafe       int `json:"marked_safe"`
	TrustedSender    int `json:"trusted_sender"`
}

// QuarantineStats summarises quarantine / release activity.
type QuarantineStats struct {
	Quarantined int `json:"quarantined"`
	Released    int `json:"released"`
	Refused     int `json:"refused"`
}

// SimulationStats summarises phishing-simulation outcomes.
type SimulationStats struct {
	Sent                 int `json:"sent"`
	Reported             int `json:"reported"`
	Clicked              int `json:"clicked"`
	SubmittedCredentials int `json:"submitted_credentials"`
	Ignored              int `json:"ignored"`
}

// DashboardSummary is the structured aggregate that backs the AI
// narrative. All counts cover the supplied time range.
type DashboardSummary struct {
	TenantID        string          `json:"tenant_id"`
	Range           TimeRange       `json:"range"`
	EmailsProcessed int             `json:"emails_processed"`
	ThreatsByTier   []TierCount     `json:"threats_by_tier"`
	ThreatsByCat    []CategoryCount `json:"threats_by_category"`
	FalsePositive   int             `json:"false_positives"`
	FalseNegative   int             `json:"false_negatives"`
	Feedback        FeedbackStats   `json:"feedback"`
	Quarantine      QuarantineStats `json:"quarantine"`
	Simulation      SimulationStats `json:"simulation"`
	GeneratedAt     time.Time       `json:"generated_at"`
	Narrative       string          `json:"narrative,omitempty"`
}
