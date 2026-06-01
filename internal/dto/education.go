package dto

import "time"

// AttackType groups phishing-simulation templates by attacker objective.
type AttackType string

const (
	AttackTypeBEC AttackType = "bec"
	// G101 false positive: this enum tags the *kind* of phishing
	// simulation, not a real credential.
	AttackTypeCredentialPhishing AttackType = "credential_phishing" //nolint:gosec
	AttackTypeQRPhishing         AttackType = "qr_phishing"
	AttackTypeInvoiceFraud       AttackType = "invoice_fraud"
	AttackTypeLookalikeDomain    AttackType = "lookalike_domain"
	AttackTypeAccountTakeover    AttackType = "account_takeover"
)

// AllAttackTypes lists every attack type in a stable order. Tests iterate
// this list to verify template coverage.
var AllAttackTypes = []AttackType{
	AttackTypeBEC,
	AttackTypeCredentialPhishing,
	AttackTypeQRPhishing,
	AttackTypeInvoiceFraud,
	AttackTypeLookalikeDomain,
	AttackTypeAccountTakeover,
}

// Valid reports whether a is a known attack type.
func (a AttackType) Valid() bool {
	for _, k := range AllAttackTypes {
		if a == k {
			return true
		}
	}
	return false
}

// DifficultyLevel grades a simulation's realism. Higher difficulty
// = more subtle red flags and harder to detect.
type DifficultyLevel string

const (
	DifficultyEasy   DifficultyLevel = "easy"
	DifficultyMedium DifficultyLevel = "medium"
	DifficultyHard   DifficultyLevel = "hard"
)

// AllDifficulties lists every difficulty in ascending order.
var AllDifficulties = []DifficultyLevel{
	DifficultyEasy,
	DifficultyMedium,
	DifficultyHard,
}

// Valid reports whether d is a known difficulty.
func (d DifficultyLevel) Valid() bool {
	switch d {
	case DifficultyEasy, DifficultyMedium, DifficultyHard:
		return true
	}
	return false
}

// SimulationTemplate is a single parameterised phishing test scenario.
// Templates are deliberately data-only — rendering is handled by the
// TemplateLibrary so the same template can be re-used across tenants.
type SimulationTemplate struct {
	TemplateID              string          `json:"template_id"`
	AttackType              AttackType      `json:"attack_type"`
	Difficulty              DifficultyLevel `json:"difficulty"`
	Locale                  string          `json:"locale,omitempty"`
	SubjectTemplate         string          `json:"subject_template"`
	BodyTemplate            string          `json:"body_template"`
	SenderDisplayTemplate   string          `json:"sender_display_template"`
	SenderDomainTemplate    string          `json:"sender_domain_template"`
	LandingPageType         string          `json:"landing_page_type"`
	ExpectedDetectionPoints []string        `json:"expected_detection_points,omitempty"`
}

// RenderedSimulation is the output of a TemplateLibrary.Render call.
type RenderedSimulation struct {
	TemplateID     string `json:"template_id"`
	Subject        string `json:"subject"`
	Body           string `json:"body"`
	SenderDisplay  string `json:"sender_display"`
	SenderDomain   string `json:"sender_domain"`
	LandingPage    string `json:"landing_page"`
	RenderedAt     time.Time
	Parameters     map[string]string `json:"parameters,omitempty"`
	ContainsHazard bool              `json:"contains_hazard"`
}

// CampaignStatus is the high-level state of a simulation campaign.
type CampaignStatus string

const (
	CampaignDraft     CampaignStatus = "draft"
	CampaignScheduled CampaignStatus = "scheduled"
	CampaignSending   CampaignStatus = "sending"
	CampaignActive    CampaignStatus = "active"
	CampaignCompleted CampaignStatus = "completed"
	CampaignCancelled CampaignStatus = "cancelled"
)

// Campaign is a single tenant-scoped phishing simulation.
type Campaign struct {
	CampaignID  string          `json:"campaign_id"`
	TenantID    string          `json:"tenant_id"`
	Name        string          `json:"name"`
	TemplateID  string          `json:"template_id"`
	Difficulty  DifficultyLevel `json:"difficulty"`
	Status      CampaignStatus  `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	ScheduledAt time.Time       `json:"scheduled_at"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	TargetCount int             `json:"target_count"`
	SentCount   int             `json:"sent_count"`
}

// UserInteractionType is the action a simulation target took.
type UserInteractionType string

const (
	InteractionDelivered            UserInteractionType = "delivered"
	InteractionOpened               UserInteractionType = "opened"
	InteractionClickedLink          UserInteractionType = "clicked_link"
	InteractionSubmittedCredentials UserInteractionType = "submitted_credentials"
	InteractionReportedPhishing     UserInteractionType = "reported_phishing"
	InteractionIgnored              UserInteractionType = "ignored"
)

// Valid reports whether i is a known interaction.
func (i UserInteractionType) Valid() bool {
	switch i {
	case InteractionDelivered,
		InteractionOpened,
		InteractionClickedLink,
		InteractionSubmittedCredentials,
		InteractionReportedPhishing,
		InteractionIgnored:
		return true
	}
	return false
}

// IsTeachable reports whether an interaction warrants a follow-up
// micro-lesson (i.e. the user fell for the simulation).
func (i UserInteractionType) IsTeachable() bool {
	switch i {
	case InteractionClickedLink, InteractionSubmittedCredentials:
		return true
	}
	return false
}

// IsGood reports whether the interaction is a positive outcome (user
// detected the simulation).
func (i UserInteractionType) IsGood() bool {
	switch i {
	case InteractionReportedPhishing, InteractionIgnored:
		return true
	}
	return false
}

// UserInteraction is a single recorded action by a simulation target.
type UserInteraction struct {
	// SchemaVersion is the WS-7c wire-format version tag. See
	// internal/dto/schema_version.go for the contract.
	SchemaVersion string              `json:"schema_version,omitempty"`
	CampaignID    string              `json:"campaign_id"`
	UserHash      string              `json:"user_hash"`
	Action        UserInteractionType `json:"action"`
	OccurredAt    time.Time           `json:"occurred_at"`
}

// SimulationResult aggregates the outcome counts for a campaign.
type SimulationResult struct {
	// SchemaVersion is the WS-7c wire-format version tag. See
	// internal/dto/schema_version.go for the contract.
	SchemaVersion        string `json:"schema_version,omitempty"`
	CampaignID           string `json:"campaign_id"`
	Delivered            int    `json:"delivered"`
	Opened               int    `json:"opened"`
	Clicked              int    `json:"clicked"`
	SubmittedCredentials int    `json:"submitted_credentials"`
	Reported             int    `json:"reported"`
	Ignored              int    `json:"ignored"`
}

// ResilienceTier is the human-readable bucket for a resilience score.
type ResilienceTier string

const (
	ResilienceLow    ResilienceTier = "low"
	ResilienceMedium ResilienceTier = "medium"
	ResilienceHigh   ResilienceTier = "high"
)

// ResilienceScore is a 0-100 score with explanatory breakdown.
type ResilienceScore struct {
	Subject         string         `json:"subject"` // user_hash or group_id
	Score           int            `json:"score"`
	Tier            ResilienceTier `json:"tier"`
	SimulationScore int            `json:"simulation_score"`
	ReportRateScore int            `json:"report_rate_score"`
	EngagementScore int            `json:"engagement_score"`
	IncidentScore   int            `json:"incident_score"`
	ComputedAt      time.Time      `json:"computed_at"`
}

// BucketTier converts a 0-100 score to its tier.
func BucketTier(score int) ResilienceTier {
	switch {
	case score < 40:
		return ResilienceLow
	case score < 70:
		return ResilienceMedium
	default:
		return ResilienceHigh
	}
}
