package dto

import (
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// EvaluateRequest is published by the ingestion layer and consumed by the
// evaluation pipeline. It is the message shipped on the `es.evaluate.>`
// JetStream subject.
type EvaluateRequest struct {
	// MessageID is the pseudonymised email message identifier.
	MessageID string `json:"message_id"`
	// TenantID identifies the tenant that owns the recipient mailbox.
	TenantID string `json:"tenant_id"`
	// CorrelationID propagates through the pipeline for tracing.
	CorrelationID string `json:"correlation_id"`

	// Sender / Recipient metadata. Email addresses themselves should be
	// pseudonymised before logging; the raw values are kept here while the
	// request is in flight so detection logic can match against them.
	Sender    string   `json:"sender"`
	Recipient string   `json:"recipient"`
	CC        []string `json:"cc,omitempty"`
	Subject   string   `json:"subject,omitempty"`

	// Body holds the normalised plaintext body (subject + text body
	// concatenated, HTML stripped). For larger payloads, an S3 reference
	// may be substituted via BodyRef.
	Body    string `json:"body,omitempty"`
	BodyRef string `json:"body_ref,omitempty"`

	// RawBodyHash is the SHA-256 of the canonical raw body; used as cache
	// key for Rspamd and AI results.
	RawBodyHash    string `json:"raw_body_hash,omitempty"`
	NormalisedHash string `json:"normalised_hash,omitempty"`

	// Signals contains the prefilter risk signals — see RiskSignals.
	Signals RiskSignals `json:"signals"`

	// Locale is the BCP-47 locale used to render the banner. Defaults to
	// the tenant's primary locale.
	Locale string `json:"locale,omitempty"`

	// ReceivedAt is when the recipient mailbox received the message.
	ReceivedAt time.Time `json:"received_at,omitempty"`
}

// EvaluateResult is the structured output of the evaluation pipeline. It
// is published back on `es.action.>` subjects (e.g. `es.action.label`,
// `es.action.banner`) for the action consumers to act on.
type EvaluateResult struct {
	MessageID     string    `json:"message_id"`
	TenantID      string    `json:"tenant_id"`
	CorrelationID string    `json:"correlation_id"`
	EvaluatedAt   time.Time `json:"evaluated_at"`

	// Score is the final aggregated risk score (0-100).
	Score int `json:"score"`
	// Tier is the bucketed disposition based on Score and overrides.
	Tier constant.Tier `json:"tier"`
	// Primary is the dominant category for this message. Secondary lists
	// up to two additional applicable categories.
	Primary   constant.Category   `json:"primary"`
	Secondary []constant.Category `json:"secondary,omitempty"`

	// Per-stage scores. Each is 0-100 except where noted. Nil pointer
	// indicates the stage was skipped or unavailable.
	Tier0  *Tier0Outcome  `json:"tier0,omitempty"`
	Tier1  *Tier1Outcome  `json:"tier1,omitempty"`
	Tier2  *Tier2Outcome  `json:"tier2,omitempty"`
	Rspamd *RspamdOutcome `json:"rspamd,omitempty"`

	// LinkScore is the aggregated risk score (0-100) from the URL scanner.
	// Zero when no URLs were scanned or the scanner was unavailable.
	LinkScore *int `json:"link_score,omitempty"`
	// AttachmentScore is the aggregated risk score (0-100) from the
	// attachment scanner. Zero when no attachments were scanned.
	AttachmentScore *int `json:"attachment_score,omitempty"`

	// ReasonCodes are compact tokens (e.g. "lookalike_domain",
	// "auth_failed_dmarc") explaining why this verdict was reached.
	// They feed the banner template and audit log.
	ReasonCodes []string `json:"reason_codes,omitempty"`

	// Degraded reports whether any downstream service was unavailable
	// during evaluation. The orchestrator sets this so dashboards can
	// distinguish "clean" from "degraded clean" verdicts.
	Degraded         bool     `json:"degraded,omitempty"`
	DegradedServices []string `json:"degraded_services,omitempty"`

	// Recipient is the recipient mailbox address. It is propagated
	// from the originating EvaluateRequest so the downstream
	// action consumers (label, banner, url_rewrite, quarantine) can
	// address the correct mailbox without re-fetching the request.
	// Treated as routing metadata only — never logged in clear text;
	// callers should still pseudonymise before persistence.
	Recipient string `json:"recipient,omitempty"`

	// SenderHash and RecipientHash are the pseudonymised participant
	// identities derived by the signal enricher
	// (HashPII(tenantID, lower(trim(address)))). They are propagated
	// onto the verdict so the management Postgres consumer that
	// persists evaluation_results can index by sender for the WS-3b
	// investigation API
	//
	//   GET /v1/investigation/sender/{sender_hash}
	//
	// without joining back to communication_histories on a non-hash
	// equality.
	//
	// Both fields are best-effort: a producer that cannot derive a
	// hash (Sender or Recipient missing / empty / privately-stored)
	// leaves them empty and the consumer treats the row as
	// participant-unknown. The omitempty tags keep older consumers
	// happy — every reader either understands the new fields or
	// silently ignores them.
	SenderHash    []byte `json:"sender_hash,omitempty"`
	RecipientHash []byte `json:"recipient_hash,omitempty"`
}

// BackfillRoutingFields propagates the routing/identity fields the
// request carries into the result so downstream consumers on
// `es.evaluate.result` see the same envelope regardless of which
// producer emitted the verdict (per-message handleEvaluateRequest in
// cmd/sn360-es/main.go vs. BatchOrchestrator.processOnce in
// internal/service/evaluate/batch.go).
//
// The two producers ran independent inline copies of the same
// conditional-on-empty backfill until the helper was unified here.
// Without the Recipient backfill in particular,
// handleIngestionAction populates `"email": ""` in every es.action.*
// signal and each action handler (handleActionLabel,
// handleActionBanner, handleActionURLRewrite,
// handleActionQuarantine) silently returns nil on the empty-email
// guard, disabling all provider-side actions for the producer that
// forgot the backfill. MessageID / TenantID / CorrelationID /
// EvaluatedAt cover the same defensive territory.
//
// Backfill is conditional on "field empty" so a downstream
// evaluator that intentionally rewrites these fields (e.g. an
// Evaluator that re-stamps EvaluatedAt at fallback exit, or that
// produces a routing recipient distinct from the request for
// forwarded mail) is not clobbered.
func BackfillRoutingFields(res *EvaluateResult, req EvaluateRequest) {
	if res.MessageID == "" {
		res.MessageID = req.MessageID
	}
	if res.TenantID == "" {
		res.TenantID = req.TenantID
	}
	if res.CorrelationID == "" {
		res.CorrelationID = req.CorrelationID
	}
	if res.EvaluatedAt.IsZero() {
		res.EvaluatedAt = time.Now().UTC()
	}
	if res.Recipient == "" {
		res.Recipient = req.Recipient
	}
}

// Tier0Outcome captures the result of the Tier 0 classification gate.
type Tier0Outcome struct {
	// Bypass reports whether the message bypassed all ML stages.
	Bypass bool `json:"bypass"`
	// Reason is the symbolic reason a bypass / forced category was applied.
	Reason string `json:"reason,omitempty"`
	// ForcedCategory is the category the gate applied directly when Bypass
	// is true.
	ForcedCategory constant.Category `json:"forced_category,omitempty"`
	// SkipML reports whether Tier 1 / Tier 2 should be skipped.
	SkipML bool `json:"skip_ml"`
	// RspamdOnly reports whether the gate routed only to Rspamd (e.g. for
	// high-volume senders).
	RspamdOnly bool `json:"rspamd_only,omitempty"`
	// ForceEscalate reports that the relationship category requires Tier 2.
	ForceEscalate bool `json:"force_escalate,omitempty"`
	// Tier1ThresholdOverride is set when Tier 1 thresholds should be
	// lowered for this message (Partner / Customer relationships).
	Tier1ThresholdOverride int `json:"tier1_threshold_override,omitempty"`
}

// Tier1Outcome is the encoder's structured output.
type Tier1Outcome struct {
	Score      int     `json:"score"`
	Confidence float64 `json:"confidence"`
	Language   string  `json:"language,omitempty"`
	ModelName  string  `json:"model_name,omitempty"`
	Pass       bool    `json:"pass"`
	Flag       bool    `json:"flag"`
	Escalate   bool    `json:"escalate"`
	LatencyMs  int64   `json:"latency_ms"`
	// ReasonCodes are short signals the encoder surfaces (e.g.
	// "URGENT_TONE", "WIRE_REQUEST"). They are folded into the
	// per-result top-level ReasonCodes by the evaluator (and batch
	// orchestrator), but kept here too so audit / replay tools can
	// see which signals came from the encoder versus the
	// categoriser without re-running the pipeline.
	ReasonCodes []string `json:"reason_codes,omitempty"`
}

// Tier2Outcome is the LLM / SLM verdict.
type Tier2Outcome struct {
	Score       int                 `json:"score"`
	Categories  []constant.Category `json:"categories,omitempty"`
	Explanation string              `json:"explanation,omitempty"`
	Confidence  float64             `json:"confidence"`
	ModelName   string              `json:"model_name,omitempty"`
	LatencyMs   int64               `json:"latency_ms"`
}

// RspamdOutcome captures the Rspamd response.
type RspamdOutcome struct {
	Score     float64            `json:"score"`
	Threshold float64            `json:"threshold"`
	Action    string             `json:"action,omitempty"`
	Symbols   map[string]float64 `json:"symbols,omitempty"`
	LatencyMs int64              `json:"latency_ms"`
}
