package evaluate

import (
	"sort"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// CategoryWeights configures the rule-weight matrix used by
// [RuleCategorizer]. Each field corresponds to a signal-→-category
// edge in the deterministic scoring graph.
//
// The fields are exported so per-tenant overrides can be loaded from
// the same config store the score-engine weights already use (see
// [Weights]). Every field has a sensible default — callers that don't
// want to think about tuning just use [DefaultCategoryWeights].
//
// All weights are added together within a category bucket; the
// highest-scoring bucket wins. See docs/CATEGORIZER_WEIGHTS.md
// for the rationale behind each default.
type CategoryWeights struct {
	// HighScoreThreshold is the EvaluateResult.Score above which the
	// LikelyPhishing bucket gets a heavy nudge regardless of other
	// signals. Defaults to 70 (matches dto.RiskTierBlock).
	HighScoreThreshold int
	// HighScoreWeight is added to LikelyPhishing when the message
	// score crosses HighScoreThreshold.
	HighScoreWeight float64
	// FirstContactWeight is added to FirstContactExternal when the
	// risk signals flag a first-time external sender.
	FirstContactWeight float64
	// LookalikeDomainWeight is added to LookalikeDomain when a
	// homograph/typosquat is detected.
	LookalikeDomainWeight float64
	// LookalikeBECNudge is added to BECImpersonation alongside the
	// LookalikeDomain primary — most lookalikes are impersonation
	// attempts on executives so we want BEC to ride along.
	LookalikeBECNudge float64
	// SuspiciousURLWeight is added to SuspiciousURL when at least one
	// URL is flagged.
	SuspiciousURLWeight float64
	// SuspiciousURLPhishingNudge is added to LikelyPhishing when a
	// suspicious URL is present (URLs and phishing co-occur often).
	SuspiciousURLPhishingNudge float64
	// SuspiciousAttachmentWeight is added to SuspiciousAttachment.
	SuspiciousAttachmentWeight float64
	// QRPhishingWeight is added to QRPhishing.
	QRPhishingWeight float64
	// InvoiceFraudWeight is added to InvoiceFraud on an invoice hint.
	InvoiceFraudWeight float64
	// InvoiceLookalikeBoost is added a second time to InvoiceFraud
	// when the message also has a lookalike sender domain — that
	// combination is the classic invoice-redirect scam.
	InvoiceLookalikeBoost float64
	// CredentialHarvestingWeight is added to CredentialHarvesting on
	// credential-collection lexicon.
	CredentialHarvestingWeight float64
	// AuthFailedWeight is added to AuthFailed when SPF/DKIM/DMARC
	// fail.
	AuthFailedWeight float64
	// AuthFailedPhishingNudge is added to LikelyPhishing alongside
	// AuthFailed — auth failures are weak on their own but reinforce
	// a phishing verdict.
	AuthFailedPhishingNudge float64
	// AccountTakeoverWeight is added to AccountTakeoverSuspected.
	AccountTakeoverWeight float64
	// VendorCompromiseWeight is added to VendorCompromise.
	VendorCompromiseWeight float64
	// LLMCategoryWeight is added to each category the LLM (Tier 2)
	// proposed. Kept low enough that the LLM can participate in
	// ranking but cannot single-handedly overrule a deterministic
	// signal.
	LLMCategoryWeight float64
	// ReasonCodeNudge is added per reason-code keyword match. Keep
	// small — reason codes are noisy free-text.
	ReasonCodeNudge float64
}

// DefaultCategoryWeights returns the tuned defaults baked into the
// production binary. See docs/CATEGORIZER_WEIGHTS.md for
// the rationale behind each value.
func DefaultCategoryWeights() CategoryWeights {
	return CategoryWeights{
		HighScoreThreshold:         70,
		HighScoreWeight:            3,
		FirstContactWeight:         2,
		LookalikeDomainWeight:      4,
		LookalikeBECNudge:          1,
		SuspiciousURLWeight:        3,
		SuspiciousURLPhishingNudge: 1,
		SuspiciousAttachmentWeight: 3,
		QRPhishingWeight:           4,
		InvoiceFraudWeight:         2,
		InvoiceLookalikeBoost:      2,
		CredentialHarvestingWeight: 3,
		AuthFailedWeight:           2,
		AuthFailedPhishingNudge:    1,
		AccountTakeoverWeight:      4,
		VendorCompromiseWeight:     4,
		LLMCategoryWeight:          1.5,
		ReasonCodeNudge:            0.5,
	}
}

// RuleCategorizer maps an EvaluateResult + RiskSignals to a primary
// category and up to two secondary categories. The scoring is
// deterministic: each rule adds a weight to its category bucket and
// the highest-scoring category becomes Primary. Ties are broken by
// AllCategories order so the output is stable.
//
// It implements the Categorizer interface declared in evaluator.go so
// callers can swap in alternative implementations.
type RuleCategorizer struct {
	weights CategoryWeights
}

// RuleCategorizerOption configures a RuleCategorizer at construction.
type RuleCategorizerOption func(*RuleCategorizer)

// WithCategoryWeights overrides the default weight matrix.
func WithCategoryWeights(w CategoryWeights) RuleCategorizerOption {
	return func(c *RuleCategorizer) { c.weights = w }
}

// NewRuleCategorizer returns a rule-based categoriser using
// [DefaultCategoryWeights]. Pass [WithCategoryWeights] to override
// per-tenant.
func NewRuleCategorizer(opts ...RuleCategorizerOption) *RuleCategorizer {
	c := &RuleCategorizer{weights: DefaultCategoryWeights()}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Weights returns the active weight matrix. Useful for tests and
// for surfacing the in-effect config on a debug endpoint.
func (c *RuleCategorizer) Weights() CategoryWeights { return c.weights }

// CategorisationDecision is the full categoriser output. Callers that
// only need the Categorizer interface contract use Categorise.
type CategorisationDecision struct {
	Primary   constant.Category
	Secondary []constant.Category
	Weights   map[constant.Category]float64
}

// Categorise implements the Categorizer interface declared in
// evaluator.go. The (primary, secondary, reasons) tuple mirrors the
// shape expected by the evaluation orchestrator.
func (c *RuleCategorizer) Categorise(r dto.EvaluateResult, sig dto.RiskSignals) (constant.Category, []constant.Category, []string) {
	dec := c.Decide(r, sig)
	reasons := make([]string, 0, len(dec.Weights))
	for cat, w := range dec.Weights {
		if w <= 0 {
			continue
		}
		reasons = append(reasons, string(cat))
	}
	return dec.Primary, dec.Secondary, reasons
}

// Decide is the full structured form of the categorisation, exposed
// so tests can pin the weight map. It is pure and safe to call
// concurrently.
func (c *RuleCategorizer) Decide(r dto.EvaluateResult, sig dto.RiskSignals) CategorisationDecision {
	w := c.weights
	scores := map[constant.Category]float64{}

	// Benign category gates first; if they fire we short-circuit so
	// trusted senders never get a phishing secondary.
	if sig.IsInternal {
		return CategorisationDecision{Primary: constant.CategoryInternalTrusted}
	}
	if sig.IsFromVendor {
		return CategorisationDecision{Primary: constant.CategoryVendorTrusted}
	}
	if sig.IsRecurringService {
		return CategorisationDecision{Primary: constant.CategoryNewsletter}
	}

	// Signal → category weight matrix. Weights are tuned so a single
	// high-confidence signal can win on its own but multiple medium
	// signals can stack up to flip the verdict.
	if r.Score >= w.HighScoreThreshold {
		scores[constant.CategoryLikelyPhishing] += w.HighScoreWeight
	}
	if sig.IsExternal && sig.RelationshipCategory == "FirstTimeExternal" {
		scores[constant.CategoryFirstContactExternal] += w.FirstContactWeight
	}
	if sig.HasLookalikeDomain {
		scores[constant.CategoryLookalikeDomain] += w.LookalikeDomainWeight
		scores[constant.CategoryBECImpersonation] += w.LookalikeBECNudge
	}
	if sig.HasSuspiciousURL {
		scores[constant.CategorySuspiciousURL] += w.SuspiciousURLWeight
		scores[constant.CategoryLikelyPhishing] += w.SuspiciousURLPhishingNudge
	}
	if sig.HasSuspiciousAttachment {
		scores[constant.CategorySuspiciousAttachment] += w.SuspiciousAttachmentWeight
	}
	if sig.HasQRCode {
		scores[constant.CategoryQRPhishing] += w.QRPhishingWeight
	}
	if sig.HasInvoiceHint {
		scores[constant.CategoryInvoiceFraud] += w.InvoiceFraudWeight
		if sig.HasLookalikeDomain {
			scores[constant.CategoryInvoiceFraud] += w.InvoiceLookalikeBoost
		}
	}
	if sig.HasCredentialLex {
		scores[constant.CategoryCredentialHarvesting] += w.CredentialHarvestingWeight
	}
	if sig.AuthFailed {
		scores[constant.CategoryAuthFailed] += w.AuthFailedWeight
		scores[constant.CategoryLikelyPhishing] += w.AuthFailedPhishingNudge
	}
	if sig.LooksLikeAccountTakeover {
		scores[constant.CategoryAccountTakeoverSuspected] += w.AccountTakeoverWeight
	}
	if sig.LooksLikeVendorCompromise {
		scores[constant.CategoryVendorCompromise] += w.VendorCompromiseWeight
	}
	// LLM categories are advisory; we adopt them with a moderate weight
	// so they participate in the ranking but cannot single-handedly
	// overrule a deterministic high-confidence signal.
	if r.Tier2 != nil {
		for _, c := range r.Tier2.Categories {
			scores[c] += w.LLMCategoryWeight
		}
	}
	// Reason codes (free-text from Tier 1/2) contribute small nudges
	// when they map onto a known category.
	for _, code := range r.ReasonCodes {
		code = strings.ToLower(code)
		switch {
		case strings.Contains(code, "phish"):
			scores[constant.CategoryLikelyPhishing] += w.ReasonCodeNudge
		case strings.Contains(code, "bec") || strings.Contains(code, "imperson"):
			scores[constant.CategoryBECImpersonation] += w.ReasonCodeNudge
		case strings.Contains(code, "scam") || strings.Contains(code, "fraud"):
			scores[constant.CategoryScamFraud] += w.ReasonCodeNudge
		case strings.Contains(code, "cred") || strings.Contains(code, "harvest"):
			scores[constant.CategoryCredentialHarvesting] += w.ReasonCodeNudge
		}
	}

	if len(scores) == 0 {
		// No signal fired and the message is not benign-tagged — call
		// it generic informational. The tier decider will pin it at
		// Trusted if the score is low enough.
		return CategorisationDecision{Primary: constant.CategoryFirstContactExternal, Weights: scores}
	}

	sorted := sortCategories(scores)
	dec := CategorisationDecision{Primary: sorted[0], Weights: scores}
	// Up to two secondaries; skip benign categories so we don't mix
	// "Newsletter" into a phishing verdict.
	for _, c := range sorted[1:] {
		if c.IsBenign() {
			continue
		}
		dec.Secondary = append(dec.Secondary, c)
		if len(dec.Secondary) == 2 {
			break
		}
	}
	return dec
}

// sortCategories returns categories ordered by descending score, with
// ties broken by AllCategories order so the output is stable.
func sortCategories(scores map[constant.Category]float64) []constant.Category {
	order := map[constant.Category]int{}
	for i, c := range constant.AllCategories {
		order[c] = i
	}
	cats := make([]constant.Category, 0, len(scores))
	for c := range scores {
		cats = append(cats, c)
	}
	sort.SliceStable(cats, func(i, j int) bool {
		if scores[cats[i]] != scores[cats[j]] {
			return scores[cats[i]] > scores[cats[j]]
		}
		return order[cats[i]] < order[cats[j]]
	})
	return cats
}
