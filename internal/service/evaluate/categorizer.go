package evaluate

import (
	"sort"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// RuleCategorizer maps an EvaluateResult + RiskSignals to a primary
// category and up to two secondary categories. The scoring is
// deterministic: each rule adds a weight to its category bucket and
// the highest-scoring category becomes Primary. Ties are broken by
// AllCategories order so the output is stable.
//
// It implements the Categorizer interface declared in evaluator.go so
// callers can swap in alternative implementations.
type RuleCategorizer struct{}

// NewRuleCategorizer returns a default rule-based categoriser. The
// struct is empty today but exists so we can later plug per-tenant
// overrides.
func NewRuleCategorizer() *RuleCategorizer { return &RuleCategorizer{} }

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
	if r.Score >= 70 {
		scores[constant.CategoryLikelyPhishing] += 3
	}
	if sig.IsExternal && sig.RelationshipCategory == "FirstTimeExternal" {
		scores[constant.CategoryFirstContactExternal] += 2
	}
	if sig.HasLookalikeDomain {
		scores[constant.CategoryLookalikeDomain] += 4
		scores[constant.CategoryBECImpersonation] += 1
	}
	if sig.HasSuspiciousURL {
		scores[constant.CategorySuspiciousURL] += 3
		scores[constant.CategoryLikelyPhishing] += 1
	}
	if sig.HasSuspiciousAttachment {
		scores[constant.CategorySuspiciousAttachment] += 3
	}
	if sig.HasQRCode {
		scores[constant.CategoryQRPhishing] += 4
	}
	if sig.HasInvoiceHint {
		scores[constant.CategoryInvoiceFraud] += 2
		if sig.HasLookalikeDomain {
			scores[constant.CategoryInvoiceFraud] += 2
		}
	}
	if sig.HasCredentialLex {
		scores[constant.CategoryCredentialHarvesting] += 3
	}
	if sig.AuthFailed {
		scores[constant.CategoryAuthFailed] += 2
		scores[constant.CategoryLikelyPhishing] += 1
	}
	if sig.LooksLikeAccountTakeover {
		scores[constant.CategoryAccountTakeoverSuspected] += 4
	}
	if sig.LooksLikeVendorCompromise {
		scores[constant.CategoryVendorCompromise] += 4
	}
	// LLM categories are advisory; we adopt them with a moderate weight
	// so they participate in the ranking but cannot single-handedly
	// overrule a deterministic high-confidence signal.
	if r.Tier2 != nil {
		for _, c := range r.Tier2.Categories {
			scores[c] += 1.5
		}
	}
	// Reason codes (free-text from Tier 1/2) contribute small nudges
	// when they map onto a known category.
	for _, code := range r.ReasonCodes {
		code = strings.ToLower(code)
		switch {
		case strings.Contains(code, "phish"):
			scores[constant.CategoryLikelyPhishing] += 0.5
		case strings.Contains(code, "bec") || strings.Contains(code, "imperson"):
			scores[constant.CategoryBECImpersonation] += 0.5
		case strings.Contains(code, "scam") || strings.Contains(code, "fraud"):
			scores[constant.CategoryScamFraud] += 0.5
		case strings.Contains(code, "cred") || strings.Contains(code, "harvest"):
			scores[constant.CategoryCredentialHarvesting] += 0.5
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
