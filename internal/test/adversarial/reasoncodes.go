package adversarial

import "strings"

// Reason codes the production evaluator currently emits via Tier 0,
// Tier 1, or the URL/attachment scanners. The adversarial property
// tests use this list to figure out whether the pipeline surfaced
// the perturbation OR silently misclassified it.
//
// IMPORTANT: this is the OBSERVED reason-code vocabulary from
// grep -rn `"<token>"` on the codebase at the time WS-4b was
// landed. We intentionally do NOT extend the evaluator to emit
// new reason codes in this PR (per the WS-4b scope: detection-
// validation infrastructure, not detection improvement). When a
// perturbation does NOT have a corresponding reason code in the
// vocabulary, the harness records a PipelineGap in the corpus
// report instead of failing the property test silently — that's
// the explicit "surface the gap" requirement.
var (
	// homoglyphReasonCodes are the codes the production pipeline
	// emits for homoglyph / lookalike attacks. As of WS-4b, the
	// vocabulary covers `lookalike_domain` (Tier 0 prefilter
	// signal HasLookalikeDomain → categorizer adds it as a reason
	// code) but does NOT cover *body-level* homoglyph substitution
	// (e.g. Cyrillic 'а' in a credential-harvest URL the Tier 0
	// scanner doesn't recognise as suspicious).
	homoglyphReasonCodes = []string{
		"lookalike_domain",
		"lookalike-domain", // hyphen variant used in some catalog entries
	}
	// zeroWidthReasonCodes — the codebase has no reason code for
	// zero-width character insertion as of WS-4b. The adversarial
	// suite documents this gap in the corpus report.
	zeroWidthReasonCodes = []string{}
	// base64URLReasonCodes — `suspicious_url` covers any URL
	// flagged by the prefilter. The data: + javascript:atob()
	// obfuscation shapes Base64ObfuscateURL emits are not
	// individually labelled in the current reason-code vocabulary;
	// we accept `suspicious_url` as the umbrella code.
	base64URLReasonCodes = []string{
		"suspicious_url",
		"has_suspicious_url",
	}
	// mimeSmugglingReasonCodes — the codebase has no specific
	// `mime_smuggling` reason code as of WS-4b. The closest signal
	// is `suspicious_attachment`, which fires when the attachment
	// scanner sees a structurally suspicious attachment.
	mimeSmugglingReasonCodes = []string{
		"suspicious_attachment",
	}
	// headerInjectionReasonCodes — DMARC/SPF/DKIM failures are the
	// closest reason codes to a forged Received header. The Tier 0
	// gate marks `internal_ato_suspected` when an apparently-
	// internal sender fails authentication; for forged externals,
	// `auth_failed_dmarc` would fire.
	headerInjectionReasonCodes = []string{
		"internal_ato_suspected",
		"auth_failed_dmarc",
		"auth_failed",
		"high_volume_sender",
	}
)

// PerturbationKind enumerates the perturbation families the suite
// exercises. The string values match the metadata key the harness
// records when surfacing a gap finding (`metadata.perturbation`).
type PerturbationKind string

const (
	KindHomoglyph       PerturbationKind = "homoglyph"
	KindZeroWidth       PerturbationKind = "zero_width"
	KindBase64URL       PerturbationKind = "base64_url"
	KindMIMESmuggling   PerturbationKind = "mime_smuggling"
	KindHeaderInjection PerturbationKind = "header_injection"
)

// ReasonCodesFor returns the list of reason codes the production
// evaluator MAY emit for the given perturbation kind. The list is
// inclusive — any of the returned codes counts as "the pipeline
// surfaced the perturbation".
//
// An empty return means there is NO existing reason code for this
// perturbation type and the property tests will record a gap rather
// than failing.
func ReasonCodesFor(kind PerturbationKind) []string {
	switch kind {
	case KindHomoglyph:
		return append([]string(nil), homoglyphReasonCodes...)
	case KindZeroWidth:
		return append([]string(nil), zeroWidthReasonCodes...)
	case KindBase64URL:
		return append([]string(nil), base64URLReasonCodes...)
	case KindMIMESmuggling:
		return append([]string(nil), mimeSmugglingReasonCodes...)
	case KindHeaderInjection:
		return append([]string(nil), headerInjectionReasonCodes...)
	}
	return nil
}

// HasAnyReasonCode reports whether any element of reasons matches
// any of expected (case-insensitive, hyphen / underscore tolerant).
func HasAnyReasonCode(reasons, expected []string) bool {
	for _, r := range reasons {
		norm := normaliseReasonCode(r)
		for _, e := range expected {
			if norm == normaliseReasonCode(e) {
				return true
			}
		}
	}
	return false
}

// HasDegradedService reports whether services contains svc
// (case-insensitive match).
func HasDegradedService(services []string, svc string) bool {
	target := strings.ToLower(svc)
	for _, s := range services {
		if strings.ToLower(s) == target {
			return true
		}
	}
	return false
}

func normaliseReasonCode(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "_")
	return s
}
