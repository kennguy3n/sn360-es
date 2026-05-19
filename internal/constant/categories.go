// Package constant defines compile-time constants shared across SN360-ES
// services. The category vocabulary is the single source of truth used by
// the categorizer and the i18n banner copy.
package constant

// Category is the canonical risk / disposition label assigned to an email
// after evaluation. The 16 categories below are the same as PROPOSAL.md
// Section 6.
type Category string

const (
	CategoryLikelyPhishing           Category = "LIKELY_PHISHING"
	CategoryBECImpersonation         Category = "BEC_IMPERSONATION"
	CategoryLookalikeDomain          Category = "LOOKALIKE_DOMAIN"
	CategorySuspiciousURL            Category = "SUSPICIOUS_URL"
	CategorySuspiciousAttachment     Category = "SUSPICIOUS_ATTACHMENT"
	CategoryFirstContactExternal     Category = "FIRST_CONTACT_EXTERNAL"
	CategoryAccountTakeoverSuspected Category = "ACCOUNT_TAKEOVER_SUSPECTED"
	CategoryVendorCompromise         Category = "VENDOR_COMPROMISE"
	CategoryCredentialHarvesting     Category = "CREDENTIAL_HARVESTING"
	CategoryInvoiceFraud             Category = "INVOICE_FRAUD"
	CategoryQRPhishing               Category = "QR_PHISHING"
	CategoryScamFraud                Category = "SCAM_FRAUD"
	CategoryAuthFailed               Category = "AUTH_FAILED"
	CategoryInternalTrusted          Category = "INTERNAL_TRUSTED"
	CategoryVendorTrusted            Category = "VENDOR_TRUSTED"
	CategoryNewsletter               Category = "NEWSLETTER"
)

// AllCategories lists every category in a fixed order. Tests iterate this
// list to ensure i18n coverage.
var AllCategories = []Category{
	CategoryLikelyPhishing,
	CategoryBECImpersonation,
	CategoryLookalikeDomain,
	CategorySuspiciousURL,
	CategorySuspiciousAttachment,
	CategoryFirstContactExternal,
	CategoryAccountTakeoverSuspected,
	CategoryVendorCompromise,
	CategoryCredentialHarvesting,
	CategoryInvoiceFraud,
	CategoryQRPhishing,
	CategoryScamFraud,
	CategoryAuthFailed,
	CategoryInternalTrusted,
	CategoryVendorTrusted,
	CategoryNewsletter,
}

// IsBenign reports whether a category indicates a clean / informational
// disposition rather than a threat.
func (c Category) IsBenign() bool {
	switch c {
	case CategoryInternalTrusted, CategoryVendorTrusted, CategoryNewsletter:
		return true
	default:
		return false
	}
}

// IsHighSeverity reports whether a category warrants Blocked/HighRisk tier.
func (c Category) IsHighSeverity() bool {
	switch c {
	case CategoryLikelyPhishing,
		CategoryBECImpersonation,
		CategoryAccountTakeoverSuspected,
		CategoryVendorCompromise,
		CategoryCredentialHarvesting,
		CategoryInvoiceFraud:
		return true
	default:
		return false
	}
}

// CopyKey returns the i18n catalog key that maps to user-facing copy for
// this category. Keys are stable across releases so translators don't have
// to chase moving targets.
func (c Category) CopyKey() string {
	return "category." + string(c)
}

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	for _, known := range AllCategories {
		if c == known {
			return true
		}
	}
	return false
}
