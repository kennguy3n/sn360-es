package corpus

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// localizedCopy is a per-locale subject/body pair. Locales that we do
// not have natural-language copy for fall back to the "en" entry.
type localizedCopy struct {
	Subject string
	Body    string
}

// categoryProfile encapsulates everything the generator needs to know
// about a category to produce a realistic example:
//
//   - subject/body templates per locale + difficulty
//   - sender domain pool (legitimate vs lookalike vs free vs disposable)
//   - which RiskSignals fields should be set so the RuleCategorizer
//     picks this category as Primary
//   - the relationship category to assign
//   - the expected score band (drives the tier ground truth)
type categoryProfile struct {
	Category      constant.Category
	AttackType    string
	SenderDomains []string
	// RecipientDomain is the tenant-side domain used for the recipient.
	RecipientDomain string
	// Copy is keyed by locale, then by difficulty.
	Copy map[string]map[Difficulty]localizedCopy
	// SetThreatSignals applies the category's risk-signal profile to
	// sig for a threat email. The function is also responsible for
	// nudging numeric / string signals (e.g. relationship, SPF/DKIM).
	SetThreatSignals func(sig *dto.RiskSignals, level Difficulty)
	// SetBenignSignals applies the equivalent benign profile (used for
	// FP-rate computation in the accuracy report). Returning false
	// signals the generator to skip the benign variant (e.g. for
	// AUTH_FAILED which has no clean analogue).
	SetBenignSignals func(sig *dto.RiskSignals) bool
}

// senderPools groups the sender-domain pools shared across categories.
type senderPools struct {
	Legit      []string
	Lookalike  []string
	Free       []string
	Disposable []string
	Newsletter []string
	Vendor     []string
}

// defaultSenderPools returns the canonical domain pools used by the
// per-category profiles. The values are aligned with the realistic
// fixtures used in uneycom/nges-perf-harness/scripts/smtp_json so the
// accuracy harness exercises the same surface as the integration
// tests.
func defaultSenderPools() senderPools {
	return senderPools{
		Legit: []string{
			"acme.example", "globex.example", "initech.example",
			"hooli.example", "umbrella.example", "soylent.example",
		},
		Lookalike: []string{
			"paypa1.com", "micr0soft-support.com", "amaz0n-security.com",
			"app1e-id-verify.com", "g00gle-notify.com", "0ffice365-alert.com",
			"d0cusign-net.com", "linkedln-careers.com",
		},
		Free: []string{
			"gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
			"protonmail.com", "icloud.com",
		},
		Disposable: []string{
			"mailinator.com", "tempmail.io", "10minutemail.com",
			"guerrillamail.com", "throwaway.email",
		},
		Newsletter: []string{
			"news.example.com", "updates.example.io", "mailer.example.net",
			"notifications.example.org",
		},
		Vendor: []string{
			"trusted-vendor.example", "approved-supplier.example",
			"known-saas.example",
		},
	}
}

// recipientDomain is the canonical tenant-side recipient domain used
// by every generated email. Tests that need a different domain may
// override LabeledEmail.Request.Recipient post-generation.
const recipientDomain = "tenant.example"

// pickFrom returns a deterministic element of xs based on idx.
func pickFrom[T any](xs []T, idx int) T {
	if len(xs) == 0 {
		var zero T
		return zero
	}
	return xs[(idx%len(xs)+len(xs))%len(xs)]
}

// allCategoryProfiles returns the per-category generation profiles in
// the canonical constant.AllCategories order.
func allCategoryProfiles() []categoryProfile {
	pools := defaultSenderPools()
	return []categoryProfile{
		likelyPhishingProfile(pools),
		becImpersonationProfile(pools),
		lookalikeDomainProfile(pools),
		suspiciousURLProfile(pools),
		suspiciousAttachmentProfile(pools),
		firstContactExternalProfile(pools),
		accountTakeoverProfile(pools),
		vendorCompromiseProfile(pools),
		credentialHarvestingProfile(pools),
		invoiceFraudProfile(pools),
		qrPhishingProfile(pools),
		scamFraudProfile(pools),
		authFailedProfile(pools),
		internalTrustedProfile(pools),
		vendorTrustedProfile(pools),
		newsletterProfile(pools),
	}
}

// --- Category-specific factories ----------------------------------

func likelyPhishingProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryLikelyPhishing,
		AttackType:      "credential-bait + url-mismatch",
		SenderDomains:   p.Lookalike,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Your account has been compromised — verify now",
					Body:    "We detected suspicious activity on your account. Visit https://secure-login.example/verify to reset your password immediately or your account will be suspended.",
				},
				DifficultyMedium: {
					Subject: "Important: confirm your identity",
					Body:    "A recent login attempt from an unrecognised device was blocked. To restore full access please confirm your identity at https://account-portal.example/verify-id.",
				},
				DifficultyHard: {
					Subject: "Re: shared document access",
					Body:    "Hi — wanted to make sure you saw the message from IT. There's a document waiting for your review at https://docs-share.example/preview/q4-plan. Let me know if the link looks odd.",
				},
			},
			"vi": {
				DifficultyEasy: {
					Subject: "Tài khoản của bạn đã bị xâm phạm — xác minh ngay",
					Body:    "Chúng tôi đã phát hiện hoạt động đáng ngờ trên tài khoản. Vào https://secure-login.example/verify để đặt lại mật khẩu ngay.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.HasSuspiciousURL = true
			sig.HasCredentialLex = true
			sig.HasLookalikeDomain = level != DifficultyHard
			sig.HasFailedAuth = level == DifficultyEasy
			sig.SPFResult = "softfail"
			sig.DKIMResult = "fail"
			sig.DMARCResult = mapDMARCBy(level)
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipPartner
			return true
		},
	}
}

func becImpersonationProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryBECImpersonation,
		AttackType:      "ceo-impersonation + wire-transfer",
		SenderDomains:   p.Free,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Quick request — are you at your desk?",
					Body:    "Hi, I'm in a board meeting and can't take calls. I need you to process an urgent wire transfer today. Please reply asap, this is time-sensitive. - CEO",
				},
				DifficultyMedium: {
					Subject: "Confidential: vendor payment",
					Body:    "Please initiate a wire of $47,500 to the new account info I'm sending in a follow-up. Keep this between us until I announce the acquisition tomorrow.",
				},
				DifficultyHard: {
					Subject: "Status on the supplier onboarding",
					Body:    "Hi — circling back on the supplier onboarding. Per our previous chat, can you confirm the bank details are updated in the system for the next run? Thanks.",
				},
			},
			"ja": {
				DifficultyEasy: {
					Subject: "至急: 振込のお願い",
					Body:    "会議中のため電話に出られません。今日中に緊急で送金を処理してください。詳細は別送します。 - CEO",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.HasLookalikeDomain = level != DifficultyHard
			sig.HasFailedAuth = level == DifficultyEasy
			sig.SPFResult = "pass"
			sig.DKIMResult = mapDKIMBy(level)
			sig.DMARCResult = mapDMARCBy(level)
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipCustomer
			return true
		},
	}
}

func lookalikeDomainProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryLookalikeDomain,
		AttackType:      "homoglyph sender domain",
		SenderDomains:   p.Lookalike,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Important security notice from PayPal",
					Body:    "Dear customer, your PayPa1 account was accessed from a new device. Click the link to confirm: https://paypa1.example/login",
				},
				DifficultyMedium: {
					Subject: "Microsoft 365 sign-in",
					Body:    "We blocked a sign-in to your Micr0soft 365 mailbox. Verify the activity here: https://micr0soft-support.example/activity",
				},
				DifficultyHard: {
					Subject: "DocuSign envelope completed",
					Body:    "Your DocuSign envelope has been completed by the sender. Download the signed PDF at https://d0cusign-net.example/envelope/41bd2.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.HasLookalikeDomain = true
			sig.HasSuspiciousURL = level != DifficultyHard
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			// "Benign lookalike" doesn't really exist in production; we
			// model it as a first-time external from a non-lookalike
			// domain to keep the FP measurement honest.
			sig.IsExternal = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
			return true
		},
	}
}

func suspiciousURLProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategorySuspiciousURL,
		AttackType:      "url-obfuscation + redirector",
		SenderDomains:   p.Free,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Tracking update — package out for delivery",
					Body:    "Your package is out for delivery. Track it here: https://bit.ly/3xY4kQ. If you cannot view the tracking page please open https://t.co/abc123 instead.",
				},
				DifficultyMedium: {
					Subject: "Your invoice is ready",
					Body:    "Hi, please find your invoice at the secure link: https://invoice-portal.example/view?id=29381&token=eyJhbGciOiJIUzI1NiJ9.",
				},
				DifficultyHard: {
					Subject: "Quick favor",
					Body:    "Can you take a look at this and tell me what you think? https://docs-shared.example/q4-roadmap-v3-final-FINAL.pdf",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.HasSuspiciousURL = true
			sig.HasCredentialLex = level == DifficultyEasy
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = mapDMARCBy(level)
			sig.RelationshipCategory = dto.RelationshipUnknown
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipCustomer
			return true
		},
	}
}

func suspiciousAttachmentProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategorySuspiciousAttachment,
		AttackType:      "macro-enabled office attachment",
		SenderDomains:   p.Free,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Updated invoice — please review",
					Body:    "Please find attached the updated invoice. Enable macros to view the protected content. The file is INV-2025-1138.xlsm.",
				},
				DifficultyMedium: {
					Subject: "Q3 financials draft",
					Body:    "Sending the Q3 draft for your eyes. The workbook has a macro that auto-refreshes the figures — please enable editing.",
				},
				DifficultyHard: {
					Subject: "RE: contract redlines",
					Body:    "Final redlines attached. The numbering may look odd in older Word versions; let me know and I can resend.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.HasAttachment = true
			sig.HasSuspiciousAttachment = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = mapDMARCBy(level)
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.HasAttachment = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipPartner
			return true
		},
	}
}

func firstContactExternalProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryFirstContactExternal,
		AttackType:      "first-time external sender",
		SenderDomains:   p.Legit,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Introduction — quick chat about partnership?",
					Body:    "Hi, we haven't met before. I lead BD at Globex and noticed your work. Would you be open to a 15-min intro call this week?",
				},
				DifficultyMedium: {
					Subject: "Following up on the conference",
					Body:    "Hi — really enjoyed your talk at the conference. I wanted to follow up on the discussion about distributed systems. Are you free to chat next week?",
				},
				DifficultyHard: {
					Subject: "Re: project handover",
					Body:    "Thanks for jumping on the call. As discussed I'm reaching out to confirm the handover dates. Let me know if the proposed timeline works.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, _ Difficulty) {
			sig.IsExternal = true
			sig.HasSuspiciousURL = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
			return true
		},
	}
}

func accountTakeoverProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryAccountTakeoverSuspected,
		AttackType:      "known sender + anomalous content",
		SenderDomains:   p.Legit,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "URGENT: send the wire",
					Body:    "Need you to send the wire I mentioned — totally forgot, can you do it now? Updated routing details attached, password is 'temp'.",
				},
				DifficultyMedium: {
					Subject: "Login issue",
					Body:    "Hey, I'm locked out and using a personal device. Can you reset my password and reply with the new one to this thread?",
				},
				DifficultyHard: {
					Subject: "Updated travel plans",
					Body:    "Heads up — my flight got moved. I'll respond from a different address for the next two days, please treat as legit.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.LooksLikeAccountTakeover = true
			sig.HasFailedAuth = level == DifficultyEasy
			sig.HasQuotaSpike = level != DifficultyHard
			sig.SPFResult = "pass"
			sig.DKIMResult = mapDKIMBy(level)
			sig.DMARCResult = mapDMARCBy(level)
			sig.RelationshipCategory = dto.RelationshipLapsedContact
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipRecurringService
			return true
		},
	}
}

func vendorCompromiseProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryVendorCompromise,
		AttackType:      "trusted vendor + anomalous content",
		SenderDomains:   p.Vendor,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "URGENT: account update required",
					Body:    "Due to a recent banking change please remit all outstanding payments to the new account effective immediately. Confirmation link: https://vendor-update.example/ack.",
				},
				DifficultyMedium: {
					Subject: "Update to remittance instructions",
					Body:    "Our finance team has migrated to a new banking partner. Please update the routing info on your next payment and acknowledge by replying to this thread.",
				},
				DifficultyHard: {
					Subject: "Q4 statement attached",
					Body:    "Attaching the Q4 statement as discussed. Note the small change in line 17; happy to walk through it on a call.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.LooksLikeVendorCompromise = true
			sig.HasInvoiceHint = level != DifficultyHard
			sig.HasSuspiciousURL = level == DifficultyEasy
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipRecurringService
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			// A clean vendor email would Tier 0-bypass; we generate a
			// "first-time external" benign for the FP measurement.
			sig.IsExternal = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipCustomer
			return true
		},
	}
}

func credentialHarvestingProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryCredentialHarvesting,
		AttackType:      "credential reset bait",
		SenderDomains:   p.Lookalike,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Action required: reset your password",
					Body:    "Your password will expire in 24 hours. Click https://account-reset.example/login to set a new password and avoid losing access to your mailbox.",
				},
				DifficultyMedium: {
					Subject: "Your mailbox is almost full",
					Body:    "You have used 99% of your mailbox quota. Sign in at https://mail-quota.example/upgrade to restore service before delivery is paused.",
				},
				DifficultyHard: {
					Subject: "Reminder: complete your security review",
					Body:    "Per the IT bulletin, please complete your annual security review at https://sec-review.example/login by Friday.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.HasCredentialLex = true
			sig.HasSuspiciousURL = true
			sig.HasLookalikeDomain = level != DifficultyHard
			sig.HasFailedAuth = level == DifficultyEasy
			sig.SPFResult = "pass"
			sig.DKIMResult = mapDKIMBy(level)
			sig.DMARCResult = mapDMARCBy(level)
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipRecurringService
			return true
		},
	}
}

func invoiceFraudProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryInvoiceFraud,
		AttackType:      "fake bank update / fraudulent invoice",
		SenderDomains:   p.Lookalike,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Updated payment details for invoice INV-2025-0042",
					Body:    "Please note our bank account has changed effective today. For invoice INV-2025-0042 please remit payment to IBAN XX12 3456 7890 1234. Confirm receipt by reply.",
				},
				DifficultyMedium: {
					Subject: "Invoice INV-2025-0099 attached",
					Body:    "Attached please find INV-2025-0099. Note the new banking details on page 2 — our previous account is no longer in use.",
				},
				DifficultyHard: {
					Subject: "Monthly statement",
					Body:    "Sending the monthly statement as agreed. Let me know if the line items need adjusting before close.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.HasInvoiceHint = true
			sig.HasLookalikeDomain = level != DifficultyHard
			sig.HasAttachment = level == DifficultyMedium
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = mapDMARCBy(level)
			sig.RelationshipCategory = dto.RelationshipCustomer
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.HasInvoiceHint = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipCustomer
			return true
		},
	}
}

func qrPhishingProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryQRPhishing,
		AttackType:      "qr-code embedded credential bait",
		SenderDomains:   p.Free,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Voicemail received — scan to listen",
					Body:    "You have a new voicemail. Scan the QR code below to listen. (QR code links to https://vmail-listen.example/play).",
				},
				DifficultyMedium: {
					Subject: "Secure document — scan to view",
					Body:    "The attached document is protected. Scan the QR code with your phone to retrieve the one-time access link.",
				},
				DifficultyHard: {
					Subject: "Event ticket",
					Body:    "Your conference ticket is in the attached PDF. The QR code is your venue entry pass.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.HasQRCode = true
			sig.HasAttachment = level != DifficultyHard
			sig.HasCredentialLex = level == DifficultyEasy
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.HasAttachment = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipPartner
			return true
		},
	}
}

func scamFraudProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryScamFraud,
		AttackType:      "advance-fee / 419 scam",
		SenderDomains:   p.Disposable,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Lottery winnings — claim today",
					Body:    "Congratulations! You have been selected for an international cash prize of USD 1,250,000. To process the transfer reply with your bank details and a small processing fee of $250.",
				},
				DifficultyMedium: {
					Subject: "Investment opportunity — limited window",
					Body:    "I have an exclusive opportunity that returns 32% in 30 days. Reply privately and I will share the deck.",
				},
				DifficultyHard: {
					Subject: "Charity drive — corporate sponsors needed",
					Body:    "We're raising funds for a local school. Any contribution helps. Reply for our wire instructions.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.IsDisposableDomain = true
			sig.HasSuspiciousURL = level != DifficultyHard
			sig.SPFResult = "softfail"
			sig.DKIMResult = "none"
			sig.DMARCResult = "none"
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.IsFreeDomain = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
			return true
		},
	}
}

func authFailedProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryAuthFailed,
		AttackType:      "spf+dkim+dmarc failure",
		SenderDomains:   p.Legit,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Updated meeting agenda",
					Body:    "Sharing the updated agenda for tomorrow's sync. Let me know if anyone wants to add an item.",
				},
				DifficultyMedium: {
					Subject: "Re: pricing question",
					Body:    "Thanks for the call. Attached is the pricing summary we discussed.",
				},
				DifficultyHard: {
					Subject: "FYI: status update",
					Body:    "Quick FYI — the staging deploy completed. Will share dashboards in the morning.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, level Difficulty) {
			sig.IsExternal = true
			sig.AuthFailed = true
			sig.HasFailedAuth = true
			sig.SPFResult = "fail"
			sig.DKIMResult = "fail"
			sig.DMARCResult = "fail"
			sig.RelationshipCategory = dto.RelationshipFirstTimeExternal
			_ = level
		},
		// AUTH_FAILED has no benign analogue — every benign email that
		// passes auth would be classified elsewhere. Return false so
		// the generator only produces threat samples for this category.
		SetBenignSignals: func(_ *dto.RiskSignals) bool { return false },
	}
}

func internalTrustedProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryInternalTrusted,
		AttackType:      "internal coworker email",
		SenderDomains:   p.Legit, // overridden to recipientDomain at compose time
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Lunch?",
					Body:    "Want to grab lunch at 12:30? I'm thinking the new ramen spot on 5th.",
				},
				DifficultyMedium: {
					Subject: "Standup notes",
					Body:    "Posting yesterday's standup notes here for the folks who missed it. Let me know if I got anything wrong.",
				},
				DifficultyHard: {
					Subject: "PR review request",
					Body:    "Can you take a look at the PR I opened? Should be a small change but I want a second pair of eyes.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, _ Difficulty) {
			// "Threat" variant of an internal-trusted email is an
			// internal account compromise; flagged via the ATO signal
			// while still routing as internal-trusted at Tier 0.
			sig.IsInternal = true
			sig.LooksLikeAccountTakeover = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsInternal = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			return true
		},
	}
}

func vendorTrustedProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryVendorTrusted,
		AttackType:      "trusted vendor regular communication",
		SenderDomains:   p.Vendor,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Your subscription renewal — receipt",
					Body:    "Thanks for renewing your subscription. Your receipt and PDF invoice are attached for your records.",
				},
				DifficultyMedium: {
					Subject: "Service status update",
					Body:    "We completed scheduled maintenance on the API gateway. No customer impact observed.",
				},
				DifficultyHard: {
					Subject: "New feature in your dashboard",
					Body:    "We shipped per-team dashboards this week. The team-management settings now let owners create as many groups as they need.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, _ Difficulty) {
			sig.IsExternal = true
			sig.IsFromVendor = true
			sig.LooksLikeVendorCompromise = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.IsFromVendor = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			return true
		},
	}
}

func newsletterProfile(p senderPools) categoryProfile {
	return categoryProfile{
		Category:        constant.CategoryNewsletter,
		AttackType:      "newsletter / recurring service",
		SenderDomains:   p.Newsletter,
		RecipientDomain: recipientDomain,
		Copy: map[string]map[Difficulty]localizedCopy{
			"en": {
				DifficultyEasy: {
					Subject: "Weekly digest — this week in tech",
					Body:    "Hello! Here is your weekly digest of the top tech stories. To unsubscribe click the link at the bottom of this email.",
				},
				DifficultyMedium: {
					Subject: "Product newsletter — September",
					Body:    "We rolled out several improvements this month. Highlights below; full notes on our blog.",
				},
				DifficultyHard: {
					Subject: "Reminder: your event is tomorrow",
					Body:    "Just a reminder that the event you registered for starts at 10:00 local time tomorrow. Calendar invite resent.",
				},
			},
		},
		SetThreatSignals: func(sig *dto.RiskSignals, _ Difficulty) {
			// Threat newsletter is unusual; we still mark it as
			// recurring service so the Tier 0 bypass mirrors the
			// production behaviour even though Tier 1 would flag.
			sig.IsExternal = true
			sig.IsRecurringService = true
			sig.HasSuspiciousURL = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
		},
		SetBenignSignals: func(sig *dto.RiskSignals) bool {
			sig.IsExternal = true
			sig.IsRecurringService = true
			sig.SPFResult = "pass"
			sig.DKIMResult = "pass"
			sig.DMARCResult = "pass"
			return true
		},
	}
}

// --- shared signal helpers ---------------------------------------

// mapDMARCBy returns the DMARC verdict consistent with the threat
// difficulty: easy → fail, medium → softfail-equivalent, hard → pass
// (so the message looks legitimate at the auth layer).
func mapDMARCBy(level Difficulty) string {
	switch level {
	case DifficultyEasy:
		return "fail"
	case DifficultyMedium:
		return "none"
	default:
		return "pass"
	}
}

// mapDKIMBy returns the DKIM verdict per difficulty.
func mapDKIMBy(level Difficulty) string {
	switch level {
	case DifficultyEasy:
		return "fail"
	case DifficultyMedium:
		return "none"
	default:
		return "pass"
	}
}

// composeAddress turns "localpart" + "domain" into a plausible RFC
// 5322 address. The local part is suffixed with idx so consecutive
// emails inside a category never reuse the same sender.
func composeAddress(localPrefix, domain string, idx int) string {
	return fmt.Sprintf("%s%d@%s", localPrefix, idx, domain)
}
