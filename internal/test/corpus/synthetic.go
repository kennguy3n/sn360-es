package corpus

import (
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"sort"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// SyntheticVersion is the source tag embedded in every synthetic
// fixture's metadata. Bumping the version is the contract used by
// SyntheticOnly + Report.CorpusVersion to distinguish runs.
const SyntheticVersion = "ws4b-synthetic-v1"

// DefaultSyntheticSeed is the canonical PRNG seed used to generate
// the corpus committed to testdata/corpus-eval/synthetic.jsonl. The
// CI baseline is captured against this seed; re-running the
// generator with the same seed produces byte-identical output.
const DefaultSyntheticSeed uint64 = 4242

// DefaultSyntheticSize is the canonical corpus size: 200 fixtures, 50
// per label. The number is chosen so per-label F1 has reasonable
// resolution (a single misclassification moves F1 by ~2 points) while
// still being small enough to evaluate in well under a second on a
// degraded pipeline.
const DefaultSyntheticSize = 200

// GenerateSynthetic returns a deterministic 200-email synthetic corpus
// (50 fixtures per label) keyed off the supplied seed. The generator
// is intentionally simple: each label has a small bag of templates
// that compose subject / body / sender domain fragments, and the
// PRNG drives the selection so the same seed produces the same
// sequence of fixtures. The result is sorted by ID for stable JSONL
// output.
//
// IMPORTANT: this is a scaffold for the harness, not a substitute
// for a real-world labelled corpus. Every fixture's metadata
// includes `source: "ws4b-synthetic-v1"` so consumers of the
// report can distinguish synthetic-vs-real headlines (see
// Report.SyntheticOnly).
func GenerateSynthetic(seed uint64) []Fixture {
	return GenerateSyntheticN(seed, DefaultSyntheticSize)
}

// GenerateSyntheticN is the size-parametric form of GenerateSynthetic.
// Sizes that are not multiples of 4 are rounded up so each label
// gets the same count (e.g. size=10 → 12 fixtures, 3 per label).
func GenerateSyntheticN(seed uint64, size int) []Fixture {
	if size <= 0 {
		size = DefaultSyntheticSize
	}
	perLabel := (size + len(AllLabels) - 1) / len(AllLabels)
	// #nosec G404 -- the synthetic corpus is test fixtures, not a
	// cryptographic source. Determinism (same seed → same corpus)
	// is the entire point; crypto/rand would break reproducibility.
	rng := rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15))

	out := make([]Fixture, 0, perLabel*len(AllLabels))
	for _, label := range AllLabels {
		for i := 0; i < perLabel; i++ {
			out = append(out, generateOne(rng, label, i))
		}
	}
	// Stable ID-sorted output so successive seed=N runs yield
	// byte-identical JSONL files.
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// WriteJSONL writes a fixture slice to w in line-delimited JSON, with
// a comment header documenting the synthetic provenance.
func WriteJSONL(w io.Writer, fixtures []Fixture) error {
	header := []string{
		"// synthetic — replace with real corpus when available",
		fmt.Sprintf("// source: %s", SyntheticVersion),
		fmt.Sprintf("// fixture_count: %d", len(fixtures)),
		"// generator: internal/test/corpus.GenerateSynthetic",
		"",
	}
	if _, err := io.WriteString(w, strings.Join(header, "\n")+"\n"); err != nil {
		return err
	}
	for _, fx := range fixtures {
		// Inline JSON encoding so the fixture can be written one
		// line at a time without buffering the whole corpus.
		b, err := marshalFixtureLine(fx)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	return nil
}

// generateOne produces a single synthetic fixture for the given label
// and per-label index. The PRNG draws are stable for the same (label,
// index) tuple given a fresh seed → the sort step in GenerateSyntheticN
// produces deterministic JSONL output.
func generateOne(rng *rand.Rand, label Label, idx int) Fixture {
	tpl := pickTemplate(rng, label)
	domain := pickDomain(rng, label, tpl)
	sender := tpl.SenderLocal + "@" + domain
	recipient := "user" + nstr(idx+1) + "@example-corp.com"
	subject := tpl.Subject
	body := tpl.Body

	rfc822 := buildRFC822(rfc822Spec{
		From:      tpl.SenderDisplay + " <" + sender + ">",
		To:        recipient,
		Subject:   subject,
		Body:      body,
		MessageID: fmt.Sprintf("<%s-%d@%s>", label, idx, domain),
	})

	expected := tpl.ExpectedTier
	if expected == "" {
		expected = label.ExpectedTier()
	}

	meta := map[string]string{
		"source":      SyntheticVersion,
		"attack_type": tpl.AttackType,
		"template":    tpl.Name,
		"domain":      domain,
	}
	for k, v := range tpl.SignalOverrides {
		meta[k] = v
	}

	return Fixture{
		ID:              fmt.Sprintf("%s-%03d", label, idx+1),
		Label:           label,
		RFC822:          base64.StdEncoding.EncodeToString([]byte(rfc822)),
		ExpectedTier:    expected,
		ExpectedPrimary: tpl.ExpectedPrimary,
		Metadata:        meta,
	}
}

// nstr is a tiny zero-pad helper used only in fixture IDs.
func nstr(n int) string {
	switch {
	case n < 10:
		return "00" + fmt.Sprintf("%d", n)
	case n < 100:
		return "0" + fmt.Sprintf("%d", n)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// template carries the parameterised fragments used to compose one
// fixture. Templates intentionally live in code rather than YAML
// so the generator stays import-free of any test-time configuration
// system.
type template struct {
	Name            string
	SenderLocal     string
	SenderDisplay   string
	Subject         string
	Body            string
	AttackType      string
	ExpectedTier    constant.Tier
	ExpectedPrimary constant.Category
	Domains         []string
	SignalOverrides map[string]string
}

// pickTemplate selects a template for the label using the PRNG. The
// table size is small (4–6 entries per label) so the distribution
// across the 50-fixture-per-label budget is balanced.
func pickTemplate(rng *rand.Rand, label Label) template {
	templates := allTemplates(label)
	return templates[rng.IntN(len(templates))]
}

// pickDomain selects a sender domain from the template's list.
func pickDomain(rng *rand.Rand, label Label, t template) string {
	if len(t.Domains) == 0 {
		switch label {
		case LabelBenign:
			return "vendor.com"
		default:
			return "suspicious.example"
		}
	}
	return t.Domains[rng.IntN(len(t.Domains))]
}

// allTemplates returns the seed set of templates for a label.
// Adding new templates here grows the corpus diversity without
// touching the rest of the generator.
func allTemplates(label Label) []template {
	switch label {
	case LabelPhish:
		return []template{
			{
				Name:            "credential-harvest-microsoft",
				SenderLocal:     "security-alert",
				SenderDisplay:   "Microsoft Account Security",
				Subject:         "URGENT: Verify your account before suspension",
				Body:            "Your Microsoft account will be suspended in 24 hours. Click the link below to verify your identity and prevent loss of access:\nhttps://microsoftt-secure.example/verify?u=user\nYou must update your password immediately to maintain access.",
				AttackType:      "credential-harvest",
				ExpectedTier:    constant.TierHighRisk,
				ExpectedPrimary: constant.CategoryCredentialHarvesting,
				Domains:         []string{"microsoftt-secure.example", "ms-account-verify.example", "office365-login.example"},
				SignalOverrides: map[string]string{
					"signals.has_lookalike_domain": "true",
					"signals.has_suspicious_url":   "true",
					"signals.has_credential_lex":   "true",
					"signals.has_failed_auth":      "true",
				},
			},
			{
				Name:            "lookalike-bank",
				SenderLocal:     "noreply",
				SenderDisplay:   "Bank of America Online",
				Subject:         "Action Required: Confirm your recent transaction",
				Body:            "We detected an unauthorised login attempt on your account. Please confirm your identity by signing in at the link below within the next hour to prevent your account from being locked:\nhttps://bankofarnerica-secure.example/confirm",
				AttackType:      "lookalike-bank",
				ExpectedTier:    constant.TierHighRisk,
				ExpectedPrimary: constant.CategoryLookalikeDomain,
				Domains:         []string{"bankofarnerica-secure.example", "bofa-alerts.example"},
				SignalOverrides: map[string]string{
					"signals.has_lookalike_domain": "true",
					"signals.has_suspicious_url":   "true",
					"signals.has_failed_auth":      "true",
				},
			},
			{
				Name:            "package-delivery-phish",
				SenderLocal:     "tracking",
				SenderDisplay:   "FedEx Shipment Notification",
				Subject:         "Delivery failed — schedule re-delivery",
				Body:            "Your package #FX2387283 could not be delivered. Re-schedule delivery by signing in at the URL below:\nhttps://fedex-redelivery.example/login\nThis link expires in 12 hours.",
				AttackType:      "package-delivery",
				ExpectedTier:    constant.TierWarning,
				ExpectedPrimary: constant.CategoryLikelyPhishing,
				Domains:         []string{"fedex-redelivery.example", "ups-redeliver.example"},
				SignalOverrides: map[string]string{
					"signals.has_suspicious_url": "true",
				},
			},
			{
				Name:            "tax-refund-phish",
				SenderLocal:     "refunds",
				SenderDisplay:   "IRS Tax Refund Service",
				Subject:         "Your 2025 tax refund of $1,847.22 is ready",
				Body:            "You are eligible for a tax refund of $1,847.22. To claim, sign in to verify your bank details:\nhttps://irs-refund-portal.example/claim",
				AttackType:      "tax-refund",
				ExpectedTier:    constant.TierWarning,
				ExpectedPrimary: constant.CategoryLikelyPhishing,
				Domains:         []string{"irs-refund-portal.example"},
				SignalOverrides: map[string]string{
					"signals.has_suspicious_url": "true",
					"signals.has_credential_lex": "true",
				},
			},
			{
				Name:            "qr-phish-mfa",
				SenderLocal:     "it-support",
				SenderDisplay:   "IT Support",
				Subject:         "Re-enroll your MFA device by Friday",
				Body:            "All staff must re-enroll their MFA device by Friday. Scan the QR code in the attached image to register your new authenticator:\n[QR CODE]\nFailure to comply will result in loss of email access.",
				AttackType:      "qr-mfa",
				ExpectedTier:    constant.TierWarning,
				ExpectedPrimary: constant.CategoryQRPhishing,
				Domains:         []string{"it-support-corp.example"},
				SignalOverrides: map[string]string{
					"signals.has_qr_code":        "true",
					"signals.has_credential_lex": "true",
				},
			},
		}
	case LabelBEC:
		return []template{
			{
				Name:            "ceo-wire-transfer",
				SenderLocal:     "ceo",
				SenderDisplay:   "Sarah Johnson",
				Subject:         "Quick wire transfer needed",
				Body:            "Are you at your desk? I need you to process a wire transfer of $48,500 to a new vendor before close of business today. Reply to confirm and I'll send the wiring instructions. Send from the operating account. Keep this confidential — we're closing an acquisition.",
				AttackType:      "ceo-wire",
				ExpectedTier:    constant.TierHighRisk,
				ExpectedPrimary: constant.CategoryBECImpersonation,
				Domains:         []string{"example-ceo.example", "ceo-private.example"},
				SignalOverrides: map[string]string{
					"signals.has_failed_auth": "true",
				},
			},
			{
				Name:            "invoice-redirect",
				SenderLocal:     "billing",
				SenderDisplay:   "Acme Vendor Billing",
				Subject:         "Updated wire instructions for Invoice #4823",
				Body:            "Please note that our banking details have changed effective immediately. For all outstanding invoices including #4823, please remit payment to the new account:\nBank: International Holdings\nAccount: 7281828\nRouting: 008712\nKindly confirm receipt and update your records.",
				AttackType:      "invoice-redirect",
				ExpectedTier:    constant.TierHighRisk,
				ExpectedPrimary: constant.CategoryInvoiceFraud,
				Domains:         []string{"acme-vendor-billing.example", "vendor-finance.example"},
				SignalOverrides: map[string]string{
					"signals.has_failed_auth":       "true",
					"signals.relationship_category": "LapsedContact",
				},
			},
			{
				Name:            "payroll-redirect",
				SenderLocal:     "j.smith",
				SenderDisplay:   "John Smith",
				Subject:         "Update direct deposit",
				Body:            "Hi, I'd like to update my direct deposit details before the next payroll run. Please switch my paycheck to the account below:\nBank: First National\nAccount: 0192837465\nRouting: 021000089\nThanks for handling this quickly.",
				AttackType:      "payroll-redirect",
				ExpectedTier:    constant.TierHighRisk,
				ExpectedPrimary: constant.CategoryBECImpersonation,
				Domains:         []string{"j-smith-personal.example", "jsmith-direct.example"},
				SignalOverrides: map[string]string{
					"signals.has_failed_auth": "true",
				},
			},
			{
				Name:            "vendor-takeover",
				SenderLocal:     "ap",
				SenderDisplay:   "Accounts Payable",
				Subject:         "Re: Payment for Invoice #2289",
				Body:            "Hi — confirming the payment for invoice #2289 should now go to our updated banking partner. Please use the new IBAN below:\nIBAN: GB29 NWBK 6016 1331 9268 19\nSwift: NWBKGB2L\nPlease confirm when sent.",
				AttackType:      "vendor-takeover",
				ExpectedTier:    constant.TierHighRisk,
				ExpectedPrimary: constant.CategoryVendorCompromise,
				Domains:         []string{"trusted-vendor-ap.example"},
				SignalOverrides: map[string]string{
					"signals.is_from_vendor":  "true",
					"signals.has_failed_auth": "true",
				},
			},
		}
	case LabelSpam:
		return []template{
			{
				Name:            "promo-newsletter",
				SenderLocal:     "deals",
				SenderDisplay:   "Daily Deals",
				Subject:         "60% OFF — Last chance for summer savings",
				Body:            "Don't miss our biggest sale of the year! Shop now and save up to 60% on everything sitewide. Limited time only — sale ends Friday. Visit our store or call 1-800-555-0100 for details.",
				AttackType:      "promo-spam",
				ExpectedTier:    constant.TierCaution,
				ExpectedPrimary: constant.CategoryScamFraud,
				Domains:         []string{"daily-deals-promo.example", "summer-sale.example"},
			},
			{
				Name:            "lottery-scam",
				SenderLocal:     "winners",
				SenderDisplay:   "International Sweepstakes Org.",
				Subject:         "Congratulations! You have won $5,000,000",
				Body:            "Dear Winner,\nYou have been selected as the recipient of $5,000,000 in our international sweepstakes. To claim your prize, reply with your name, phone number, and bank account information.\nRegards,\nSweepstakes Coordinator",
				AttackType:      "lottery-scam",
				ExpectedTier:    constant.TierCaution,
				ExpectedPrimary: constant.CategoryScamFraud,
				Domains:         []string{"sweeps-winner.example"},
			},
			{
				Name:            "supplements-spam",
				SenderLocal:     "noreply",
				SenderDisplay:   "Wellness Now",
				Subject:         "New: Lose 20 lbs in 30 days",
				Body:            "Our breakthrough supplement formula has helped thousands of customers achieve their weight loss goals — guaranteed results in 30 days or your money back. Visit wellness-now.example to order.",
				AttackType:      "supplements-spam",
				ExpectedTier:    constant.TierCaution,
				ExpectedPrimary: constant.CategoryScamFraud,
				Domains:         []string{"wellness-now.example"},
			},
			{
				Name:            "crypto-investment",
				SenderLocal:     "ceo",
				SenderDisplay:   "Crypto Daily Insider",
				Subject:         "Last call: 1000x crypto pick this week",
				Body:            "Our analysts have identified a new crypto token poised for a 1000x gain. Don't miss out — sign up for our newsletter today to receive the buy signal.",
				AttackType:      "crypto-spam",
				ExpectedTier:    constant.TierCaution,
				ExpectedPrimary: constant.CategoryScamFraud,
				Domains:         []string{"crypto-insider-tips.example"},
			},
		}
	case LabelBenign:
		return []template{
			{
				Name:            "internal-mail",
				SenderLocal:     "k.adams",
				SenderDisplay:   "Karen Adams",
				Subject:         "Q4 planning notes",
				Body:            "Hi all,\nAttached are my notes from the Q4 planning session. The summary of the action items is in the appendix. Let me know if I missed anything.\nThanks,\nKaren",
				AttackType:      "internal-trusted",
				ExpectedTier:    constant.TierTrusted,
				ExpectedPrimary: constant.CategoryInternalTrusted,
				Domains:         []string{"example-corp.com"},
				SignalOverrides: map[string]string{
					"signals.is_internal":      "true",
					"signals.sender_domain":    "example-corp.com",
					"signals.recipient_domain": "example-corp.com",
				},
			},
			{
				Name:            "vendor-trusted",
				SenderLocal:     "billing",
				SenderDisplay:   "Acme Co. Billing",
				Subject:         "Your monthly invoice is ready",
				Body:            "Hi,\nYour invoice for November 2025 is now available in the customer portal. Total due: $1,250.00.\nLog in to view or pay online. Thanks for your business!\n— Acme Co.",
				AttackType:      "vendor-trusted",
				ExpectedTier:    constant.TierTrusted,
				ExpectedPrimary: constant.CategoryVendorTrusted,
				Domains:         []string{"acme-co-billing.com"},
				SignalOverrides: map[string]string{
					"signals.is_from_vendor": "true",
				},
			},
			{
				Name:            "newsletter-trusted",
				SenderLocal:     "newsletter",
				SenderDisplay:   "Industry Weekly",
				Subject:         "This week in cybersecurity",
				Body:            "Welcome to this week's edition of Industry Weekly! In this issue: zero-trust adoption trends, the latest CVEs to watch, and our annual reader survey.\nUnsubscribe at the link below if you no longer wish to receive these updates.",
				AttackType:      "newsletter",
				ExpectedTier:    constant.TierInformational,
				ExpectedPrimary: constant.CategoryNewsletter,
				Domains:         []string{"industry-weekly.example"},
				SignalOverrides: map[string]string{
					"signals.is_recurring_service": "true",
				},
			},
			{
				Name:            "transactional-receipt",
				SenderLocal:     "receipts",
				SenderDisplay:   "Office Supply Co.",
				Subject:         "Your order has shipped",
				Body:            "Hi,\nGood news — your order #82717 has shipped and will arrive on Tuesday. Tracking number AB1234567US.\nThanks for shopping with us!",
				AttackType:      "transactional",
				ExpectedTier:    constant.TierTrusted,
				ExpectedPrimary: constant.CategoryVendorTrusted,
				Domains:         []string{"office-supply-co.example"},
				SignalOverrides: map[string]string{
					"signals.is_from_vendor": "true",
				},
			},
			{
				Name:            "calendar-invite",
				SenderLocal:     "calendar",
				SenderDisplay:   "Calendar",
				Subject:         "Meeting accepted: Project sync",
				Body:            "Karen Adams has accepted the meeting invitation for 'Project sync' on Tuesday at 10:00. The event details are in your calendar.",
				AttackType:      "calendar",
				ExpectedTier:    constant.TierTrusted,
				ExpectedPrimary: constant.CategoryInternalTrusted,
				Domains:         []string{"example-corp.com"},
				SignalOverrides: map[string]string{
					"signals.is_internal": "true",
				},
			},
		}
	}
	return nil
}

// rfc822Spec is the minimum payload needed to build a parseable
// RFC822 message. The generator deliberately uses plaintext bodies
// to keep MIME parsing concerns out of the synthetic corpus; the
// adversarial fuzz suite layers MIME smuggling on top of the
// generated fixtures.
type rfc822Spec struct {
	From      string
	To        string
	Subject   string
	Body      string
	MessageID string
}

// buildRFC822 assembles the spec into a CRLF-delimited RFC822 message.
// Bare LF in the body is left as-is; net/mail.ReadMessage is forgiving
// enough that the harness loader accepts it.
func buildRFC822(s rfc822Spec) string {
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(s.From)
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(s.To)
	b.WriteString("\r\n")
	b.WriteString("Subject: ")
	b.WriteString(s.Subject)
	b.WriteString("\r\n")
	b.WriteString("Message-ID: ")
	b.WriteString(s.MessageID)
	b.WriteString("\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(s.Body)
	return b.String()
}

// marshalFixtureLine encodes a fixture as compact JSON suitable for a
// single JSONL line. We use a deterministic key ordering (id, label,
// expected_tier, expected_primary, metadata, rfc822 last) so the
// committed fixture file is byte-stable across regeneration runs.
func marshalFixtureLine(fx Fixture) ([]byte, error) {
	var b strings.Builder
	b.WriteString(`{"id":`)
	b.WriteString(quoteJSON(fx.ID))
	b.WriteString(`,"label":`)
	b.WriteString(quoteJSON(string(fx.Label)))
	if fx.ExpectedTier != "" {
		b.WriteString(`,"expected_tier":`)
		b.WriteString(quoteJSON(string(fx.ExpectedTier)))
	}
	if fx.ExpectedPrimary != "" {
		b.WriteString(`,"expected_primary":`)
		b.WriteString(quoteJSON(string(fx.ExpectedPrimary)))
	}
	if len(fx.Metadata) > 0 {
		b.WriteString(`,"metadata":{`)
		keys := make([]string, 0, len(fx.Metadata))
		for k := range fx.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(quoteJSON(k))
			b.WriteByte(':')
			b.WriteString(quoteJSON(fx.Metadata[k]))
		}
		b.WriteByte('}')
	}
	b.WriteString(`,"rfc822":`)
	b.WriteString(quoteJSON(fx.RFC822))
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// quoteJSON renders s as a JSON string literal. It re-uses
// strconv.Quote semantics (Go-style escapes for control chars +
// non-ASCII as \uXXXX) which matches what encoding/json produces by
// default. We hand-roll it here only to keep the JSONL line
// generation allocation-light and key-ordered; correctness is
// covered by TestSyntheticDeterministic which round-trips the
// produced JSONL through encoding/json.
func quoteJSON(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
