package templates

import (
	"fmt"
	"math/rand"
	"strings"
)

// recipient returns a stable per-tenant recipient address. Templates
// use it instead of hard-coding so the same Index always produces the
// same recipient (helpful for diffing corpus runs).
func recipient(opts Options) string {
	users := []string{"alice", "bob", "carol", "david", "ellen", "fionn", "grace", "hideo"}
	user := users[opts.Index%len(users)]
	tenant := opts.Tenant
	if tenant == "" {
		tenant = "acme.example"
	}
	return fmt.Sprintf("%s@%s", user, tenant)
}

// emailAddr builds a tenant-scoped address.
func emailAddr(localPart, tenant string) string {
	if tenant == "" {
		tenant = "acme.example"
	}
	return fmt.Sprintf("%s@%s", localPart, tenant)
}

// randomFreemailSender produces an attacker-style address on a free
// webmail or burner domain, used for likely-phishing / scam-fraud
// senders that should NOT look like a vendor.
func randomFreemailSender(r *rand.Rand, hint string) string {
	domains := []string{
		"gmail.com", "outlook.com", "yahoo.com", "proton.me",
		"mail.ru", "yandex.com", "gmx.com", "tutanota.com",
	}
	suffix := r.Intn(9999)
	user := fmt.Sprintf("%s.%04d", strings.ToLower(hint), suffix)
	return fmt.Sprintf("%s@%s", user, pick(r, domains))
}

// suspiciousLoginURL builds a plausibly-phishy login URL. easy
// difficulty uses obvious red flags; medium/hard use punycode and
// path obfuscation.
func suspiciousLoginURL(r *rand.Rand, level Level) string {
	hosts := map[Level][]string{
		LevelEasy: {
			"http://verify-account-now.tk/login",
			"http://microsoft-security-update.cf/auth",
			"http://office365-renew.gq/signin",
		},
		LevelMedium: {
			"https://login-microsoftonline.co/verify",
			"https://accounts-google.support/secure",
			"https://o365-portal.app/login",
		},
		LevelHard: {
			"https://login.microsoftonline.com.security-verify.app/auth?id=%s",
			"https://accounts.google.com.session-renew.io/?continue=%s",
			"https://xn--logn-3oa.microsoft.com/auth",
		},
	}
	tmpl := pick(r, hosts[level])
	if strings.Contains(tmpl, "%s") {
		return fmt.Sprintf(tmpl, fmt.Sprintf("%08x", r.Uint32()))
	}
	return tmpl
}

// lookalikeDomain returns a string that visually resembles target but
// is registrable on a public TLD. Used by lookalike_domain.go and
// invoice_fraud.go.
func lookalikeDomain(r *rand.Rand, target string) string {
	swaps := []func(string) string{
		func(s string) string { return strings.Replace(s, "o", "0", 1) },
		func(s string) string { return strings.Replace(s, "l", "1", 1) },
		func(s string) string { return strings.Replace(s, "m", "rn", 1) },
		func(s string) string { return s + "-support" },
		func(s string) string { return s + "-secure" },
	}
	swap := swaps[r.Intn(len(swaps))]
	tlds := []string{".com", ".co", ".net", ".biz", ".app"}
	base := swap(strings.ToLower(strings.TrimSuffix(target, ".com")))
	return base + pick(r, tlds)
}

// localePool returns a small phrase pool keyed by locale. Each helper
// (`t`, `body`) selects the locale's translation or falls back to the
// English template.
func localePool(loc Locale) *Pool {
	return &Pool{loc: loc}
}

// Pool is a tiny locale-keyed phrase pool used by templates.
type Pool struct {
	loc Locale
}

// t picks a translation from the variadic list. The first argument is
// the English form; subsequent arguments are th/ja/ko/zh/vi in that
// order. If a translation is missing the English form is returned.
func (p *Pool) t(en string, others ...string) string {
	order := []Locale{LocaleTH, LocaleJA, LocaleKO, LocaleZH, LocaleVI}
	if p.loc == LocaleEN || p.loc == "" {
		return en
	}
	for i, l := range order {
		if l == p.loc && i < len(others) {
			return others[i]
		}
	}
	return en
}

// body joins lines with a blank line, idiomatic for email bodies.
func (p *Pool) body(lines []string) string {
	return strings.Join(lines, "\n\n")
}
