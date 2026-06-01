// Package adversarial implements the WS-4b adversarial fuzz suite —
// a property-based test framework that emits synthetic adversarial
// perturbations of seed emails (homoglyph substitution, zero-width
// insertion, base64-encoded URL obfuscation, MIME-multipart smuggling,
// header injection) and asserts the evaluator either (a) classifies
// the perturbed message identically to the clean one or (b) flags
// the result with `degraded: true` AND a specific reason code that
// matches the perturbation type.
//
// Silent misclassification — i.e. a result that flips classification
// without surfacing a degraded/reason-code signal — is a test failure.
//
// All perturbation functions are pure: same input + same options →
// same output. The PRNG-driven position selection is parameterised
// via a *rand.Rand argument so callers control determinism. The
// property tests under properties_test.go drive each function with
// 100 iterations against a fixed seed.
package adversarial

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/url"
	"regexp"
	"strings"
)

// homoglyphTable maps ASCII characters to a Unicode confusable.
// Most are Cyrillic look-alikes; the few Greek and Latin Extended
// substitutes fill in the gaps where Cyrillic has no good match.
// Every value renders the same as the key in a standard browser
// font but has a different codepoint, which is exactly the class
// of attack the detector is supposed to catch.
//
// Sources: Unicode TR39 confusables, the OWASP IDN homograph paper.
// We pin a curated subset rather than the full TR39 table because
// (a) several TR39 substitutions are visually distinguishable in
// monospace fonts (so they wouldn't be useful in a real attack),
// and (b) the smaller table keeps the round-trip normalisation
// behaviour stable in HomoglyphSubstitute_Unicode_Round_Trip.
var homoglyphTable = map[rune][]rune{
	'a': {'а'}, // Cyrillic small letter a (U+0430)
	'c': {'с'}, // Cyrillic small letter es (U+0441)
	'e': {'е'}, // Cyrillic small letter ie (U+0435)
	'i': {'і'}, // Cyrillic small letter byelorussian-ukrainian i (U+0456)
	'l': {'ӏ'}, // Cyrillic small letter palochka (U+04CF)
	'o': {'о'}, // Cyrillic small letter o (U+043E)
	'p': {'р'}, // Cyrillic small letter er (U+0440)
	's': {'ѕ'}, // Cyrillic small letter dze (U+0455)
	'x': {'х'}, // Cyrillic small letter ha (U+0445)
	'y': {'у'}, // Cyrillic small letter u (U+0443)
	'A': {'А'}, // Cyrillic capital letter a (U+0410)
	'B': {'В'}, // Cyrillic capital letter ve (U+0412)
	'C': {'С'}, // Cyrillic capital letter es (U+0421)
	'E': {'Е'}, // Cyrillic capital letter ie (U+0415)
	'H': {'Н'}, // Cyrillic capital letter en (U+041D)
	'I': {'І'}, // Cyrillic capital letter byelorussian-ukrainian i (U+0406)
	'K': {'К'}, // Cyrillic capital letter ka (U+041A)
	'M': {'М'}, // Cyrillic capital letter em (U+041C)
	'O': {'О'}, // Cyrillic capital letter o (U+041E)
	'P': {'Р'}, // Cyrillic capital letter er (U+0420)
	'T': {'Т'}, // Cyrillic capital letter te (U+0422)
	'X': {'Х'}, // Cyrillic capital letter ha (U+0425)
}

// HomoglyphSubstitute replaces ASCII characters in s with visually-
// confusable Unicode codepoints. The PRNG is consulted only to decide
// which positions to substitute; the table is deterministic (each
// ASCII codepoint maps to exactly one Unicode confusable in this
// implementation, so HomoglyphSubstitute(s, seed, 1.0) always
// produces the same output for fixed s + seed regardless of the
// rate parameter).
//
// rate is the probability (0..1) that any individual substitutable
// position is replaced. A rate of 1.0 substitutes every position;
// 0.5 substitutes roughly half. Rates outside [0, 1] are clamped.
//
// The function operates over UTF-8 runes, not bytes, so existing
// non-ASCII characters in s pass through unchanged.
func HomoglyphSubstitute(s string, rng *rand.Rand, rate float64) string {
	if s == "" {
		return s
	}
	if rate < 0 {
		rate = 0
	}
	if rate > 1 {
		rate = 1
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for _, r := range s {
		subs, ok := homoglyphTable[r]
		if !ok {
			b.WriteRune(r)
			continue
		}
		if rng.Float64() >= rate {
			b.WriteRune(r)
			continue
		}
		b.WriteRune(subs[0])
	}
	return b.String()
}

// HomoglyphPositions counts how many runes in s would be substituted
// at rate=1.0. The property tests use it to assert that "at least one
// substitution happened" when the seed string contains substitutable
// runes.
func HomoglyphPositions(s string) int {
	n := 0
	for _, r := range s {
		if _, ok := homoglyphTable[r]; ok {
			n++
		}
	}
	return n
}

// IsHomoglyph reports whether r is one of the confusables in the
// substitution table.
func IsHomoglyph(r rune) bool {
	for _, subs := range homoglyphTable {
		for _, h := range subs {
			if h == r {
				return true
			}
		}
	}
	return false
}

// zeroWidthChars are the codepoints ZeroWidthInsert injects. Every
// one of them renders as invisible width in modern browsers and
// terminals, and several are commonly used in real-world phishing
// to defeat keyword-based filters.
var zeroWidthChars = []rune{
	'\u200B', // zero-width space
	'\u200C', // zero-width non-joiner
	'\u200D', // zero-width joiner
	'\uFEFF', // zero-width no-break space (BOM)
}

// ZeroWidthInsert returns s with zero-width characters inserted at
// random positions. count is the number of insertions; the PRNG
// picks both the position and which zero-width codepoint to insert.
// A count of 0 or a negative value yields s unchanged.
//
// The function is rune-aware: positions are measured in runes, not
// bytes, so multi-byte UTF-8 sequences in s are never split.
func ZeroWidthInsert(s string, rng *rand.Rand, count int) string {
	if count <= 0 || s == "" {
		return s
	}
	runes := []rune(s)
	// Cap the insertion count at len(runes)+1 so we never attempt
	// to insert at a position past the end of the string.
	if count > len(runes)+1 {
		count = len(runes) + 1
	}
	type insertion struct {
		pos int
		ch  rune
	}
	insertions := make([]insertion, count)
	for i := 0; i < count; i++ {
		insertions[i] = insertion{
			pos: rng.IntN(len(runes) + 1),
			ch:  zeroWidthChars[rng.IntN(len(zeroWidthChars))],
		}
	}
	// Sort insertions by position descending so they apply in
	// reverse order — this means later insertions don't shift the
	// indices of earlier ones.
	for i := 1; i < len(insertions); i++ {
		for j := i; j > 0 && insertions[j-1].pos < insertions[j].pos; j-- {
			insertions[j-1], insertions[j] = insertions[j], insertions[j-1]
		}
	}
	out := make([]rune, 0, len(runes)+count)
	out = append(out, runes...)
	for _, ins := range insertions {
		out = append(out[:ins.pos], append([]rune{ins.ch}, out[ins.pos:]...)...)
	}
	return string(out)
}

// ContainsZeroWidth reports whether s contains any of the zero-width
// codepoints ZeroWidthInsert emits. The property tests use it as
// the round-trip assertion.
func ContainsZeroWidth(s string) bool {
	for _, r := range s {
		for _, z := range zeroWidthChars {
			if r == z {
				return true
			}
		}
	}
	return false
}

// StripZeroWidth returns s with every zero-width codepoint removed.
// Useful both for the round-trip test (HomoglyphSubstitute followed
// by NFKD restores the ASCII; ZeroWidthInsert followed by StripZeroWidth
// restores the original) and as a reference implementation for any
// future pipeline-side normaliser.
func StripZeroWidth(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		zero := false
		for _, z := range zeroWidthChars {
			if r == z {
				zero = true
				break
			}
		}
		if !zero {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// urlPattern matches HTTP / HTTPS URLs in a body. The regex is
// intentionally permissive — the production URL scanner has a
// stricter parser; the goal here is to find URLs to obfuscate, not
// to validate them.
var urlPattern = regexp.MustCompile(`https?://[^\s<>")]+`)

// Base64ObfuscateURL returns rfc822 with every http(s) URL in the
// body rewritten into one of three obfuscation forms, selected by
// the PRNG:
//
//  1. data:text/html;base64,<base64 of '<a href="<URL>">click</a>'>
//  2. https://example.com/redirect?u=<base64 of URL>
//  3. <a href="javascript:window.location.href=atob('<base64 URL>')">click</a>
//
// All three are real obfuscation techniques observed in modern
// phishing campaigns. The headers are left untouched so the
// resulting message remains parseable.
func Base64ObfuscateURL(rfc822 string, rng *rand.Rand) string {
	// Split header / body on the first blank line. RFC822 mandates
	// CRLF CRLF; net/mail also accepts bare LF LF in practice.
	idx := strings.Index(rfc822, "\r\n\r\n")
	sep := "\r\n\r\n"
	if idx < 0 {
		idx = strings.Index(rfc822, "\n\n")
		sep = "\n\n"
	}
	if idx < 0 {
		// No body — treat the whole thing as body.
		return rewriteBodyURLs(rfc822, rng)
	}
	header := rfc822[:idx]
	body := rfc822[idx+len(sep):]
	return header + sep + rewriteBodyURLs(body, rng)
}

func rewriteBodyURLs(body string, rng *rand.Rand) string {
	return urlPattern.ReplaceAllStringFunc(body, func(match string) string {
		choice := rng.IntN(3)
		encoded := base64.StdEncoding.EncodeToString([]byte(match))
		switch choice {
		case 0:
			snippet := fmt.Sprintf(`<a href="%s">click</a>`, match)
			return "data:text/html;base64," + base64.StdEncoding.EncodeToString([]byte(snippet))
		case 1:
			return "https://r.example/redir?u=" + url.QueryEscape(encoded)
		default:
			return fmt.Sprintf(`<a href="javascript:window.location.href=atob('%s')">click</a>`, encoded)
		}
	})
}

// ExtractObfuscatedURLs reverses the encoding applied by
// Base64ObfuscateURL: it walks the body, finds the three obfuscation
// shapes, base64-decodes the payload, and returns the recovered URLs.
// Used by the property tests to assert the obfuscation is reversible
// (round-trip property).
func ExtractObfuscatedURLs(rfc822 string) []string {
	var out []string
	// data:text/html;base64,<b64>
	dataRe := regexp.MustCompile(`data:text/html;base64,([A-Za-z0-9+/=]+)`)
	for _, m := range dataRe.FindAllStringSubmatch(rfc822, -1) {
		decoded, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			continue
		}
		// The payload was '<a href="<URL>">click</a>'; recover URL.
		s := string(decoded)
		hrefRe := regexp.MustCompile(`href="([^"]+)"`)
		if hm := hrefRe.FindStringSubmatch(s); len(hm) == 2 {
			out = append(out, hm[1])
		}
	}
	// https://r.example/redir?u=<urlencoded(b64)>
	redirRe := regexp.MustCompile(`https://r\.example/redir\?u=([A-Za-z0-9%+/=]+)`)
	for _, m := range redirRe.FindAllStringSubmatch(rfc822, -1) {
		raw, err := url.QueryUnescape(m[1])
		if err != nil {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			continue
		}
		out = append(out, string(decoded))
	}
	// javascript:atob('<b64>')
	jsRe := regexp.MustCompile(`javascript:window\.location\.href=atob\('([A-Za-z0-9+/=]+)'\)`)
	for _, m := range jsRe.FindAllStringSubmatch(rfc822, -1) {
		decoded, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			continue
		}
		out = append(out, string(decoded))
	}
	return out
}

// MIMEMultipartSmuggle wraps rfc822's body in a nested multipart
// envelope with conflicting boundary declarations. The result is a
// well-formed-enough message that net/mail.ReadMessage accepts it,
// but the body contains a smuggled part that uses a boundary OTHER
// than the one declared in the Content-Type header — i.e. exactly
// the class of attack where two different MIME parsers (e.g. the
// Tier 0 scanner and the rendering layer) disagree about which
// part is "the body".
//
// rng is consulted to select a boundary string from a fixed pool so
// each invocation produces a deterministic-but-different envelope.
// The returned message has a multipart/mixed Content-Type with
// outer boundary B1; the body contains a part declared with
// boundary B2 (and a closing --B1-- that the smuggled part is
// embedded within). A robust scanner notices the mismatch; a naive
// one parses only the outer envelope and never sees the smuggled
// content.
func MIMEMultipartSmuggle(rfc822 string, rng *rand.Rand) string {
	boundaries := []string{
		"----=_NextPart_001_001A",
		"----=_NextPart_001_002B",
		"=====sn360-mixed=====",
		"=====sn360-alt=====",
		"--boundary-aaa",
		"--boundary-bbb",
	}
	outer := boundaries[rng.IntN(len(boundaries))]
	inner := boundaries[rng.IntN(len(boundaries))]
	// Force outer != inner so the smuggled boundary is always
	// genuinely conflicting. Loop until distinct: the previous
	// single-retry fallback (`(rng.IntN(N)+1)%N`) was also
	// uniform over all indices, so it had a 1/N chance of
	// landing back on `outer` — producing matching boundaries
	// ~1/6 of iterations and silently degrading the smuggling
	// scenario the test is supposed to exercise.
	for inner == outer {
		inner = boundaries[rng.IntN(len(boundaries))]
	}

	idx := strings.Index(rfc822, "\r\n\r\n")
	sep := "\r\n\r\n"
	if idx < 0 {
		idx = strings.Index(rfc822, "\n\n")
		sep = "\n\n"
	}
	var header, body string
	if idx < 0 {
		body = rfc822
	} else {
		header = rfc822[:idx]
		body = rfc822[idx+len(sep):]
	}

	// Strip any existing Content-Type header so the new
	// multipart wrapper isn't duplicated.
	header = stripHeader(header, "Content-Type")
	header = stripHeader(header, "Content-Transfer-Encoding")

	var b strings.Builder
	b.WriteString(header)
	if !strings.HasSuffix(header, "\r\n") && header != "" {
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n", outer)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString(sep)
	// Outer part: text/plain body (the original).
	fmt.Fprintf(&b, "--%s\r\n", outer)
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	// Smuggled inner part: declares its own boundary that DOES NOT
	// match the outer. A scanner that only follows the outer
	// boundary will treat the entire `inner` block as opaque
	// text; a scanner that descends will follow the inner
	// boundary into the smuggled payload.
	fmt.Fprintf(&b, "--%s\r\n", outer)
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", inner)
	fmt.Fprintf(&b, "--%s\r\n", inner)
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n\r\n")
	b.WriteString(`<html><body><a href="https://smuggled.example/login">Smuggled link</a></body></html>`)
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s--\r\n", inner)
	fmt.Fprintf(&b, "--%s--\r\n", outer)
	return b.String()
}

// stripHeader removes any header line matching name (case-insensitive).
// Header continuation lines (those starting with whitespace) are
// stripped along with the matching header.
func stripHeader(header, name string) string {
	if header == "" {
		return ""
	}
	lines := strings.Split(header, "\r\n")
	if len(lines) == 1 && strings.Contains(header, "\n") {
		lines = strings.Split(header, "\n")
	}
	out := make([]string, 0, len(lines))
	skip := false
	prefix := strings.ToLower(name) + ":"
	for _, ln := range lines {
		lower := strings.ToLower(strings.TrimSpace(ln))
		if strings.HasPrefix(lower, prefix) {
			skip = true
			continue
		}
		if skip && (strings.HasPrefix(ln, " ") || strings.HasPrefix(ln, "\t")) {
			continue
		}
		skip = false
		out = append(out, ln)
	}
	return strings.Join(out, "\r\n")
}

// HeaderInjection inserts a CRLF + a fake Received header into one
// of the existing header values. The result is parsed differently
// by RFC2822-strict parsers (which split the header) vs. lenient
// ones (which fold the new line into the existing value). This is
// the same family of attacks used to spoof Received chains in
// real-world abuse.
//
// The fake Received header is a forged "from internal.example by
// mailserver" line designed to make the message look like it
// originated inside the recipient tenant.
func HeaderInjection(rfc822 string, rng *rand.Rand) string {
	idx := strings.Index(rfc822, "\r\n\r\n")
	sep := "\r\n\r\n"
	if idx < 0 {
		idx = strings.Index(rfc822, "\n\n")
		sep = "\n\n"
	}
	if idx < 0 {
		// No body — append the forged header at the end.
		return rfc822 + "\r\nReceived: from internal.example (internal.example [192.0.2.1])\r\n\tby mailserver.example with SMTP id INJECTED;\r\n\tMon, 01 Jan 2026 00:00:00 +0000\r\n"
	}
	header := rfc822[:idx]
	body := rfc822[idx+len(sep):]
	lines := strings.Split(header, "\r\n")
	if len(lines) <= 1 {
		lines = strings.Split(header, "\n")
	}
	if len(lines) == 0 {
		return rfc822
	}
	// Pick a header to inject after.
	pos := rng.IntN(len(lines))
	forged := []string{
		"Received: from internal.example (internal.example [192.0.2.1])",
		"\tby mailserver.example with SMTP id INJECTED;",
		"\tMon, 01 Jan 2026 00:00:00 +0000",
	}
	out := append([]string{}, lines[:pos+1]...)
	out = append(out, forged...)
	out = append(out, lines[pos+1:]...)
	return strings.Join(out, "\r\n") + sep + body
}

// ContainsInjectedHeader reports whether s contains the marker
// HeaderInjection uses ("INJECTED;"). The property tests use it to
// assert that the injection actually took effect.
func ContainsInjectedHeader(s string) bool {
	return bytes.Contains([]byte(s), []byte("INJECTED;"))
}
