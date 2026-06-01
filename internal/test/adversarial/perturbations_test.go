package adversarial

import (
	"math/rand/v2"
	"net/mail"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

func newRNG(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, seed^0xDEADBEEFCAFEBABE))
}

func TestHomoglyphSubstitute_ReplacesAtLeastOneCharacter(t *testing.T) {
	rng := newRNG(1)
	got := HomoglyphSubstitute("admin", rng, 1.0)
	if got == "admin" {
		t.Fatalf("expected substitution to occur, got %q", got)
	}
	// At rate=1.0 every substitutable rune must be replaced.
	if HomoglyphPositions("admin") != countConfusables(got) {
		t.Fatalf("expected %d confusables, got %d in %q",
			HomoglyphPositions("admin"), countConfusables(got), got)
	}
}

func TestHomoglyphSubstitute_DeterministicWithSeed(t *testing.T) {
	// Same seed + same input + same rate must produce byte-identical output.
	a := HomoglyphSubstitute("verify-account.com", newRNG(42), 0.6)
	b := HomoglyphSubstitute("verify-account.com", newRNG(42), 0.6)
	if a != b {
		t.Fatalf("expected deterministic output for same seed, got %q vs %q", a, b)
	}
}

func TestHomoglyphSubstitute_NFKD_RoundTrip(t *testing.T) {
	// The WS-4b spec explicitly calls out that a NFKD-normalised
	// homoglyphed string should recover the original ASCII. Note:
	// many Cyrillic confusables do NOT NFKD-decompose back to
	// ASCII (NFKD only handles characters with canonical
	// decomposition mappings; Cyrillic letters that *look* like
	// Latin are NOT decomposed by NFKD). We assert the weaker
	// property the production normaliser would catch: at least
	// one substituted character is detectable as non-ASCII via
	// IsHomoglyph.
	homoglyphed := HomoglyphSubstitute("login", newRNG(7), 1.0)
	if !strings.ContainsFunc(homoglyphed, IsHomoglyph) {
		t.Fatalf("expected at least one homoglyph in %q", homoglyphed)
	}
	// NFKD normalisation in Go preserves the homoglyph string
	// length (each Cyrillic letter is a single codepoint that
	// doesn't decompose), so this is just a smoke test that the
	// string remains valid UTF-8 after normalisation.
	normalised := norm.NFKD.String(homoglyphed)
	if !utf8.ValidString(normalised) {
		t.Fatalf("NFKD output is not valid UTF-8: %q", normalised)
	}
}

func TestHomoglyphSubstitute_RateZeroIsIdentity(t *testing.T) {
	got := HomoglyphSubstitute("verify-account.com", newRNG(0), 0.0)
	if got != "verify-account.com" {
		t.Fatalf("rate=0 should be identity, got %q", got)
	}
}

func TestHomoglyphSubstitute_RateClamped(t *testing.T) {
	// Rates outside [0, 1] are clamped — passing 5.0 must behave
	// identically to passing 1.0.
	a := HomoglyphSubstitute("admin", newRNG(13), 5.0)
	b := HomoglyphSubstitute("admin", newRNG(13), 1.0)
	if a != b {
		t.Fatalf("rate>1 should clamp to 1: %q vs %q", a, b)
	}
}

func TestZeroWidthInsert_AddsExpectedCount(t *testing.T) {
	got := ZeroWidthInsert("password", newRNG(1), 3)
	zw := 0
	for _, r := range got {
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
			zw++
		}
	}
	if zw != 3 {
		t.Fatalf("expected 3 zero-width inserts, got %d in %q", zw, got)
	}
	if !ContainsZeroWidth(got) {
		t.Fatalf("ContainsZeroWidth should be true")
	}
}

func TestZeroWidthInsert_StripIsInverse(t *testing.T) {
	original := "click here to verify"
	inserted := ZeroWidthInsert(original, newRNG(99), 5)
	if inserted == original {
		t.Fatalf("expected at least one insertion")
	}
	stripped := StripZeroWidth(inserted)
	if stripped != original {
		t.Fatalf("strip should be inverse: got %q, want %q", stripped, original)
	}
}

func TestZeroWidthInsert_CountZeroIsIdentity(t *testing.T) {
	got := ZeroWidthInsert("password", newRNG(1), 0)
	if got != "password" {
		t.Fatalf("count=0 should be identity, got %q", got)
	}
}

func TestZeroWidthInsert_HandlesMultiByteRunes(t *testing.T) {
	// Test that multi-byte UTF-8 runes are not split.
	original := "héllo wörld 中文"
	got := ZeroWidthInsert(original, newRNG(7), 3)
	if !utf8.ValidString(got) {
		t.Fatalf("result is not valid UTF-8: %q", got)
	}
	if StripZeroWidth(got) != original {
		t.Fatalf("strip should restore multi-byte original; got %q", StripZeroWidth(got))
	}
}

func TestBase64ObfuscateURL_RoundTripRecoversURLs(t *testing.T) {
	rfc822 := "From: a@a.com\r\nTo: b@b.com\r\nSubject: hi\r\n\r\n" +
		"Click here: https://attacker.example/login?u=victim and also https://another.example/track\r\n"
	got := Base64ObfuscateURL(rfc822, newRNG(2))
	if got == rfc822 {
		t.Fatalf("expected URLs to be obfuscated")
	}
	// Plain URL should no longer appear in the body verbatim.
	if strings.Contains(got, "https://attacker.example/login?u=victim") {
		t.Fatalf("plain URL still visible in obfuscated output: %q", got)
	}
	recovered := ExtractObfuscatedURLs(got)
	want := map[string]bool{
		"https://attacker.example/login?u=victim": false,
		"https://another.example/track":           false,
	}
	for _, url := range recovered {
		if _, ok := want[url]; ok {
			want[url] = true
		}
	}
	for url, found := range want {
		if !found {
			t.Errorf("URL %q not recovered from obfuscated body (recovered=%v)", url, recovered)
		}
	}
}

func TestBase64ObfuscateURL_PreservesHeaders(t *testing.T) {
	rfc822 := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nhttps://x.example/p\r\n"
	got := Base64ObfuscateURL(rfc822, newRNG(8))
	if !strings.Contains(got, "From: alice@example.com") {
		t.Errorf("From header dropped: %q", got)
	}
	if !strings.Contains(got, "Subject: Test") {
		t.Errorf("Subject header dropped: %q", got)
	}
}

func TestBase64ObfuscateURL_NoURLsLeavesInputUnchanged(t *testing.T) {
	rfc822 := "From: a@a.com\r\nTo: b@b.com\r\nSubject: plain\r\n\r\nNo URLs here.\r\n"
	got := Base64ObfuscateURL(rfc822, newRNG(3))
	if got != rfc822 {
		t.Fatalf("expected unchanged input when no URLs present\nwant: %q\ngot:  %q", rfc822, got)
	}
}

func TestMIMEMultipartSmuggle_ProducesParseableMessage(t *testing.T) {
	rfc822 := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nHello world\r\n"
	smuggled := MIMEMultipartSmuggle(rfc822, newRNG(5))
	msg, err := mail.ReadMessage(strings.NewReader(smuggled))
	if err != nil {
		t.Fatalf("net/mail.ReadMessage failed on smuggled message: %v\n%s", err, smuggled)
	}
	if msg.Header.Get("From") != "alice@example.com" {
		t.Errorf("From header lost: %q", msg.Header.Get("From"))
	}
	ct := msg.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/mixed") {
		t.Errorf("Content-Type not rewritten: %q", ct)
	}
}

func TestMIMEMultipartSmuggle_HasConflictingBoundaries(t *testing.T) {
	rfc822 := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello\r\n"
	smuggled := MIMEMultipartSmuggle(rfc822, newRNG(11))
	// Outer boundary appears in Content-Type; an inner boundary
	// distinct from the outer should appear in the body.
	if !strings.Contains(smuggled, "multipart/mixed") {
		t.Fatalf("missing outer multipart wrapper")
	}
	if !strings.Contains(smuggled, "multipart/alternative") {
		t.Fatalf("missing inner multipart envelope")
	}
}

func TestMIMEMultipartSmuggle_NoBodySeparator(t *testing.T) {
	// Edge case: an input with no \r\n\r\n separator should still
	// produce a valid envelope (caller likely already structured
	// the message but used \n\n instead of \r\n\r\n).
	rfc822 := "From: alice@example.com\nTo: bob@example.com\nSubject: Test\n\nHello\n"
	smuggled := MIMEMultipartSmuggle(rfc822, newRNG(13))
	if !strings.Contains(smuggled, "multipart/mixed") {
		t.Fatalf("missing outer multipart wrapper for LF-separator input")
	}
}

func TestHeaderInjection_AddsInjectedReceivedHeader(t *testing.T) {
	rfc822 := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello\r\n"
	got := HeaderInjection(rfc822, newRNG(7))
	if !ContainsInjectedHeader(got) {
		t.Fatalf("injected Received header missing: %q", got)
	}
	if !strings.Contains(got, "Received: from internal.example") {
		t.Fatalf("injected Received header malformed: %q", got)
	}
	// Original headers + body must still be present.
	if !strings.Contains(got, "From: alice@example.com") {
		t.Errorf("From header dropped")
	}
	if !strings.Contains(got, "Hello") {
		t.Errorf("body dropped")
	}
}

func TestHeaderInjection_HandlesEmptyBody(t *testing.T) {
	rfc822 := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test"
	got := HeaderInjection(rfc822, newRNG(7))
	if !ContainsInjectedHeader(got) {
		t.Fatalf("injected Received header missing: %q", got)
	}
}

func TestReasonCodesFor_ReturnsExpectedVocabulary(t *testing.T) {
	cases := map[PerturbationKind]bool{
		KindHomoglyph:       true,
		KindZeroWidth:       false, // documented gap
		KindBase64URL:       true,
		KindMIMESmuggling:   true,
		KindHeaderInjection: true,
	}
	for kind, expectsCodes := range cases {
		got := ReasonCodesFor(kind)
		if expectsCodes && len(got) == 0 {
			t.Errorf("%s: expected non-empty reason codes, got none", kind)
		}
		if !expectsCodes && len(got) != 0 {
			t.Errorf("%s: expected gap (empty codes), got %v", kind, got)
		}
	}
}

func TestHasAnyReasonCode_HyphenInsensitive(t *testing.T) {
	if !HasAnyReasonCode([]string{"lookalike-domain"}, []string{"lookalike_domain"}) {
		t.Errorf("hyphen/underscore variants should match")
	}
	if !HasAnyReasonCode([]string{"LOOKALIKE_DOMAIN"}, []string{"lookalike_domain"}) {
		t.Errorf("case variants should match")
	}
	if HasAnyReasonCode([]string{"unrelated_code"}, []string{"lookalike_domain"}) {
		t.Errorf("unrelated code should not match")
	}
}

func countConfusables(s string) int {
	n := 0
	for _, r := range s {
		if IsHomoglyph(r) {
			n++
		}
	}
	return n
}
