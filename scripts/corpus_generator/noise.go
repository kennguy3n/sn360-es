package main

import (
	"math/rand"
	"strings"
	"unicode"

	"github.com/kennguy3n/sn360-es/scripts/corpus_generator/templates"
)

// noiseInjector applies controlled, deterministic perturbations to a
// generated payload so adjacent test emails don't read like exact
// copies. Every transformation is keyed on the generator's *rand.Rand
// so the same seed always reproduces the same corpus.
type noiseInjector struct {
	rng *rand.Rand
}

// newNoiseInjector returns a fresh injector keyed by rng.
func newNoiseInjector(rng *rand.Rand) *noiseInjector {
	return &noiseInjector{rng: rng}
}

// apply mutates payload in place. The locale determines greeting and
// sign-off style; level controls how aggressive perturbations are.
//
// easy : add greeting + sign-off only.
// medium: greeting + sign-off + 0-1 whitespace tweaks.
// hard  : greeting + sign-off + whitespace tweaks + 1-2 typos +
//
//	mixed-case capitalisation on a random word.
//
// apply NEVER drops or rewrites attachments / headers — those carry
// the detection signals.
func (n *noiseInjector) apply(p *templates.Payload, level templates.Level, loc templates.Locale) {
	pool := poolFor(loc)
	p.BodyText = n.prependGreeting(p.BodyText, pool)
	p.BodyText = n.appendSignOff(p.BodyText, pool)

	if level == templates.LevelEasy {
		return
	}

	// medium: 0-1 whitespace tweaks
	if n.rng.Intn(2) == 0 {
		p.BodyText = n.tweakWhitespace(p.BodyText)
	}
	if level == templates.LevelMedium {
		return
	}

	// hard: extra typos + mixed-case word
	for i := 0; i < n.rng.Intn(2)+1; i++ {
		p.BodyText = n.injectTypo(p.BodyText)
	}
	p.BodyText = n.mixedCaseWord(p.BodyText)
}

// prependGreeting puts a locale-appropriate greeting at the top of the
// body if one is not already present.
func (n *noiseInjector) prependGreeting(body string, pool localePools) string {
	greeting := pickFromPool(n.rng, pool.Greetings)
	trimmed := strings.TrimLeft(body, " \t\r\n")
	// If body already starts with the chosen greeting, don't duplicate.
	if strings.HasPrefix(trimmed, greeting) {
		return body
	}
	return greeting + ",\n\n" + body
}

// appendSignOff appends a locale-appropriate sign-off plus signature
// block if the body doesn't already end with one.
func (n *noiseInjector) appendSignOff(body string, pool localePools) string {
	signoff := pickFromPool(n.rng, pool.SignOffs)
	sig := pickFromPool(n.rng, pool.Signatures)
	trimmed := strings.TrimRight(body, " \t\r\n")
	if strings.HasSuffix(trimmed, signoff) {
		return body
	}
	return trimmed + "\n\n" + signoff + ",\n" + sig
}

// tweakWhitespace inserts a single extra space at one of the
// existing space positions in s. We pick from the set of byte indices
// where s[i] == ' ' so we never split a multi-byte rune.
func (n *noiseInjector) tweakWhitespace(s string) string {
	positions := make([]int, 0, 16)
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			positions = append(positions, i)
		}
	}
	if len(positions) == 0 {
		return s
	}
	mid := positions[n.rng.Intn(len(positions))]
	return s[:mid] + " " + s[mid:]
}

// injectTypo swaps two adjacent runes in a random non-URL word.
// Whitespace structure (newlines, paragraph breaks, tabs) is
// preserved: we locate word byte spans and splice the modified word
// back into the original string at its exact original offset. URLs
// (anything starting with http / containing @, /, or :) are skipped
// so downstream URL signal extractors keep working.
func (n *noiseInjector) injectTypo(s string) string {
	spans := wordSpans(s)
	if len(spans) < 3 {
		return s
	}
	for i := 0; i < 5; i++ {
		sp := spans[n.rng.Intn(len(spans))]
		w := s[sp.start:sp.end]
		if !typoable(w) {
			continue
		}
		runes := []rune(w)
		if len(runes) < 4 {
			continue
		}
		pos := n.rng.Intn(len(runes) - 1)
		runes[pos], runes[pos+1] = runes[pos+1], runes[pos]
		return s[:sp.start] + string(runes) + s[sp.end:]
	}
	return s
}

// mixedCaseWord finds a random non-URL word and randomises its
// capitalisation. Whitespace structure is preserved by splicing the
// rewritten word back at its original byte offset.
func (n *noiseInjector) mixedCaseWord(s string) string {
	spans := wordSpans(s)
	if len(spans) == 0 {
		return s
	}
	for i := 0; i < 5; i++ {
		sp := spans[n.rng.Intn(len(spans))]
		w := s[sp.start:sp.end]
		if !typoable(w) {
			continue
		}
		runes := []rune(w)
		if len(runes) < 4 {
			continue
		}
		for j, r := range runes {
			if !unicode.IsLetter(r) {
				continue
			}
			if (j+n.rng.Intn(3))%2 == 0 {
				runes[j] = unicode.ToUpper(r)
			} else {
				runes[j] = unicode.ToLower(r)
			}
		}
		return s[:sp.start] + string(runes) + s[sp.end:]
	}
	return s
}

// wordSpan is a half-open [start, end) byte range pointing at a
// non-whitespace run inside the original string.
type wordSpan struct {
	start, end int
}

// wordSpans scans s once and returns the byte ranges of every
// maximal non-whitespace run. We operate on bytes (not runes) so the
// returned offsets can be spliced directly back into s. Multi-byte
// runes never get split because the only thing we look at is whether
// each byte is a whitespace separator.
func wordSpans(s string) []wordSpan {
	out := make([]wordSpan, 0, 32)
	start := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if start >= 0 {
				out = append(out, wordSpan{start: start, end: i})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, wordSpan{start: start, end: len(s)})
	}
	return out
}

// typoable reports whether w is a "plain word" we're willing to
// rewrite. URLs, emails, and tokens with structural punctuation are
// rejected so we don't mutate signals downstream extractors rely on.
func typoable(w string) bool {
	if strings.HasPrefix(w, "http") {
		return false
	}
	if strings.ContainsAny(w, "@/:") {
		return false
	}
	return true
}
