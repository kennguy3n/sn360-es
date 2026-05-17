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

// injectTypo swaps two adjacent characters in a random non-URL word.
// We operate on runes (not bytes) so multi-byte CJK / Thai text
// doesn't get truncated mid-codepoint. URLs are skipped so downstream
// URL signal extractors keep working.
func (n *noiseInjector) injectTypo(s string) string {
	fields := strings.Fields(s)
	if len(fields) < 3 {
		return s
	}
	for i := 0; i < 5; i++ {
		idx := n.rng.Intn(len(fields))
		w := fields[idx]
		if strings.HasPrefix(w, "http") || strings.ContainsAny(w, "@/:") {
			continue
		}
		runes := []rune(w)
		if len(runes) < 4 {
			continue
		}
		pos := n.rng.Intn(len(runes) - 1)
		runes[pos], runes[pos+1] = runes[pos+1], runes[pos]
		fields[idx] = string(runes)
		return strings.Join(fields, " ")
	}
	return s
}

// mixedCaseWord finds a random non-URL word and randomises its
// capitalisation. Useful as adversarial noise for the encoder.
func (n *noiseInjector) mixedCaseWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}
	for i := 0; i < 5; i++ {
		idx := n.rng.Intn(len(fields))
		w := fields[idx]
		if len(w) < 4 || strings.HasPrefix(w, "http") || strings.ContainsAny(w, "@/:") {
			continue
		}
		runes := []rune(w)
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
		fields[idx] = string(runes)
		return strings.Join(fields, " ")
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
