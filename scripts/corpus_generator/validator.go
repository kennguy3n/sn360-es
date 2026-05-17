package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/scripts/corpus_generator/templates"
)

// ValidationReport summarises corpus health. OK is true iff every
// check passed.
type ValidationReport struct {
	OK             bool
	TotalEmails    int
	CategoryCounts map[constant.Category]int
	DifficultyMix  map[constant.Category]map[templates.Level]int
	LocaleMix      map[templates.Locale]int
	NearDuplicates int
	Errors         []string
	Warnings       []string
}

// Render returns a human-readable textual summary for stdout / CI logs.
func (r *ValidationReport) Render() string {
	var b strings.Builder
	b.WriteString("Corpus validation report\n")
	b.WriteString("------------------------\n")
	fmt.Fprintf(&b, "Total emails: %d\n", r.TotalEmails)
	b.WriteString("Per-category counts:\n")
	cats := make([]constant.Category, 0, len(r.CategoryCounts))
	for c := range r.CategoryCounts {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool { return string(cats[i]) < string(cats[j]) })
	for _, c := range cats {
		fmt.Fprintf(&b, "  %-30s %d\n", c, r.CategoryCounts[c])
	}
	b.WriteString("Locale mix:\n")
	locs := make([]templates.Locale, 0, len(r.LocaleMix))
	for l := range r.LocaleMix {
		locs = append(locs, l)
	}
	sort.Slice(locs, func(i, j int) bool { return string(locs[i]) < string(locs[j]) })
	for _, l := range locs {
		fmt.Fprintf(&b, "  %-4s %d\n", l, r.LocaleMix[l])
	}
	fmt.Fprintf(&b, "Near-duplicate pairs flagged: %d\n", r.NearDuplicates)
	if len(r.Warnings) > 0 {
		b.WriteString("Warnings:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  - %s\n", w)
		}
	}
	if len(r.Errors) > 0 {
		b.WriteString("Errors:\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "  - %s\n", e)
		}
	}
	if r.OK {
		b.WriteString("Status: OK\n")
	} else {
		b.WriteString("Status: FAILED\n")
	}
	return b.String()
}

// ValidateCorpus reads dir, runs the full battery of checks, and
// returns a report. Errors short-circuit individual checks but do
// not stop the validator from continuing.
func ValidateCorpus(dir string) (*ValidationReport, error) {
	emails, err := loadCorpus(dir)
	if err != nil {
		return nil, err
	}
	return ValidateEmails(emails), nil
}

// ValidateEmails runs the validator on an in-memory corpus. Useful in
// unit tests and for sample.json smoke-checks during CI.
func ValidateEmails(emails []TestEmail) *ValidationReport {
	rep := &ValidationReport{
		OK:             true,
		TotalEmails:    len(emails),
		CategoryCounts: make(map[constant.Category]int),
		DifficultyMix:  make(map[constant.Category]map[templates.Level]int),
		LocaleMix:      make(map[templates.Locale]int),
	}

	ids := make(map[string]struct{}, len(emails))
	shingles := make(map[constant.Category][]map[string]struct{})

	for i, e := range emails {
		// Required-field & enum checks.
		if e.TestID == "" {
			rep.addErr(fmt.Sprintf("email[%d]: missing test_id", i))
		} else if _, dup := ids[e.TestID]; dup {
			rep.addErr(fmt.Sprintf("email[%d]: duplicate test_id %q", i, e.TestID))
		} else {
			ids[e.TestID] = struct{}{}
		}
		if !e.Category.Valid() {
			rep.addErr(fmt.Sprintf("%s: invalid category %q", e.TestID, e.Category))
		}
		if !e.ExpectedTier.Valid() {
			rep.addErr(fmt.Sprintf("%s: invalid expected_tier %q", e.TestID, e.ExpectedTier))
		}
		if !validLevel(e.Difficulty) {
			rep.addErr(fmt.Sprintf("%s: invalid difficulty %q", e.TestID, e.Difficulty))
		}
		if !validLocale(e.Locale) {
			rep.addErr(fmt.Sprintf("%s: invalid locale %q", e.TestID, e.Locale))
		}
		if !validVerdict(e.ExpectedTier1Verdict) {
			rep.addErr(fmt.Sprintf("%s: invalid expected_tier1_verdict %q", e.TestID, e.ExpectedTier1Verdict))
		}

		// Score-tier consistency.
		if !scoreMatchesTier(e.ExpectedTier, e.ExpectedScoreRange) {
			rep.addErr(fmt.Sprintf("%s: score range %v inconsistent with tier %s", e.TestID, e.ExpectedScoreRange, e.ExpectedTier))
		}

		// Pipeline contract: bypass implies skip + no tier 2.
		if e.Tier0Bypass {
			if e.ExpectedTier1Verdict != "skip" {
				rep.addErr(fmt.Sprintf("%s: tier0_bypass=true but tier1_verdict=%q", e.TestID, e.ExpectedTier1Verdict))
			}
			if e.ExpectedTier2Needed {
				rep.addErr(fmt.Sprintf("%s: tier0_bypass=true must imply tier2_needed=false", e.TestID))
			}
		}
		if e.ExpectedTier1Verdict == "pass" && e.ExpectedTier2Needed {
			rep.addErr(fmt.Sprintf("%s: tier1=pass must imply tier2_needed=false", e.TestID))
		}
		// Tier 2 category consistency.
		if e.ExpectedTier2Needed {
			if len(e.ExpectedTier2Categories) == 0 && e.IsThreat {
				rep.addErr(fmt.Sprintf("%s: tier2_needed but expected_tier2_categories empty", e.TestID))
			}
			for _, c := range e.ExpectedTier2Categories {
				if !c.Valid() {
					rep.addErr(fmt.Sprintf("%s: invalid tier2 category %q", e.TestID, c))
				}
			}
		}

		// Payload sanity.
		if e.Payload.From == "" || e.Payload.To == "" || e.Payload.Subject == "" || e.Payload.BodyText == "" {
			rep.addErr(fmt.Sprintf("%s: payload missing required field(s)", e.TestID))
		}

		// Accumulate distribution counters.
		rep.CategoryCounts[e.Category]++
		if rep.DifficultyMix[e.Category] == nil {
			rep.DifficultyMix[e.Category] = make(map[templates.Level]int)
		}
		rep.DifficultyMix[e.Category][e.Difficulty]++
		rep.LocaleMix[e.Locale]++

		// Shingles for dedup.
		shingles[e.Category] = append(shingles[e.Category], trigramShingle(e.Payload.BodyText))
	}

	// Distribution checks: at least 1 per category, ≥10% non-English per
	// locale-bearing corpus. Production target is ≥300 per category but
	// we warn rather than fail so small smoke runs still pass.
	for _, c := range constant.AllCategories {
		if rep.CategoryCounts[c] == 0 {
			rep.addErr(fmt.Sprintf("category %s has zero emails", c))
		} else if rep.CategoryCounts[c] < 300 {
			rep.addWarn(fmt.Sprintf("category %s has only %d emails (target ≥300)", c, rep.CategoryCounts[c]))
		}
	}
	for _, l := range []templates.Locale{templates.LocaleTH, templates.LocaleJA, templates.LocaleKO, templates.LocaleZH, templates.LocaleVI} {
		pct := 0
		if rep.TotalEmails > 0 {
			pct = rep.LocaleMix[l] * 100 / rep.TotalEmails
		}
		if pct < 3 && rep.TotalEmails >= 1000 {
			rep.addWarn(fmt.Sprintf("locale %s only %d%% of corpus (target ≥3%%)", l, pct))
		}
	}

	// Dedup: any pair of bodies in the same category with Jaccard > 0.9
	// on word trigrams.
	for cat, sets := range shingles {
		for i := 0; i < len(sets); i++ {
			for j := i + 1; j < len(sets); j++ {
				if jaccard(sets[i], sets[j]) > 0.9 {
					rep.NearDuplicates++
					if rep.NearDuplicates <= 5 {
						rep.addWarn(fmt.Sprintf("near-duplicate bodies in %s at indices %d,%d", cat, i, j))
					}
				}
			}
		}
	}
	if rep.NearDuplicates > 50 {
		rep.addErr(fmt.Sprintf("%d near-duplicate body pairs detected", rep.NearDuplicates))
	}

	rep.OK = len(rep.Errors) == 0
	return rep
}

func (r *ValidationReport) addErr(s string) {
	r.Errors = append(r.Errors, s)
	r.OK = false
}

func (r *ValidationReport) addWarn(s string) {
	r.Warnings = append(r.Warnings, s)
}

func validLevel(l templates.Level) bool {
	switch l {
	case templates.LevelEasy, templates.LevelMedium, templates.LevelHard:
		return true
	}
	return false
}

func validLocale(l templates.Locale) bool {
	switch l {
	case templates.LocaleEN, templates.LocaleTH, templates.LocaleJA,
		templates.LocaleKO, templates.LocaleZH, templates.LocaleVI:
		return true
	}
	return false
}

func validVerdict(v string) bool {
	switch v {
	case "pass", "escalate", "flag", "skip":
		return true
	}
	return false
}

// scoreMatchesTier validates [low, high] sits inside the tier band
// defined by the config defaults (Blocked 85-100, etc.).
func scoreMatchesTier(t constant.Tier, span [2]int) bool {
	lo, hi := span[0], span[1]
	if lo < 0 || hi > 100 || lo > hi {
		return false
	}
	bLo, bHi := tierBand(t)
	return lo >= bLo && hi <= bHi
}

func tierBand(t constant.Tier) (int, int) {
	switch t {
	case constant.TierBlocked:
		return 85, 100
	case constant.TierHighRisk:
		return 70, 84
	case constant.TierWarning:
		return 50, 69
	case constant.TierCaution:
		return 30, 49
	case constant.TierInformational:
		return 15, 29
	case constant.TierTrusted:
		return 0, 14
	default:
		return 0, 0
	}
}

// trigramShingle returns the set of word-trigrams in s. Stable
// hashing (sha1[:8]) keeps the set compact for the dedup loop.
func trigramShingle(s string) map[string]struct{} {
	words := strings.Fields(strings.ToLower(s))
	out := make(map[string]struct{})
	if len(words) < 3 {
		for _, w := range words {
			out[w] = struct{}{}
		}
		return out
	}
	for i := 0; i <= len(words)-3; i++ {
		tri := strings.Join(words[i:i+3], " ")
		sum := sha1.Sum([]byte(tri))
		out[hex.EncodeToString(sum[:8])] = struct{}{}
	}
	return out
}

func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}
