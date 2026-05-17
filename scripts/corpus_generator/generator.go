package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/scripts/corpus_generator/templates"
)

// Generator orchestrates corpus production. It enumerates each
// requested category, splits malicious/benign per category metadata,
// distributes difficulty and locale per CLI ratios, and invokes the
// matching templates.Generator. Output is one JSON file per category
// plus an aggregated all.json in opts.OutputDir.
type Generator struct {
	opts   GenerateOptions
	llm    *LLMClient // nil unless --llm-assist
	noise  *noiseInjector
	rng    *rand.Rand
	tenant string
}

// NewGenerator returns a Generator wired up with opts. The PRNG is
// seeded from opts.Seed so two runs with the same seed produce
// byte-identical corpora.
func NewGenerator(opts GenerateOptions) *Generator {
	rng := rand.New(rand.NewSource(opts.Seed))
	return &Generator{
		opts:   opts,
		rng:    rng,
		noise:  newNoiseInjector(rng),
		tenant: "acme.example",
	}
}

// WithLLMAssist enables Ternary-Bonsai-8B-assisted generation for the
// hard-to-template categories (BEC_IMPERSONATION, VENDOR_COMPROMISE,
// ACCOUNT_TAKEOVER_SUSPECTED). When the LLM returns an error, the
// generator falls back to the deterministic template so a missing LLM
// never breaks corpus generation.
func (g *Generator) WithLLMAssist(client *LLMClient) {
	g.llm = client
}

// Run produces the corpus and writes it to disk. It returns the first
// error encountered; partial output may exist on failure.
func (g *Generator) Run() error {
	if err := os.MkdirAll(g.opts.OutputDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", g.opts.OutputDir, err)
	}
	all := make([]TestEmail, 0, g.opts.CountPerCategory*len(g.opts.Categories))

	for _, cat := range g.opts.Categories {
		gen, ok := g.opts.Registry.Get(cat)
		if !ok {
			return fmt.Errorf("no generator registered for %s", cat)
		}
		emails, err := g.runCategory(cat, gen)
		if err != nil {
			return fmt.Errorf("category %s: %w", cat, err)
		}
		if err := g.writeCategory(cat, emails); err != nil {
			return err
		}
		all = append(all, emails...)
	}

	return g.writeFile(filepath.Join(g.opts.OutputDir, "all.json"), all)
}

// runCategory generates the configured number of emails for cat.
func (g *Generator) runCategory(cat constant.Category, tg templates.Generator) ([]TestEmail, error) {
	count := g.opts.CountPerCategory
	threatPct := threatPercentFor(cat)
	threatCount := count * threatPct / 100

	emails := make([]TestEmail, 0, count)
	for i := 0; i < count; i++ {
		isThreat := i < threatCount
		difficulty := g.pickDifficulty(i, threatCount, count)
		locale := g.pickLocale()

		topts := templates.Options{
			Rand:       g.rng,
			IsThreat:   isThreat,
			Difficulty: difficulty,
			Locale:     locale,
			Index:      i,
			Tenant:     g.tenant,
		}
		result := tg.Generate(topts)
		if g.llm != nil && llmAssistCategory(cat) {
			if augmented, ok := g.llm.Augment(cat, topts, result); ok {
				result = augmented
			}
		}
		g.noise.apply(&result.Payload, difficulty, locale)
		email := g.composeEmail(cat, result, topts)
		emails = append(emails, email)
	}
	return emails, nil
}

// composeEmail builds the canonical TestEmail value, applying the
// category × is_threat × difficulty rules described in section 6 of
// the task. The returned TestEmail is the on-disk JSON shape.
func (g *Generator) composeEmail(cat constant.Category, r templates.Result, opts templates.Options) TestEmail {
	tier, lo, hi := tierAndScoreFor(cat, opts.IsThreat, opts.Difficulty)
	bypass := tier0BypassFor(cat, opts.IsThreat)
	tier1Verdict := tier1VerdictFor(bypass, opts.IsThreat, opts.Difficulty)
	tier2Needed := tier2NeededFor(bypass, tier1Verdict)
	tier2Cats := tier2CategoriesFor(cat, tier2Needed, opts.IsThreat)

	return TestEmail{
		TestID:                  buildTestID(cat, opts.Index),
		Category:                cat,
		ExpectedTier:            tier,
		ExpectedScoreRange:      [2]int{lo, hi},
		IsThreat:                opts.IsThreat,
		Difficulty:              opts.Difficulty,
		Locale:                  opts.Locale,
		AttackType:              r.AttackType,
		Description:             r.Description,
		ExpectedSignals:         dedupStrings(r.ExpectedSignals),
		Tier0Bypass:             bypass,
		ExpectedTier1Verdict:    tier1Verdict,
		ExpectedTier2Needed:     tier2Needed,
		ExpectedTier2Categories: tier2Cats,
		Payload:                 r.Payload,
	}
}

// pickDifficulty distributes difficulty levels according to the
// configured DifficultyPct, ensuring every email gets a deterministic
// pick. We use modular arithmetic instead of randomness so the split
// is exact and reproducible per index.
func (g *Generator) pickDifficulty(i, _, count int) templates.Level {
	if count == 0 {
		return templates.LevelMedium
	}
	pos := i * 100 / count // 0..99
	easyCut := g.opts.DifficultyPct[0]
	medCut := easyCut + g.opts.DifficultyPct[1]
	switch {
	case pos < easyCut:
		return templates.LevelEasy
	case pos < medCut:
		return templates.LevelMedium
	default:
		return templates.LevelHard
	}
}

// pickLocale draws a locale according to weighted bins. The PRNG is
// the only randomness here so the locale mix matches the configured
// split across enough samples.
func (g *Generator) pickLocale() templates.Locale {
	weights := g.opts.LocaleWeights
	total := 0
	for _, w := range weights {
		total += w
	}
	if total <= 0 {
		return templates.LocaleEN
	}
	x := g.rng.Intn(total)
	acc := 0
	for i, w := range weights {
		acc += w
		if x < acc && i < len(g.opts.Locales) {
			return templates.Locale(g.opts.Locales[i])
		}
	}
	return templates.LocaleEN
}

// writeCategory writes one JSON file for cat under opts.OutputDir.
func (g *Generator) writeCategory(cat constant.Category, emails []TestEmail) error {
	fname := strings.ToLower(string(cat)) + ".json"
	return g.writeFile(filepath.Join(g.opts.OutputDir, fname), emails)
}

// writeFile serialises v as pretty-printed JSON with a trailing
// newline, atomically replacing path.
func (g *Generator) writeFile(path string, v any) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("encode %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// threatPercentFor returns the threat share (0..100) for cat per the
// distribution table in the task. Benign categories get 10% threat,
// high-severity get 80%, everything else 60%.
func threatPercentFor(cat constant.Category) int {
	switch {
	case cat.IsBenign():
		return 10
	case cat.IsHighSeverity():
		return 80
	default:
		return 60
	}
}

// tierAndScoreFor returns the expected tier and score range based on
// the rule:
//
//	benign  → Trusted [0,14] (Tier 0 bypass) or Informational [15,29]
//	threat easy   → Blocked [85,100]
//	threat medium → HighRisk [70,84]
//	threat hard   → Warning [50,69]
//
// High-severity threats one tier hotter (Blocked even at medium).
// AUTH_FAILED threat is HighRisk regardless of difficulty.
func tierAndScoreFor(cat constant.Category, isThreat bool, level templates.Level) (constant.Tier, int, int) {
	if !isThreat {
		if cat.IsBenign() {
			return constant.TierTrusted, 0, 14
		}
		return constant.TierInformational, 15, 29
	}
	if cat == constant.CategoryAuthFailed {
		return constant.TierHighRisk, 70, 84
	}
	if cat.IsHighSeverity() {
		switch level {
		case templates.LevelEasy:
			return constant.TierBlocked, 85, 100
		case templates.LevelMedium:
			return constant.TierBlocked, 85, 100
		default:
			return constant.TierHighRisk, 70, 84
		}
	}
	switch level {
	case templates.LevelEasy:
		return constant.TierBlocked, 85, 100
	case templates.LevelMedium:
		return constant.TierHighRisk, 70, 84
	default:
		return constant.TierWarning, 50, 69
	}
}

// tier0BypassFor returns true when the rule-based gate should
// short-circuit. Benign messages in the three trusted categories are
// the only candidates; we never bypass a threat even if its category
// is benign-typed.
func tier0BypassFor(cat constant.Category, isThreat bool) bool {
	if isThreat {
		return false
	}
	return cat.IsBenign()
}

// tier1VerdictFor maps (bypass, threat, difficulty) → expected
// verdict string per the task's pipeline contract.
func tier1VerdictFor(bypass, isThreat bool, level templates.Level) string {
	if bypass {
		return "skip"
	}
	if !isThreat {
		return "pass"
	}
	switch level {
	case templates.LevelEasy, templates.LevelMedium:
		return "flag"
	default:
		return "escalate"
	}
}

// tier2NeededFor returns true when Tier 2 should be invoked. By
// contract Tier 2 is skipped whenever Tier 0 bypassed OR Tier 1
// passed.
func tier2NeededFor(bypass bool, tier1Verdict string) bool {
	if bypass {
		return false
	}
	if tier1Verdict == "pass" {
		return false
	}
	return true
}

// tier2CategoriesFor builds the expected Tier 2 output. For threat
// emails the LLM should at minimum agree with the ground-truth
// category. For benign-but-escalated emails we leave it empty.
func tier2CategoriesFor(cat constant.Category, needed, isThreat bool) []constant.Category {
	if !needed {
		return []constant.Category{}
	}
	if !isThreat {
		return []constant.Category{}
	}
	return []constant.Category{cat}
}

// llmAssistCategory returns true when the LLM should produce a body
// variant for cat. Restricted to the three categories where templates
// most struggle to capture nuance.
func llmAssistCategory(cat constant.Category) bool {
	switch cat {
	case constant.CategoryBECImpersonation,
		constant.CategoryVendorCompromise,
		constant.CategoryAccountTakeoverSuspected:
		return true
	default:
		return false
	}
}

// buildTestID returns a stable per-category sequential identifier such
// as "phish-000123". The short-form prefix table below is the only
// place we map category → short name; keep it in sync with the schema
// comment on test_id.
func buildTestID(cat constant.Category, index int) string {
	prefix := categoryShortForm(cat)
	return fmt.Sprintf("%s-%06d", prefix, index)
}

// categoryShortForm returns a 4-8 character snake_case prefix used
// for human-readable test_ids.
func categoryShortForm(cat constant.Category) string {
	switch cat {
	case constant.CategoryLikelyPhishing:
		return "phish"
	case constant.CategoryBECImpersonation:
		return "bec"
	case constant.CategoryLookalikeDomain:
		return "lookalike"
	case constant.CategorySuspiciousURL:
		return "url"
	case constant.CategorySuspiciousAttachment:
		return "attach"
	case constant.CategoryFirstContactExternal:
		return "first"
	case constant.CategoryAccountTakeoverSuspected:
		return "ato"
	case constant.CategoryVendorCompromise:
		return "vendor_c"
	case constant.CategoryCredentialHarvesting:
		return "cred"
	case constant.CategoryInvoiceFraud:
		return "invoice"
	case constant.CategoryQRPhishing:
		return "qr"
	case constant.CategoryScamFraud:
		return "scam"
	case constant.CategoryAuthFailed:
		return "auth"
	case constant.CategoryInternalTrusted:
		return "internal"
	case constant.CategoryVendorTrusted:
		return "vendor_t"
	case constant.CategoryNewsletter:
		return "news"
	default:
		return "x"
	}
}

// dedupStrings returns a sorted, de-duplicated copy of in. We sort
// for stable diffs; signals are an unordered set in the schema.
func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// loadCorpus reads the per-category JSON files under dir and returns
// a flat slice. Used by the validator and the model validator.
//
// Two filenames are normally excluded to avoid double-counting:
//
//   - all.json:    the aggregated combined output written by Run().
//   - sample.json: the small checked-in CI fixture in
//     scripts/corpus/evaluation/. It shares test_ids with the
//     freshly generated per-category files (e.g. phish-000000), so
//     including it alongside a fresh corpus would always trigger the
//     validator's duplicate-test_id and dedup checks.
//
// As a convenience, if the directory contains no per-category files
// at all and sample.json IS present, sample.json is loaded as a
// fallback. This lets `make validate-corpus` run in CI against the
// checked-in fixture without first having to invoke generate-corpus.
//
// All other *.json files are treated as per-category corpus files.
func loadCorpus(dir string) ([]TestEmail, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}
	var (
		all              []TestEmail
		sawSample        bool
		samplePath       string
		perCategoryCount int
	)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if e.Name() == "all.json" {
			continue
		}
		if e.Name() == "sample.json" {
			sawSample = true
			samplePath = filepath.Join(dir, e.Name())
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		var batch []TestEmail
		if err := json.Unmarshal(b, &batch); err != nil {
			return nil, fmt.Errorf("decode %s: %w", e.Name(), err)
		}
		all = append(all, batch...)
		perCategoryCount++
	}
	// Fixture-only fallback: when nothing else is on disk, load the
	// checked-in sample so `validate-corpus` works in CI.
	if perCategoryCount == 0 && sawSample {
		b, err := os.ReadFile(samplePath)
		if err != nil {
			return nil, fmt.Errorf("read sample.json: %w", err)
		}
		if err := json.Unmarshal(b, &all); err != nil {
			return nil, fmt.Errorf("decode sample.json: %w", err)
		}
	}
	if len(all) == 0 {
		return nil, errors.New("no test emails found")
	}
	return all, nil
}
