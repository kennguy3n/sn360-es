package corpus

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Generate builds a deterministic labelled corpus from cfg. The
// returned slice has at least cfg.Size entries and is guaranteed to
// contain at least cfg.MinPerCategory entries per category (default
// 50). The order of returned entries is deterministic for the same
// seed.
//
// Generate never returns an error — invalid Config values are
// normalised in place. This keeps the API simple for tests and the
// CLI.
func Generate(cfg Config) []LabeledEmail {
	cfg = applyDefaults(cfg)
	rng := rand.New(rand.NewSource(cfg.Seed))

	profiles := allCategoryProfiles()
	locales := compileLocales(cfg.Locales)

	perCategory := planAllocations(cfg.Size, cfg.MinPerCategory, len(profiles))

	corpus := make([]LabeledEmail, 0, sumAllocations(perCategory))
	for i, profile := range profiles {
		want := perCategory[i]
		threatTarget, benignTarget := threatBenignSplit(profile.Category, want, profile.SetBenignSignals != nil)
		for j := 0; j < threatTarget; j++ {
			corpus = append(corpus, build(profile, j, true, pickDifficulty(rng, j), pickLocale(rng, locales)))
		}
		for j := 0; j < benignTarget; j++ {
			email, ok := buildBenign(profile, j, pickLocale(rng, locales))
			if !ok {
				// Profile rejected the benign variant; substitute an
				// extra threat sample so we still hit the allocation
				// target.
				corpus = append(corpus, build(profile, threatTarget+j, true, pickDifficulty(rng, threatTarget+j), pickLocale(rng, locales)))
				continue
			}
			corpus = append(corpus, email)
		}
	}

	// Stable shuffle so consumers don't see all of one category in a row;
	// this matters for the resource-profile latency distribution.
	rng.Shuffle(len(corpus), func(i, j int) { corpus[i], corpus[j] = corpus[j], corpus[i] })
	return corpus
}

// applyDefaults fills in zero-valued cfg fields.
func applyDefaults(cfg Config) Config {
	if cfg.Size <= 0 {
		cfg.Size = 1000
	}
	if cfg.MinPerCategory <= 0 {
		cfg.MinPerCategory = 50
	}
	if cfg.Seed == 0 {
		cfg.Seed = 42
	}
	if len(cfg.Locales) == 0 {
		cfg.Locales = DefaultLocaleWeights
	}
	return cfg
}

// compileLocales returns a flat slice of locale strings repeated
// according to their weight. This makes locale picking a single
// O(1) slice index rather than a cumulative-distribution lookup.
func compileLocales(weights []LocaleWeight) []string {
	out := make([]string, 0, 100)
	for _, w := range weights {
		if w.Weight <= 0 {
			continue
		}
		for i := 0; i < w.Weight; i++ {
			out = append(out, w.Locale)
		}
	}
	if len(out) == 0 {
		out = append(out, "en")
	}
	return out
}

// planAllocations splits totalSize across nCategories with a floor of
// minPerCategory each. Categories that have already exceeded the
// floor get a proportionally-rounded share of the remainder.
func planAllocations(totalSize, minPerCategory, nCategories int) []int {
	if nCategories == 0 {
		return nil
	}
	if minPerCategory*nCategories > totalSize {
		// Floor dominates: every category gets minPerCategory and the
		// resulting corpus is slightly larger than requested.
		out := make([]int, nCategories)
		for i := range out {
			out[i] = minPerCategory
		}
		return out
	}
	out := make([]int, nCategories)
	for i := range out {
		out[i] = minPerCategory
	}
	remaining := totalSize - minPerCategory*nCategories
	// Distribute the remainder evenly; give earlier categories the
	// extra +1 when remaining doesn't divide evenly so the result is
	// deterministic.
	share := remaining / nCategories
	extra := remaining % nCategories
	for i := range out {
		out[i] += share
		if i < extra {
			out[i]++
		}
	}
	return out
}

// sumAllocations returns the total number of emails the plan will
// produce.
func sumAllocations(plan []int) int {
	total := 0
	for _, n := range plan {
		total += n
	}
	return total
}

// threatBenignSplit returns (threatCount, benignCount) for a category.
// Benign categories (Internal/Vendor/Newsletter) lean heavily benign;
// every threat category leans heavily threat with a small benign tail
// so the accuracy harness can compute a meaningful false-positive
// rate.
func threatBenignSplit(cat constant.Category, want int, hasBenign bool) (int, int) {
	if want <= 0 {
		return 0, 0
	}
	if !hasBenign {
		return want, 0
	}
	switch cat {
	case constant.CategoryInternalTrusted,
		constant.CategoryVendorTrusted,
		constant.CategoryNewsletter:
		// Mostly benign with ~10% compromised variants.
		benign := want * 9 / 10
		return want - benign, benign
	case constant.CategoryAuthFailed:
		return want, 0
	default:
		// Threat-heavy categories: ~85% threat / ~15% benign so the
		// FP measurement reflects realistic background traffic.
		benign := want * 15 / 100
		if benign < 1 {
			benign = 1
		}
		return want - benign, benign
	}
}

// pickDifficulty cycles through difficulties with a deterministic
// preference order seeded by idx so a single category's emails span
// all three buckets.
func pickDifficulty(rng *rand.Rand, idx int) Difficulty {
	roll := rng.Intn(100) + idx
	switch {
	case roll%10 < 5:
		return DifficultyEasy
	case roll%10 < 8:
		return DifficultyMedium
	default:
		return DifficultyHard
	}
}

// pickLocale returns a locale chosen from the compiled weights.
func pickLocale(rng *rand.Rand, pool []string) string {
	return pool[rng.Intn(len(pool))]
}

// build assembles a single LabeledEmail for the given profile.
func build(profile categoryProfile, idx int, threat bool, level Difficulty, locale string) LabeledEmail {
	copyText := selectCopy(profile, locale, level)
	sender := composeSender(profile, idx, threat)
	recipient := composeAddress("user", profile.RecipientDomain, idx)

	signals := dto.RiskSignals{
		SenderDomain:    splitDomain(sender),
		RecipientDomain: profile.RecipientDomain,
	}
	if threat {
		profile.SetThreatSignals(&signals, level)
	} else {
		// Should not happen: builds with threat=false should go
		// through buildBenign; the path is retained as a safety net.
		_ = profile.SetBenignSignals(&signals)
	}

	body := withSenderEcho(copyText.Body, sender, idx)
	req := dto.EvaluateRequest{
		MessageID:     fmt.Sprintf("msg-%s-%04d", shortCat(profile.Category), idx),
		TenantID:      "tenant-bench",
		CorrelationID: fmt.Sprintf("corr-%s-%04d", shortCat(profile.Category), idx),
		Sender:        sender,
		Recipient:     recipient,
		Subject:       copyText.Subject,
		Body:          body,
		Signals:       signals,
		Locale:        locale,
		ReceivedAt:    time.Unix(1_700_000_000, int64(idx)).UTC(),
	}

	expectedScore := expectedScoreFor(profile.Category, signals, threat, level)
	return LabeledEmail{
		Request:            req,
		ExpectedPrimary:    expectedPrimaryFor(profile.Category, signals, threat),
		ExpectedTier:       expectedTierFor(profile.Category, expectedScore[0], expectedScore[1], threat),
		ExpectedScoreRange: expectedScore,
		Difficulty:         level,
		AttackType:         profile.AttackType,
		IsThreat:           threat,
		Locale:             locale,
	}
}

// buildBenign builds the benign variant of a category. Returns ok=false
// when the profile has no benign mode (e.g. AUTH_FAILED).
func buildBenign(profile categoryProfile, idx int, locale string) (LabeledEmail, bool) {
	signals := dto.RiskSignals{
		SenderDomain:    "",
		RecipientDomain: profile.RecipientDomain,
	}
	if !profile.SetBenignSignals(&signals) {
		return LabeledEmail{}, false
	}
	level := DifficultyHard // benign emails are by definition "subtle".
	copyText := selectCopy(profile, locale, level)
	sender := composeSender(profile, idx, false)
	signals.SenderDomain = splitDomain(sender)

	body := withSenderEcho(copyText.Body, sender, idx)
	req := dto.EvaluateRequest{
		MessageID:     fmt.Sprintf("msg-%s-benign-%04d", shortCat(profile.Category), idx),
		TenantID:      "tenant-bench",
		CorrelationID: fmt.Sprintf("corr-%s-benign-%04d", shortCat(profile.Category), idx),
		Sender:        sender,
		Recipient:     composeAddress("user", profile.RecipientDomain, idx),
		Subject:       copyText.Subject,
		Body:          body,
		Signals:       signals,
		Locale:        locale,
		ReceivedAt:    time.Unix(1_700_000_000, int64(idx)).UTC(),
	}

	expected := expectedScoreFor(profile.Category, signals, false, level)
	return LabeledEmail{
		Request:            req,
		ExpectedPrimary:    expectedPrimaryFor(profile.Category, signals, false),
		ExpectedTier:       expectedTierFor(profile.Category, expected[0], expected[1], false),
		ExpectedScoreRange: expected,
		Difficulty:         level,
		AttackType:         profile.AttackType + " (benign)",
		IsThreat:           false,
		Locale:             locale,
	}, true
}

// composeSender picks a sender address based on the profile and idx.
// For the internal-trusted profile the recipient domain is reused so
// the Tier 0 IsInternal gate fires correctly.
func composeSender(profile categoryProfile, idx int, threat bool) string {
	domain := pickFrom(profile.SenderDomains, idx)
	if profile.Category == constant.CategoryInternalTrusted {
		domain = profile.RecipientDomain
	}
	prefix := localPrefixFor(profile.Category, threat)
	return composeAddress(prefix, domain, idx)
}

func localPrefixFor(cat constant.Category, threat bool) string {
	switch cat {
	case constant.CategoryBECImpersonation:
		if threat {
			return "ceo.urgent.account."
		}
		return "amelia.bryce."
	case constant.CategoryNewsletter:
		return "noreply."
	case constant.CategoryAccountTakeoverSuspected:
		return "compromised.user."
	case constant.CategoryVendorCompromise:
		return "billing."
	case constant.CategoryInternalTrusted:
		return "team.member."
	case constant.CategoryVendorTrusted:
		return "support."
	default:
		return "sender."
	}
}

// selectCopy resolves the subject/body for (locale, difficulty),
// falling back to English then to the easy variant if necessary.
func selectCopy(profile categoryProfile, locale string, level Difficulty) localizedCopy {
	if entries, ok := profile.Copy[locale]; ok {
		if c, ok := entries[level]; ok {
			return c
		}
		// Try the same locale at any difficulty (deterministic order).
		for _, d := range AllDifficulties {
			if c, ok := entries[d]; ok {
				return c
			}
		}
	}
	if entries, ok := profile.Copy["en"]; ok {
		if c, ok := entries[level]; ok {
			return c
		}
		for _, d := range AllDifficulties {
			if c, ok := entries[d]; ok {
				return c
			}
		}
	}
	return localizedCopy{Subject: "(no subject)", Body: "(no body)"}
}

// withSenderEcho appends a short signature-like postscript that
// includes a hash of the sender; this prevents identical bodies across
// thousands of generated emails which would make the body hash trivial
// to memoize in downstream caches.
func withSenderEcho(body, sender string, idx int) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(sender))
	_, _ = h.Write([]byte{byte(idx)})
	return body + "\n\n— Ref: " + fmt.Sprintf("%x", h.Sum64())
}

// splitDomain returns the domain portion of an email address. Returns
// the empty string when addr does not contain '@'.
func splitDomain(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return addr[at+1:]
}

// shortCat returns a 4-letter lowercase prefix for a category, used to
// build deterministic message IDs.
func shortCat(c constant.Category) string {
	s := strings.ToLower(string(c))
	if len(s) <= 6 {
		return s
	}
	return s[:6]
}

// expectedPrimaryFor returns the category the RuleCategorizer is
// expected to produce given the signals. For threat samples this is
// the same as profile.Category; for benign samples it depends on the
// signal profile (often FirstContactExternal or one of the trusted
// labels).
func expectedPrimaryFor(cat constant.Category, sig dto.RiskSignals, threat bool) constant.Category {
	if sig.IsInternal {
		return constant.CategoryInternalTrusted
	}
	if sig.IsFromVendor {
		return constant.CategoryVendorTrusted
	}
	if sig.IsRecurringService {
		return constant.CategoryNewsletter
	}
	if !threat {
		// Benign external email with no specific signal lands on
		// FirstContactExternal in the RuleCategorizer.
		if cat == constant.CategoryInvoiceFraud && sig.HasInvoiceHint {
			return constant.CategoryInvoiceFraud
		}
		return constant.CategoryFirstContactExternal
	}
	return cat
}

// expectedScoreFor returns an inclusive [lo, hi] score band the
// pipeline should produce. Bands are tuned against the signal→weight
// matrix in categorizer.go so accuracy regressions surface as soon as
// the categorizer drifts.
func expectedScoreFor(cat constant.Category, sig dto.RiskSignals, threat bool, level Difficulty) [2]int {
	_ = sig // reserved for future per-signal tuning; currently unused.
	if !threat {
		// Benign default band: scorer aggregates AI≈0 + Rspamd≈low, so
		// the final score lands in the Trusted/Informational region.
		return [2]int{0, 25}
	}
	switch cat {
	case constant.CategoryInternalTrusted:
		return [2]int{0, 10}
	case constant.CategoryVendorTrusted:
		return [2]int{0, 15}
	case constant.CategoryNewsletter:
		// Threat newsletter lands in Informational so the tier
		// coverage tests see all six tiers in a 1000-row corpus.
		return [2]int{15, 30}
	case constant.CategoryFirstContactExternal:
		// FirstContact threats are the canonical Caution-tier
		// samples: external sender + suspicious URL, no auth fail.
		return [2]int{25, 45}
	case constant.CategoryAuthFailed:
		return [2]int{40, 75}
	}
	switch level {
	case DifficultyEasy:
		return [2]int{80, 100}
	case DifficultyMedium:
		return [2]int{60, 90}
	default:
		return [2]int{30, 80}
	}
}

// expectedTierFor maps an [lo, hi] score band onto a tier label. We
// use the midpoint of the band against the production thresholds
// (PROPOSAL.md §3 / DefaultTierThresholds) so the ground-truth tier
// distribution honours the actual decider behaviour, not just the
// upper bound.
func expectedTierFor(cat constant.Category, lo, hi int, threat bool) constant.Tier {
	if !threat {
		switch cat {
		case constant.CategoryInternalTrusted, constant.CategoryVendorTrusted:
			return constant.TierTrusted
		case constant.CategoryNewsletter:
			return constant.TierInformational
		case constant.CategoryInvoiceFraud:
			// A benign invoice still flags as informational because of
			// the HasInvoiceHint signal weight.
			return constant.TierInformational
		}
		return constant.TierTrusted
	}
	mid := (lo + hi) / 2
	switch {
	case mid >= 85:
		return constant.TierBlocked
	case mid >= 70:
		return constant.TierHighRisk
	case mid >= 50:
		return constant.TierWarning
	case mid >= 30:
		return constant.TierCaution
	case mid >= 15:
		return constant.TierInformational
	default:
		return constant.TierTrusted
	}
}

// CategoryCounts returns the distribution of categories in c, sorted
// by category. Useful in tests and as the basis for the accuracy
// report's per-category rollup.
func CategoryCounts(c []LabeledEmail) []CategoryCount {
	counts := map[constant.Category]int{}
	for _, e := range c {
		counts[e.ExpectedPrimary]++
	}
	out := make([]CategoryCount, 0, len(counts))
	for k, v := range counts {
		out = append(out, CategoryCount{Category: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out
}

// CategoryCount is one row of CategoryCounts.
type CategoryCount struct {
	Category constant.Category
	Count    int
}

// TierCounts returns the distribution of expected tiers in c.
func TierCounts(c []LabeledEmail) map[constant.Tier]int {
	out := map[constant.Tier]int{}
	for _, e := range c {
		out[e.ExpectedTier]++
	}
	return out
}
