package agent

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

//go:embed explanations/*.json
var embeddedExplanations embed.FS

// ExplanationCatalog holds per-locale verdict explanation data loaded
// from embedded JSON files. Thread-safe for concurrent reads.
type ExplanationCatalog struct {
	mu      sync.RWMutex
	locales map[string]*localeExplanation
}

type localeExplanation struct {
	TierExplanations    map[string]string `json:"tier_explanations"`
	TierSuggestions     map[string]string `json:"tier_suggestions"`
	CategoryNames       map[string]string `json:"category_names"`
	PrimarySignal       string            `json:"primary_signal"`
	ContributingFactors string            `json:"contributing_factors"`
	DegradedNotice      string            `json:"degraded_notice"`
	VerdictPending      string            `json:"verdict_pending"`
	EscalatedSuggestion string            `json:"escalated_suggestion"`
	ReleaseSuggestion   string            `json:"release_suggestion"`
}

// DefaultExplanationCatalog loads the embedded explanation catalogs.
func DefaultExplanationCatalog() (*ExplanationCatalog, error) {
	return loadExplanationCatalogFromFS(embeddedExplanations, "explanations")
}

func loadExplanationCatalogFromFS(fsys fs.FS, root string) (*ExplanationCatalog, error) {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("explanations: read dir %s: %w", root, err)
	}
	cat := &ExplanationCatalog{locales: make(map[string]*localeExplanation)}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		blob, err := fs.ReadFile(fsys, path.Join(root, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("explanations: read %s: %w", e.Name(), err)
		}
		locale := strings.TrimSuffix(e.Name(), ".json")
		var le localeExplanation
		if err := json.Unmarshal(blob, &le); err != nil {
			return nil, fmt.Errorf("explanations: parse %s: %w", e.Name(), err)
		}
		cat.locales[locale] = &le
	}
	if _, ok := cat.locales["en"]; !ok {
		return nil, fmt.Errorf("explanations: en.json is required")
	}
	return cat, nil
}

// resolve returns the locale data for the requested locale, falling back
// to "en" if unavailable. Must be called with at least a read lock.
func (c *ExplanationCatalog) resolve(locale string) *localeExplanation {
	if locale == "" {
		locale = "en"
	}
	if le, ok := c.locales[locale]; ok {
		return le
	}
	return c.locales["en"]
}

// TierExplanation returns the explanation string for a tier in the given locale.
func (c *ExplanationCatalog) TierExplanation(tier constant.Tier, locale string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	le := c.resolve(locale)
	if s, ok := le.TierExplanations[string(tier)]; ok {
		return s
	}
	return c.locales["en"].VerdictPending
}

// TierSuggestion returns the default suggestion for a tier in the given locale.
func (c *ExplanationCatalog) TierSuggestion(tier constant.Tier, locale string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	le := c.resolve(locale)
	if s, ok := le.TierSuggestions[string(tier)]; ok {
		return s
	}
	// Fallback to en for missing tier.
	if s, ok := c.locales["en"].TierSuggestions[string(tier)]; ok {
		return s
	}
	return ""
}

// CategoryName returns the human-readable category name in the given locale.
func (c *ExplanationCatalog) CategoryName(cat constant.Category, locale string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	le := c.resolve(locale)
	if s, ok := le.CategoryNames[string(cat)]; ok {
		return s
	}
	// Fallback to en.
	if s, ok := c.locales["en"].CategoryNames[string(cat)]; ok {
		return s
	}
	return string(cat)
}

// PrimarySignalLabel returns the "Primary signal: " prefix in the given locale.
func (c *ExplanationCatalog) PrimarySignalLabel(locale string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resolve(locale).PrimarySignal
}

// ContributingFactorsLabel returns the "Contributing factors: " prefix.
func (c *ExplanationCatalog) ContributingFactorsLabel(locale string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resolve(locale).ContributingFactors
}

// DegradedNotice returns the degraded-service notice.
func (c *ExplanationCatalog) DegradedNotice(locale string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resolve(locale).DegradedNotice
}

// VerdictPending returns the "Verdict pending." text.
func (c *ExplanationCatalog) VerdictPending(locale string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resolve(locale).VerdictPending
}

// EscalatedSuggestion returns the escalation suggestion text.
func (c *ExplanationCatalog) EscalatedSuggestion(locale string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resolve(locale).EscalatedSuggestion
}

// ReleaseSuggestion returns the release-queued suggestion text.
func (c *ExplanationCatalog) ReleaseSuggestion(locale string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resolve(locale).ReleaseSuggestion
}

// Locales returns a sorted list of loaded locales.
func (c *ExplanationCatalog) Locales() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.locales))
	for k := range c.locales {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
