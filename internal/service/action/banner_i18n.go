package action

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
)

// JSONCatalog is the default Translator: a per-locale map<string,string>
// loaded from embedded JSON files. Files are flat key→value maps so
// translators don't have to think about Go structs.
type JSONCatalog struct {
	mu       sync.RWMutex
	tables   map[string]map[string]string
	fallback string
}

// NewJSONCatalogFromFS loads every "<locale>.json" file under root in fsys.
// The fallback locale is used when a key is missing from the requested
// locale.
func NewJSONCatalogFromFS(fsys fs.FS, root, fallback string) (*JSONCatalog, error) {
	if fallback == "" {
		fallback = "en"
	}
	c := &JSONCatalog{tables: map[string]map[string]string{}, fallback: fallback}
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("i18n: read dir %s: %w", root, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		locale := strings.TrimSuffix(e.Name(), ".json")
		blob, err := fs.ReadFile(fsys, path.Join(root, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("i18n: read %s: %w", e.Name(), err)
		}
		var table map[string]string
		if err := json.Unmarshal(blob, &table); err != nil {
			return nil, fmt.Errorf("i18n: parse %s: %w", e.Name(), err)
		}
		c.tables[locale] = table
	}
	if len(c.tables) == 0 {
		return nil, errors.New("i18n: no locale catalogs found")
	}
	if _, ok := c.tables[fallback]; !ok {
		return nil, fmt.Errorf("i18n: fallback locale %q missing", fallback)
	}
	return c, nil
}

// Locales returns the sorted list of locales loaded.
func (c *JSONCatalog) Locales() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.tables))
	for k := range c.tables {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Translate looks up key in locale, falling back to the catalog's
// configured fallback locale, then to the raw key on miss.
func (c *JSONCatalog) Translate(locale, key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if locale != "" {
		if v, ok := c.tables[locale][key]; ok {
			return v
		}
		// Try the language-only form (e.g. "en-US" → "en").
		if dash := strings.IndexByte(locale, '-'); dash > 0 {
			if v, ok := c.tables[locale[:dash]][key]; ok {
				return v
			}
		}
	}
	if v, ok := c.tables[c.fallback][key]; ok {
		return v
	}
	return key
}

//go:embed catalogs/*.json
var embeddedCatalogs embed.FS

// DefaultBannerCatalog loads the embedded en + vi banner catalogs.
// Exported so the service entrypoint can wire it directly without
// touching the filesystem.
func DefaultBannerCatalog() (*JSONCatalog, error) {
	return NewJSONCatalogFromFS(embeddedCatalogs, "catalogs", "en")
}
