// Package translation provides cross-service i18n bundles for SN360-ES
// user-facing strings (banner copy, education lessons, banner action
// confirmations, etc.).
//
// Catalogs are stored as flat key/value JSON files under
// `internal/translation/banners/`, one file per BCP-47 locale code. The
// banner action pipeline still loads its source catalogs from
// `internal/service/action/catalogs/` so this package can be adopted
// without touching the v2 feature code; both directories share the same
// JSON schema and content.
package translation

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

//go:embed banners/*.json
var embeddedBanners embed.FS

// DefaultLocale is the fallback locale used when no other locale matches.
const DefaultLocale = "en"

// Catalog is the type-safe handle on a translation registry.
type Catalog struct {
	mu      sync.RWMutex
	bundles map[string]map[string]string
}

// New constructs an empty Catalog. Use Load* helpers to populate it.
func New() *Catalog {
	return &Catalog{bundles: map[string]map[string]string{}}
}

// LoadEmbeddedBanners loads the SN360-ES default banner catalogs into the
// returned Catalog. Suitable for production startup.
func LoadEmbeddedBanners() (*Catalog, error) {
	c := New()
	if err := c.loadFromFS(embeddedBanners, "banners"); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadFromDir loads JSON catalogs from the given directory on disk. Used
// by tools and tests that want to override the embedded defaults.
func (c *Catalog) LoadFromDir(dir string) error {
	return c.loadFromFS(osFS{}, dir)
}

func (c *Catalog) loadFromFS(fsys fs.FS, dir string) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return fmt.Errorf("translation: read %s: %w", dir, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		locale := strings.TrimSuffix(name, ".json")
		data, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			return fmt.Errorf("translation: read %s: %w", name, err)
		}
		var bundle map[string]string
		if err := json.Unmarshal(data, &bundle); err != nil {
			return fmt.Errorf("translation: parse %s: %w", name, err)
		}
		c.bundles[locale] = bundle
	}
	if _, ok := c.bundles[DefaultLocale]; !ok {
		return errors.New("translation: missing default locale (en.json)")
	}
	return nil
}

// Locales returns the sorted list of loaded locale codes.
func (c *Catalog) Locales() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.bundles))
	for k := range c.bundles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Translate resolves key in the requested locale.
//
// Lookup precedence: exact locale → primary subtag (e.g. "zh-Hant" →
// "zh") → DefaultLocale → key itself. The returned bool reports whether
// any non-fallback translation was found.
func (c *Catalog) Translate(locale, key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if locale == "" {
		locale = DefaultLocale
	}
	if b, ok := c.bundles[locale]; ok {
		if v, ok := b[key]; ok && v != "" {
			return v, true
		}
	}
	if i := strings.IndexAny(locale, "-_"); i > 0 {
		primary := locale[:i]
		if b, ok := c.bundles[primary]; ok {
			if v, ok := b[key]; ok && v != "" {
				return v, true
			}
		}
	}
	if b, ok := c.bundles[DefaultLocale]; ok {
		if v, ok := b[key]; ok && v != "" {
			return v, false
		}
	}
	return key, false
}

// T is the short form of Translate; it returns the translation or the
// key itself when no match exists. Useful in template-driven banner
// rendering where the caller does not care about the found bool.
func (c *Catalog) T(locale, key string) string {
	v, _ := c.Translate(locale, key)
	return v
}

// Has reports whether the requested key is present in the requested
// locale (without falling back).
func (c *Catalog) Has(locale, key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	b, ok := c.bundles[locale]
	if !ok {
		return false
	}
	_, ok = b[key]
	return ok
}

// osFS adapts os-level file IO to fs.FS so we can share the embed.FS code
// path with on-disk loading without pulling in os.DirFS at every call
// site (which is a Go 1.16+ feature but introduces an additional import
// surface for the test).
type osFS struct{}

func (osFS) Open(name string) (fs.File, error)        { return openOS(name) }
func (osFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return readDirOS(name)
}
func (osFS) ReadFile(name string) ([]byte, error) {
	return readFileOS(name)
}
