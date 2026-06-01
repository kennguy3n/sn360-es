package slm

import (
	"fmt"
	"sort"
	"sync"
)

// Factory constructs a Client from a ProviderConfig. Factories are
// expected to validate cfg (URL non-empty, model non-empty after
// defaults, etc.) and return a typed error rather than panicking.
// They are called once at process boot per (deployment-default +
// per-tenant) provider, so allocation cost is not on the hot path.
type Factory func(cfg ProviderConfig) (Client, error)

// providersMu guards the package-level providers map. Registration
// happens at init() time across multiple goroutines (Go spec says
// init runs sequentially per file, but the package-level init order
// across providers/* subpackages is not guaranteed when they live
// in independent compilation units), so we lock defensively.
//
// New also takes a read lock so a Register racing with a New cannot
// observe a torn map. The map itself is small (one entry per
// provider) and lookups happen at boot, not per request, so the
// lock contention is operationally invisible.
var (
	providersMu sync.RWMutex
	providers   = map[string]Factory{}
)

// Register associates name with a factory. Panics on duplicate
// registration so an accidental copy/paste in a new provider's
// init() fails the process at boot instead of silently shadowing
// an existing provider (which would route every Evaluate to the
// wrong implementation and only become visible via verdict drift).
//
// Names are lowercased before registration so TIER2_PROVIDER is
// case-insensitive at the env layer; users can write
// "TernaryBonsai" or "ternarybonsai" interchangeably.
//
// Register panics rather than returning an error because the
// expected call site is a package-level init() — there is no
// caller to handle a returned error, and a panic at boot is
// strictly preferable to a silent miswiring at runtime.
func Register(name string, f Factory) {
	if name == "" {
		panic("slm.Register: name must not be empty")
	}
	if f == nil {
		panic("slm.Register: factory must not be nil")
	}
	key := normalizeName(name)
	providersMu.Lock()
	defer providersMu.Unlock()
	if _, exists := providers[key]; exists {
		panic(fmt.Sprintf("slm.Register: provider %q already registered", key))
	}
	providers[key] = f
}

// New looks the registered factory up by cfg.Name (case-insensitive)
// and invokes it. Returns ErrProviderNotRegistered if the name is
// unknown so callers can distinguish a config error (typo in
// TIER2_PROVIDER) from a transient construction error (network
// unreachable while validating the URL).
//
// cfg.Name is normalized before lookup so callers do not have to
// canonicalize it themselves.
func New(cfg ProviderConfig) (Client, error) {
	key := normalizeName(cfg.Name)
	if key == "" {
		return nil, fmt.Errorf("%w: empty name", ErrProviderNotRegistered)
	}
	providersMu.RLock()
	f, ok := providers[key]
	providersMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q (available: %s)",
			ErrProviderNotRegistered, key, formatRegistered())
	}
	// Normalise the name on the cfg copy passed to the factory so
	// the factory does not have to know about case rules.
	cfg.Name = key
	return f(cfg)
}

// Registered returns the set of registered provider names in
// deterministic order. Useful for boot-time logging and error
// messages.
func Registered() []string {
	providersMu.RLock()
	defer providersMu.RUnlock()
	names := make([]string, 0, len(providers))
	for k := range providers {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// IsRegistered reports whether name has a factory registered.
// Useful for soft validation in CLI flag parsing.
func IsRegistered(name string) bool {
	key := normalizeName(name)
	if key == "" {
		return false
	}
	providersMu.RLock()
	_, ok := providers[key]
	providersMu.RUnlock()
	return ok
}

// formatRegistered builds a comma-separated, sorted list of
// registered names for inclusion in error messages. Returns
// "<none>" when no providers are registered so the error remains
// informative in a stripped binary that forgot to blank-import
// pkg/inference/slm/all.
func formatRegistered() string {
	names := Registered()
	if len(names) == 0 {
		return "<none>"
	}
	out := names[0]
	for _, n := range names[1:] {
		out += ", " + n
	}
	return out
}

// normalizeName lowercases the provider name and strips surrounding
// whitespace. Centralising this lets every entry point (Register,
// New, IsRegistered, ResetForTest) apply the same canonicalisation.
func normalizeName(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			// Strip whitespace anywhere in the name. Names are
			// short identifiers (e.g. "ternarybonsai") so this
			// is safe — there is no legitimate use case for an
			// internal space.
			continue
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// resetForTest clears the registry. Used only by tests within this
// package — production code MUST NOT call it. Keeping it package-
// private (lowercase) enforces that.
func resetForTest() {
	providersMu.Lock()
	defer providersMu.Unlock()
	providers = map[string]Factory{}
}
