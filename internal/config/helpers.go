package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// --- env helpers ------------------------------------------------------------

func getStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return def
}

// getIntStrict is the variant of getInt used for critical settings
// (HTTP_PORT, tier timeouts, decision thresholds) where a typo or
// stray whitespace must fail boot rather than silently fall back to
// a default that may differ from the operator's intent. It returns:
//
//   - (def, nil)  when the env var is unset or empty.
//   - (n,   nil)  when the env var parses cleanly as an int.
//   - (0,   err)  when the env var is set but unparseable.
//
// The error wraps the offending value (NOT the secret value of the
// env var, since these are all numeric tunables) so operators get an
// actionable diagnostic at boot.
func getIntStrict(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid integer: %w", key, v, err)
	}
	return n, nil
}

// getDurationStrict is the duration twin of getIntStrict. We apply
// the strict policy to the same set of critical settings (tier
// timeouts in particular) so a malformed value like '5second'
// surfaces as a boot error instead of silently reverting to the
// (potentially much shorter or much longer) default.
func getDurationStrict(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid duration: %w", key, v, err)
	}
	return d, nil
}

func getBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func getFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return f
		}
	}
	return def
}

// getFloatPtr returns nil when the env var is unset, empty, or
// unparseable, and a pointer to the parsed float64 otherwise. This
// is the variant used for "tri-state" tunables where an unset
// value MUST be distinguishable from an explicit zero — e.g.
// TIER2_TEMPERATURE=0 means "force greedy/argmax decoding" and
// must not collapse onto the provider's documented default of
// 0.1. See pkg/inference/slm/config.go ProviderConfig.Temperature
// for the downstream consumer of this distinction.
//
// Unparseable values are treated as unset (returns nil) rather
// than failing boot, matching the lenient policy of getFloat. The
// strict variant (boot failure on bad input) is not currently
// needed for any tri-state tunable, but mirroring getIntStrict /
// getDurationStrict would be straightforward if a future caller
// requires it.
func getFloatPtr(key string) *float64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return nil
	}
	return &f
}

func getDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}

// parseCSV splits a comma-separated list into a trimmed slice. Empty
// fields are dropped so trailing or duplicate commas do not produce
// empty allow-list entries.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// loadDotEnv parses a minimal .env file and assigns variables that aren't
// already in the process environment. Lines beginning with `#` and blank
// lines are ignored. Values may be optionally quoted.
//
// This is intentionally tiny: production deployments should source the
// environment from the orchestrator (k8s ConfigMap/Secret, ECS env, etc.).
func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[0] == val[len(val)-1] {
			val = val[1 : len(val)-1]
		}
		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		_ = os.Setenv(key, val)
	}
	return nil
}
