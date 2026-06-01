package config

// NATS super-cluster config parser (WS-7a).
//
// Operators declare cross-region NATS topology in `NATS_SUPERCLUSTER`,
// a JSON object mapping region -> comma-separated NATS URL list:
//
//	NATS_SUPERCLUSTER={"ap-southeast-1": "nats://nats-asia-1:4222,nats://nats-asia-2:4222",
//	                   "us-east-1":      "nats://nats-us-1:4222"}
//
// The map drives the cross-region SOC bridge: the bridge publisher /
// subscriber resolves a target region to its NATS URL list and dials
// that cluster with the rest of the NATS config (auth, TLS, reconnect)
// inherited from the primary `NATS_*` env vars. The map is NOT used by
// the in-region client (`NewClient` continues to dial `NATS_URL`
// unchanged) — it only kicks in for explicit cross-region subjects.
//
// Failure modes (malformed JSON, empty region name, empty URL list)
// fail at boot here rather than at first cross-region publish, so an
// operator who typoed a leaf-cluster URL in their manifest sees the
// error during deploy rather than as a stream of dropped bridge
// messages hours later.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// parseNATSSuperclusterMap parses the JSON NATS_SUPERCLUSTER payload.
//
// Empty / whitespace input returns (nil, nil) so callers can treat
// "no supercluster" identically to "single-region deployment". The
// returned map is keyed by region name with values normalised to the
// canonical comma-separated form (whitespace around URLs stripped,
// empty fields dropped). At least one URL per region is required —
// an entry with only commas or whitespace is rejected at boot.
func parseNATSSuperclusterMap(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var byRegion map[string]string
	if err := json.Unmarshal([]byte(raw), &byRegion); err != nil {
		return nil, fmt.Errorf("NATS_SUPERCLUSTER: invalid JSON: %w", err)
	}
	if len(byRegion) == 0 {
		return nil, errors.New("NATS_SUPERCLUSTER: must contain at least one region (set the env var to empty to disable cross-region routing)")
	}
	out := make(map[string]string, len(byRegion))
	for region, urls := range byRegion {
		trimmed := strings.TrimSpace(region)
		if trimmed == "" {
			return nil, errors.New("NATS_SUPERCLUSTER: region name must not be empty")
		}
		canonical, err := canonicaliseURLList(urls)
		if err != nil {
			return nil, fmt.Errorf("NATS_SUPERCLUSTER[%s]: %w", trimmed, err)
		}
		out[trimmed] = canonical
	}
	return out, nil
}

// canonicaliseURLList splits a comma-separated NATS URL list, strips
// surrounding whitespace from each entry, drops empties, and rejoins
// with commas. It rejects a list that contains zero non-empty URLs
// (the operator either typoed the value or supplied a trailing-comma-
// only string that would produce an empty URL list at dial time).
//
// Per-URL validation (scheme = nats://, parseable host:port) is left
// to the option-builder in pkg/events/nats/supercluster.go so that
// the config package stays decoupled from the NATS library import.
// The builder runs at construction time, BEFORE any cross-region
// publish, so per-URL errors still surface at boot.
func canonicaliseURLList(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("URL list must not be empty")
	}
	parts := strings.Split(raw, ",")
	urls := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		urls = append(urls, p)
	}
	if len(urls) == 0 {
		return "", errors.New("URL list contains no non-empty entries")
	}
	return strings.Join(urls, ","), nil
}
