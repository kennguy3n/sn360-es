// supercluster.go implements the WS-7a NATS super-cluster option
// builder. The runtime behaviour is: when Config.Supercluster is
// non-empty, the binary picks the home-region URL list out of the
// map and merges it with Config.URL to produce a single
// comma-separated server list. nats.Connect's first argument
// already accepts a comma-separated list (it splits and dials in
// the listed order), so the resulting cross-region failover is
// "primary URL first, then leaf-cluster URLs from the same region
// in the order the operator configured them".
//
// Out of scope for this file: spinning up the leaf nodes
// themselves (an operator concern documented in
// internal/docs/MULTI_REGION.md) and cross-region account /
// JetStream replication (an nats-server config, not a client
// option). The client-side surface is intentionally narrow: parse
// the env var (in internal/config), pick the home-region list
// here, fail closed if it's missing.
package nats

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// resolveSuperclusterServers builds the comma-separated server list
// nats.Connect receives. When cfg.Supercluster is non-empty it
// validates the home-region entry exists, splits + dedupes the
// home-region URL list against cfg.URL, and returns the merged
// list. When cfg.Supercluster is nil / empty it returns cfg.URL
// unchanged — that is the single-region default and the pre-WS-7a
// code path verbatim.
//
// A non-empty Supercluster map MUST have an entry for
// cfg.HomeRegion or this function returns an error. Failing here
// at boot is by design: a deployment that explicitly configured a
// super-cluster but forgot its own region almost certainly will
// behave incorrectly under load (every cross-region publish would
// dial the primary URL only, defeating the point of the
// super-cluster), so the operator wants the boot to fail loudly
// rather than degrade silently.
func resolveSuperclusterServers(cfg Config) (string, error) {
	if len(cfg.Supercluster) == 0 {
		return cfg.URL, nil
	}
	if cfg.HomeRegion == "" {
		return "", errors.New("nats: supercluster configured without home region")
	}
	raw, ok := cfg.Supercluster[cfg.HomeRegion]
	if !ok {
		return "", fmt.Errorf("nats: supercluster missing entry for home region %q; got regions %v",
			cfg.HomeRegion, sortedSuperclusterRegions(cfg.Supercluster))
	}
	urls := splitSuperclusterURLs(raw)
	if len(urls) == 0 {
		// Reject the empty list explicitly rather than
		// silently falling back to cfg.URL — an operator who
		// supplied an empty entry meant for the supercluster
		// list to be authoritative.
		return "", fmt.Errorf("nats: supercluster entry for home region %q is empty", cfg.HomeRegion)
	}
	servers := mergeNATSServerList(cfg.URL, urls)
	return strings.Join(servers, ","), nil
}

// splitSuperclusterURLs parses a comma-separated NATS URL list and
// returns the trimmed, non-empty entries in input order. Whitespace
// inside each URL is preserved as-is (the nats client itself rejects
// malformed schemes).
//
// No error return: per-URL scheme / host validation is delegated to
// nats.Connect (which surfaces a clear error on dial), so the only
// failure mode at this layer — an entirely empty URL list — is
// expressed by callers checking `len(out) == 0` rather than threading
// a dead error through every call site.
func splitSuperclusterURLs(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// mergeNATSServerList returns the primary URL first followed by every
// supercluster URL that is not the primary. The deterministic order
// is important: nats.Connect dials in list order, so the primary
// (which has been health-checked locally) wins under normal
// operations and the leaf-cluster URLs are tried only on primary
// failure. Empty primary collapses to just the supercluster list.
func mergeNATSServerList(primary string, supercluster []string) []string {
	seen := make(map[string]struct{}, 1+len(supercluster))
	out := make([]string, 0, 1+len(supercluster))
	if p := strings.TrimSpace(primary); p != "" {
		out = append(out, p)
		seen[p] = struct{}{}
	}
	for _, u := range supercluster {
		s := strings.TrimSpace(u)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// sortedSuperclusterRegions returns the keys of a supercluster map
// in lexicographic order so error messages are deterministic and
// easy to grep for in incident retrospectives.
func sortedSuperclusterRegions(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
