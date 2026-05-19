package main

import (
	"testing"
)

// TestRateLimitRouteLabel pins the cardinality-bound mapping the
// 429 path emits onto the http_rate_limited_total counter. The
// label set is small, fixed, and deliberately collapses every
// non-mux-registered path into "/other" so attacker traffic
// spraying random URLs cannot create one Prometheus series per
// distinct path.
func TestRateLimitRouteLabel(t *testing.T) {
	patterns := defaultRouteTemplates()
	known := defaultKnownExactRoutes()

	cases := []struct {
		name string
		path string
		want string
	}{
		{"escalation id collapses", "/v1/escalation/8675309", "/v1/escalation/:id"},
		{"l token collapses", "/l/abc.def.ghi", "/l/:token"},
		{"education lesson collapses", "/v1/education/lesson/anyid", "/v1/education/lesson/:id"},
		{"vendors id collapses", "/v1/vendors/uuid-here", "/v1/vendors/:id"},
		{"known exact preserved", "/v1/banner/action", "/v1/banner/action"},
		{"known exact predict", "/v1/predict/open", "/v1/predict/open"},
		// Random attacker paths bucket into "/other" rather than
		// producing one new label per request.
		{"random path buckets to other", "/admin/.env", "/other"},
		{"deep random path buckets to other", "/aaaaaaa/bbbbbbb/ccccccc", "/other"},
		{"empty path buckets to other", "", "/other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rateLimitRouteLabel(tc.path, patterns, known)
			if got != tc.want {
				t.Fatalf("rateLimitRouteLabel(%q) = %q; want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestRateLimitRouteLabel_BoundsCardinality is the property that
// motivates the helper: no matter how many distinct unknown paths
// arrive, only one label ("/other") gets used. The test sweeps a
// large set of synthetic paths to make the bound concrete.
func TestRateLimitRouteLabel_BoundsCardinality(t *testing.T) {
	patterns := defaultRouteTemplates()
	known := defaultKnownExactRoutes()
	seen := map[string]struct{}{}
	for i := 0; i < 10_000; i++ {
		label := rateLimitRouteLabel(synthPath(i), patterns, known)
		seen[label] = struct{}{}
	}
	if _, ok := seen["/other"]; !ok {
		t.Fatalf("synthetic attacker paths did not collapse into /other; saw labels: %v", seen)
	}
	for label := range seen {
		if label != "/other" {
			t.Fatalf("unexpected label %q leaked through; the bucket must collapse all synthetic paths", label)
		}
	}
}

// TestDefaultKnownExactRoutes_ReferentialIntegrity guards the
// allowlist against drift: every path declared as known-exact must
// start with a slash. Known-exact paths CAN be shadowed by a route
// template (e.g. /v1/vendors versus /v1/vendors/:id) — rateLimitRouteLabel
// checks the known-exact map first, so the literal path label wins.
// This is the deliberate design: the known-exact list is the
// authoritative source for stable "collection" endpoints; templates
// only apply to the parameterized siblings.
func TestDefaultKnownExactRoutes_ReferentialIntegrity(t *testing.T) {
	patterns := defaultRouteTemplates()
	for path := range defaultKnownExactRoutes() {
		if len(path) == 0 || path[0] != '/' {
			t.Errorf("known exact route %q must start with '/'", path)
		}
		// Re-asserts the priority order: rateLimitRouteLabel
		// returns the known-exact path verbatim even when a
		// template would otherwise match. If this property
		// changes, the metric label for these endpoints would
		// silently flip from /v1/vendors -> /v1/vendors/:id,
		// breaking dashboards.
		if got := rateLimitRouteLabel(path, patterns, defaultKnownExactRoutes()); got != path {
			t.Errorf("known exact route %q labelled as %q; known-exact priority broken", path, got)
		}
	}
}

func synthPath(i int) string {
	// Stable but unique per i; no chance any pattern or known-exact
	// entry happens to match.
	return "/atk/" + intToString(i) + "/payload"
}

func intToString(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
