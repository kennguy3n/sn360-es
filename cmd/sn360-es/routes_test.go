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
		// WS-3b investigation API: every probed pseudo_id /
		// sender_hash MUST fold into a single label so the
		// per-message and per-sender hashes don't blow up
		// Prometheus head series.
		{"investigation message id collapses", "/v1/investigation/message/abcdef1234", "/v1/investigation/message/:pseudo_id"},
		{"investigation sender hash collapses", "/v1/investigation/sender/AAAA-BBBB", "/v1/investigation/sender/:sender_hash"},
		// WS-5B.2 webhook-sinks API: tenant_id AND sink_id are
		// both per-customer UUIDs, so the parent prefix collapses
		// every sub-resource (list, /<id>, /<id>/test) into a
		// single Prometheus label. The `method` label preserves
		// the verb distinction for dashboards.
		{"webhook-sinks list collapses", "/v1/tenants/11111111-2222-3333-4444-555555555555/webhook-sinks", "/v1/tenants/:tenant_id/webhook-sinks"},
		{"webhook-sinks item collapses", "/v1/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/webhook-sinks/ffffffff-1111-2222-3333-444444444444", "/v1/tenants/:tenant_id/webhook-sinks"},
		{"webhook-sinks test collapses", "/v1/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/webhook-sinks/ffffffff-1111-2222-3333-444444444444/test", "/v1/tenants/:tenant_id/webhook-sinks"},
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

// TestDefaultRateLimitSkipPaths_PushIsBypassed pins the invariant
// that the push-webhook prefix is exempt from per-IP rate-limiting.
// Without this exemption, push callbacks from Google Pub/Sub and
// Microsoft Graph would share a single token bucket behind a load
// balancer (the LB's IP is the bucket key when
// RATE_LIMIT_TRUSTED_PROXIES is unconfigured), and a notification
// burst would 429 legitimate provider traffic — forcing both
// providers into their retry schedules and visibly delaying email
// ingestion. The signature-verification layer in the push handler
// remains the closed-by-default defense against unauthenticated
// traffic, so skipping rate-limiting here does not weaken the DoS
// posture.
func TestDefaultRateLimitSkipPaths_PushIsBypassed(t *testing.T) {
	paths := defaultRateLimitSkipPaths()
	var hasPushPrefix bool
	for _, p := range paths {
		if p == "/v1/push/" {
			hasPushPrefix = true
			break
		}
	}
	if !hasPushPrefix {
		t.Fatalf("defaultRateLimitSkipPaths() must include the prefix-style entry %q so push webhooks bypass the rate limiter; got %v", "/v1/push/", paths)
	}
}

// TestDefaultAuthSkipPaths_PushIsBypassed pins the parallel invariant
// for JWT authentication: /v1/push/ MUST bypass the JWT middleware
// because provider callbacks authenticate via OIDC bearer (Google
// Pub/Sub) or clientState constant-time comparison (Microsoft
// Graph) — not a Bearer JWT this service issues. If this entry is
// ever removed, every push callback would 401 at the auth middleware
// before reaching the signature verifier, silently disabling push
// ingestion until an operator notices the missing email traffic.
func TestDefaultAuthSkipPaths_PushIsBypassed(t *testing.T) {
	paths := defaultAuthSkipPaths()
	var hasPushPrefix bool
	for _, p := range paths {
		if p == "/v1/push/" {
			hasPushPrefix = true
			break
		}
	}
	if !hasPushPrefix {
		t.Fatalf("defaultAuthSkipPaths() must include the prefix-style entry %q so push webhooks bypass JWT auth; got %v", "/v1/push/", paths)
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
