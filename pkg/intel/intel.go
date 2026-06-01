// Package intel is the threat-intel feed consumption layer.
//
// Responsibilities split across the package and its sub-packages:
//
//   - This file (intel.go) holds the cross-provider types — Indicator,
//     IndicatorType, Poller interface, Result envelope — along with
//     the canonicalisation + hashing routines every provider funnels
//     its parsed rows through. Canonicalisation lives here (not per
//     provider) so two pollers that ingest the same domain under
//     different shapes ("Example.COM", "example.com.", "www.example.com")
//     collapse to one SHA-256 fingerprint and the upsert path stays
//     monotonic.
//
//   - registry.go wires provider names → poller constructors. The
//     intel_worker reads `provider` from the intel_feeds row, looks up
//     the constructor, and dispatches the poll.
//
//   - urlhaus/, misp/, stixtaxii/, csv/ each contain a single
//     spec-compliant Poller implementation. None of them returns
//     in-memory canned data — they all issue real HTTP requests
//     against the configured URL and parse the real response shape.
//
// The IntelStore interface is the persistence seam the pollers and
// scheduler write through; the Postgres implementation lives in
// internal/repository/intel.go and the in-memory implementation in
// internal/repository/memory_intel.go.
package intel

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// IndicatorType classifies the value an IOC carries. The string
// constants match the `indicator_type` column on intel_indicators —
// changing them requires a migration.
type IndicatorType string

const (
	IndicatorDomain IndicatorType = "domain"
	IndicatorURL    IndicatorType = "url"
	IndicatorIP     IndicatorType = "ip"
	// IndicatorSHA256 is the file-hash family. Pollers should emit
	// only lowercased hex digests; the canonicaliser enforces this.
	IndicatorSHA256 IndicatorType = "sha256"
)

// Valid reports whether t is one of the supported indicator types.
// The Postgres CHECK constraint on intel_indicators.indicator_type
// rejects rows whose type is not in this set, so we mirror the
// check at the application boundary to fail fast and produce
// readable errors instead of opaque pq constraint-violation
// messages.
func (t IndicatorType) Valid() bool {
	switch t {
	case IndicatorDomain, IndicatorURL, IndicatorIP, IndicatorSHA256:
		return true
	}
	return false
}

// Indicator is a single canonicalised IOC. It is the unit the pollers
// emit and the IntelStore upserts. Hash is filled in by Canonicalise()
// before persistence; callers should not set it manually.
type Indicator struct {
	// Indicator is the canonicalised raw value (e.g. "example.com",
	// "http://bad.example/path", "203.0.113.42",
	// "deadbeef…<64 hex>"). It is what the Tier 0 gate joins on after
	// canonicalising the message's URLs / sender domain.
	Indicator string
	// Type selects which canonicaliser was applied and lets the
	// gate route by class (a URL match upgrades severity differently
	// than a file-hash match).
	Type IndicatorType
	// Hash is the SHA-256 of the canonical indicator bytes. Stored
	// as BYTEA in Postgres for compact equality joins.
	Hash []byte
	// Severity is the per-feed 0-100 confidence. Pollers map their
	// feed's notion of "confidence" / "level" / "score" onto this
	// range; the upsert keeps the GREATEST of the existing and
	// incoming value so a high-confidence feed never gets clobbered
	// by a low-confidence republish.
	Severity int
	// Tags are short keyword markers (campaign name, malware family,
	// observation source). They are surfaced verbatim in the Tier 0
	// match metadata and indexed via the intel_indicators.tags GIN
	// index for audit queries.
	Tags []string
}

// Result is the value a Poller returns: the list of indicators
// collected for the current poll, plus an opaque cursor the worker
// records on success. Cursors are provider-specific (last-modified
// timestamp for STIX-TAXII, last-event-id for MISP, etc.) — the
// worker treats them as black-box strings and round-trips them on
// the next call.
type Result struct {
	Indicators []Indicator
	// Cursor is reserved for future use to support delta polling.
	// Today the worker ignores it and pollers should leave it
	// blank; callers MUST tolerate empty cursors.
	Cursor string
}

// Poller is the cross-provider contract. The intel_worker constructs
// a Poller from the registry, calls Poll exactly once per cycle, and
// applies the result through the IntelStore. Concurrency is bounded
// by the worker; individual pollers do not need internal locks.
type Poller interface {
	// Provider returns the canonical key (e.g. "urlhaus", "misp")
	// the registry mapped this poller from. The worker logs and
	// alerts use it; the Postgres column intel_feeds.provider holds
	// the same string.
	Provider() string

	// Poll issues the provider request against the configured feed
	// and returns the parsed Indicators. Implementations must
	// honour ctx (cancellation, deadlines) and must not block once
	// ctx is Done.
	//
	// A non-nil error fails the poll: the scheduler records it on
	// intel_feeds (last_ok=false, last_error, consecutive_failures++)
	// and on three consecutive failures emits the alert metric.
	// Partial-success is not modelled — a poll either commits
	// every indicator atomically (via the IntelStore upsert) or
	// fails the whole call.
	Poll(ctx context.Context) (Result, error)
}

// FeedConfig is the per-feed configuration the registry hands to a
// Poller constructor. It is the in-memory shape of an intel_feeds
// row — the worker reads from Postgres, the constructor reads from
// this struct, and the two never need to share a database row type.
type FeedConfig struct {
	// ID is the intel_feeds row id. Pollers do not need it for
	// fetch but record it on every Indicator the IntelStore
	// persists.
	ID string
	// Name is the human-readable feed name. Used in logs / alerts.
	Name string
	// Provider selects the constructor in registry.go.
	Provider string
	// URL is the feed endpoint. Each provider documents its shape:
	//   - urlhaus: full URL to the CSV (e.g.
	//     https://urlhaus.haus.fail/downloads/csv_recent/).
	//   - misp:    the MISP base URL (e.g. https://misppriv.circl.lu).
	//   - stix-taxii: the collection objects endpoint
	//     (e.g. https://taxii.example/taxii2/collections/<id>/objects/).
	//   - csv:     full URL to the CSV; query string carries the
	//     `type=` and `column=` knobs the generic reader honours.
	URL string
	// APIKey is the credential for providers that require auth
	// (MISP). Loaded from env / secrets manager by the wiring layer.
	APIKey string
	// HTTPClient is supplied by the wiring layer (sn360-es-cli /
	// app.go) and may be nil when the registry decides to
	// construct its own. Providers must accept nil and fall back
	// to a sane default — the tests rely on it.
	HTTPClient HTTPDoer
	// Now is the clock seam. Pollers stamp Indicators with this
	// when the feed itself does not supply a per-indicator
	// timestamp; tests inject a fixed clock.
	Now func() time.Time
}

// HTTPDoer is the minimal HTTP surface every poller depends on. It
// matches the *http.Client.Do signature so the standard library and
// pkg/httpclient both satisfy it for free, and tests can stub it
// without pulling in a full breaker/retry wrapper. In production
// every implementation routes through pkg/httpclient so the
// breaker / retry / metric story stays consistent.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// DefaultHTTPDoer is the fallback the pollers use when FeedConfig.HTTPClient
// is nil. A short timeout prevents a misbehaving feed from holding
// the worker's concurrency slot indefinitely. The 30s value is
// deliberately generous: the URLhaus CSV is ~10 MiB and MISP/STIX
// responses on a cold connection can take ~10s, so a tighter budget
// would flap healthy feeds.
var DefaultHTTPDoer HTTPDoer = &http.Client{Timeout: 30 * time.Second}

// Canonicalise normalises raw indicator bytes and returns a new
// Indicator with the canonicalised value + SHA-256 hash filled in.
// The original Indicator is not mutated. Returns an error if the
// indicator type is unknown, if the value is empty after trimming,
// or if normalisation fails (e.g. invalid IDN punycode, malformed
// URL).
//
// Per-type canonicalisation rules:
//
//   - domain: lowercased, IDN-encoded via golang.org/x/net/idna's
//     Lookup profile (RFC 5891), trailing "." stripped, leading
//     "www." stripped so "WWW.EXAMPLE.COM." and "example.com" land
//     on the same hash.
//
//   - url: parsed as net/url; scheme + host lowercased, host
//     IDN-encoded, default ports stripped, fragment dropped (the
//     fragment is client-side and not observable by upstream
//     defences), trailing slash on a bare host normalised away
//     ("http://x/" → "http://x"). Query string is preserved
//     verbatim because campaign trackers often live in the query.
//
//   - ip: parsed via net/netip.ParseAddr — both IPv4 and IPv6 are
//     supported and the canonical form is the netip String()
//     output (lowercased IPv6 in shortest-form notation). Inputs
//     that fail the parse are rejected with ErrIndicatorMalformed
//     so a malformed feed row cannot accidentally collide with a
//     domain canonicalisation.
//
//   - sha256: lowercased; must be exactly 64 hex chars (32 bytes).
//     Anything else returns ErrIndicatorMalformed so a malformed
//     MISP attribute does not corrupt the hash column.
//
// The returned Indicator.Severity is clamped to [0, 100] to match
// the CHECK constraint on intel_indicators.severity.
func Canonicalise(raw Indicator) (Indicator, error) {
	if !raw.Type.Valid() {
		return Indicator{}, fmt.Errorf("intel: unknown indicator type %q", raw.Type)
	}
	val := strings.TrimSpace(raw.Indicator)
	if val == "" {
		return Indicator{}, ErrIndicatorMalformed
	}
	var (
		canonical string
		err       error
	)
	switch raw.Type {
	case IndicatorDomain:
		canonical, err = canonicaliseDomain(val)
	case IndicatorURL:
		canonical, err = canonicaliseURL(val)
	case IndicatorIP:
		canonical, err = canonicaliseIP(val)
	case IndicatorSHA256:
		canonical, err = canonicaliseSHA256(val)
	}
	if err != nil {
		return Indicator{}, err
	}
	if canonical == "" {
		return Indicator{}, ErrIndicatorMalformed
	}
	sev := raw.Severity
	if sev < 0 {
		sev = 0
	} else if sev > 100 {
		sev = 100
	}
	sum := sha256.Sum256([]byte(canonical))
	out := Indicator{
		Indicator: canonical,
		Type:      raw.Type,
		Hash:      sum[:],
		Severity:  sev,
		Tags:      cleanTags(raw.Tags),
	}
	return out, nil
}

// ErrIndicatorMalformed is returned by Canonicalise when the input
// fails the per-type shape constraints (empty after trim, malformed
// IDN, wrong SHA-256 length, etc.). It is exported so tests can
// errors.Is against it instead of substring-matching error messages.
var ErrIndicatorMalformed = errors.New("intel: indicator malformed")

// HashIndicator returns the SHA-256 of the canonical form of value
// for indicator type t. This is the function the Tier 0 gate calls
// per-URL / per-domain extracted from a message; it shares the same
// canonicaliser pollers use so the bytes hash equally on both sides.
//
// Returns nil + error when canonicalisation fails. The caller (the
// gate) treats a nil hash as "skip this candidate" rather than
// "look up the empty hash", so a malformed URL in a message never
// produces a spurious ti_match.
func HashIndicator(t IndicatorType, value string) ([]byte, error) {
	cn, err := Canonicalise(Indicator{Indicator: value, Type: t})
	if err != nil {
		return nil, err
	}
	return cn.Hash, nil
}

func canonicaliseDomain(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimSuffix(v, ".")
	v = strings.TrimPrefix(v, "www.")
	if v == "" {
		return "", ErrIndicatorMalformed
	}
	// Lookup profile enforces the RFC 5891 IDNA2008 lookup rules
	// (rejects non-XID characters, normalises mixed-script). The
	// returned ASCII form is what we hash.
	ascii, err := idna.Lookup.ToASCII(v)
	if err != nil {
		return "", fmt.Errorf("intel: canonicalise domain %q: %w", v, err)
	}
	return ascii, nil
}

func canonicaliseURL(v string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil {
		return "", fmt.Errorf("intel: canonicalise url %q: %w", v, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", ErrIndicatorMalformed
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", ErrIndicatorMalformed
	}
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil {
		return "", fmt.Errorf("intel: canonicalise url host %q: %w", host, err)
	}
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		u.Host = ascii + ":" + port
	} else {
		u.Host = ascii
	}
	// Drop fragments — they are client-side and feed publishers
	// occasionally include random fragments to deduplicate
	// otherwise-identical URLs.
	u.Fragment = ""
	out := u.String()
	// A naked-host URL ("http://example.com/") and a bare ("http://example.com")
	// produce the same risk verdict; normalise the trailing slash
	// when there is no path component beyond it.
	if u.Path == "/" && u.RawQuery == "" {
		out = strings.TrimSuffix(out, "/")
	}
	return out, nil
}

func canonicaliseIP(v string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return "", fmt.Errorf("intel: canonicalise ip %q: %w", v, ErrIndicatorMalformed)
	}
	return addr.String(), nil
}

func canonicaliseSHA256(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) != 64 {
		return "", fmt.Errorf("intel: sha256 must be 64 hex chars, got %d: %w", len(v), ErrIndicatorMalformed)
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return "", fmt.Errorf("intel: sha256 contains non-hex %q: %w", r, ErrIndicatorMalformed)
		}
	}
	return v, nil
}

// cleanTags drops empty / whitespace-only tag entries and de-dupes
// in stable order. Tags reach the Postgres `tags TEXT[]` column
// verbatim; empty strings would still count toward the GIN index
// size and produce confusing audit dumps.
func cleanTags(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
