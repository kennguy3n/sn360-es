// Package stixtaxii implements the STIX-TAXII 2.1 collection poller
// for the SN360 intel feed layer.
//
// The poller targets the OASIS-standard
// `/taxii2/collections/{collection-id}/objects/` endpoint
// (https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107530).
// The endpoint returns an Envelope object with an `objects` array of
// STIX 2.1 SDOs; this implementation extracts `indicator` SDOs and
// parses the `pattern` field.
//
// Supported pattern shapes (the spec defines a richer grammar but
// most operational feeds restrict themselves to these simple cases,
// and the Tier 0 gate cannot match on the more exotic ones):
//
//	[domain-name:value = 'evil.example']
//	[url:value = 'http://evil.example/path']
//	[ipv4-addr:value = '203.0.113.42']
//	[ipv6-addr:value = '2001:db8::1']
//	[file:hashes.'SHA-256' = '0123…<64 hex>']
//
// Multi-clause patterns joined by AND / OR / FOLLOWEDBY are
// flattened: each clause becomes a separate Indicator (with the
// same severity / tags inherited from the parent SDO). This is
// the same behaviour the upstream `python-stix2` library exposes
// via `stix2.parsing.parse_pattern` and avoids dropping a feed
// row entirely just because one clause uses an unsupported
// observable type.
//
// Pagination follows the TAXII 2.1 cursor protocol: when the
// response includes `more=true` we re-request with `?next=<value>`
// from the envelope. The loop terminates when `more` is false or
// absent or when ctx is cancelled.
//
// Authentication is via `Authorization: Bearer <token>` when
// FeedConfig.APIKey is supplied. Anonymous public collections (a
// common shape for community-shared TI) are allowed when APIKey
// is empty.
package stixtaxii

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// Provider is the registry key.
const Provider = "stix-taxii"

// maxPages bounds the cursor loop. The TAXII 2.1 server can
// technically return many small pages; capping at 1000 mirrors
// the MISP poller and gives us a 1M-object ceiling per poll.
const maxPages = 1000

func init() {
	intel.DefaultRegistry.MustRegister(Provider, New)
}

// Poller is the STIX-TAXII implementation of intel.Poller.
type Poller struct {
	cfg     intel.FeedConfig
	baseURL *url.URL
}

// New constructs a Poller. FeedConfig.URL must already be the
// collection-objects endpoint (e.g.
// `https://taxii.example.com/taxii2/collections/<id>/objects/`);
// the constructor will not synthesise the path.
func New(cfg intel.FeedConfig) (intel.Poller, error) {
	if cfg.URL == "" {
		return nil, errors.New("stixtaxii: feed url required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("stixtaxii: parse url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("stixtaxii: url must be absolute")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = intel.DefaultHTTPDoer
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Poller{cfg: cfg, baseURL: u}, nil
}

// Provider returns the registry key.
func (p *Poller) Provider() string { return Provider }

// Poll walks the TAXII 2.1 collection-objects endpoint, paginating
// via the `next` cursor when the server signals more pages.
func (p *Poller) Poll(ctx context.Context) (intel.Result, error) {
	all := make([]intel.Indicator, 0, 512)
	next := ""
	for page := 0; page < maxPages; page++ {
		u := *p.baseURL
		if next != "" {
			q := u.Query()
			q.Set("next", next)
			u.RawQuery = q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return intel.Result{}, fmt.Errorf("stixtaxii: build request: %w", err)
		}
		req.Header.Set("Accept", "application/taxii+json;version=2.1")
		req.Header.Set("User-Agent", "sn360-es/intel-stixtaxii")
		if p.cfg.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
		}
		resp, err := p.cfg.HTTPClient.Do(req)
		if err != nil {
			return intel.Result{}, fmt.Errorf("stixtaxii: http: %w", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
		_ = resp.Body.Close()
		if readErr != nil {
			return intel.Result{}, fmt.Errorf("stixtaxii: read: %w", readErr)
		}
		if resp.StatusCode/100 != 2 {
			truncated := raw
			if len(truncated) > 1024 {
				truncated = truncated[:1024]
			}
			return intel.Result{}, fmt.Errorf("stixtaxii: http %d: %s",
				resp.StatusCode, strings.TrimSpace(string(truncated)))
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return intel.Result{}, fmt.Errorf("stixtaxii: decode: %w", err)
		}
		all = append(all, decodeObjects(env.Objects)...)
		if !bool(env.More) || env.Next == "" {
			return intel.Result{Indicators: all}, nil
		}
		next = env.Next
	}
	return intel.Result{}, fmt.Errorf("stixtaxii: pagination exceeded %d pages", maxPages)
}

// Decode parses a TAXII envelope from r and returns the resulting
// Indicators. Exported for unit-test use without HTTP.
func Decode(r io.Reader) (intel.Result, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return intel.Result{}, fmt.Errorf("stixtaxii: read: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return intel.Result{}, fmt.Errorf("stixtaxii: decode: %w", err)
	}
	return intel.Result{Indicators: decodeObjects(env.Objects)}, nil
}

// decodeObjects walks a STIX `objects` array and emits Indicators
// for every `indicator` SDO whose pattern parses.
func decodeObjects(objs []stixObject) []intel.Indicator {
	out := make([]intel.Indicator, 0, len(objs)*2)
	for _, o := range objs {
		if o.Type != "indicator" {
			continue
		}
		sev := severityFromConfidence(o.Confidence)
		tags := append([]string{}, o.Labels...)
		for _, clause := range parsePattern(o.Pattern) {
			ind, err := intel.Canonicalise(intel.Indicator{
				Indicator: clause.value,
				Type:      clause.typ,
				Severity:  sev,
				Tags:      tags,
			})
			if err == nil {
				out = append(out, ind)
			}
		}
	}
	return out
}

// severityFromConfidence maps the optional STIX confidence (0-100)
// into our severity scale. When the SDO omits confidence we fall
// back to 60 (mid).
func severityFromConfidence(c int) int {
	if c <= 0 {
		return 60
	}
	if c > 100 {
		return 100
	}
	return c
}

// patternClause is one extracted observable-object clause from a
// STIX pattern.
type patternClause struct {
	typ   intel.IndicatorType
	value string
}

// parsePattern teases out the simple `[obs:prop = 'value']`
// clauses from a STIX pattern string. Multi-clause patterns
// separated by AND / OR / FOLLOWEDBY produce multiple clauses.
//
// We deliberately do NOT implement the full STIX pattern grammar
// (set-membership, regex, temporal qualifiers) — those produce
// observables the Tier 0 gate cannot evaluate at hot-path
// latency. The supported subset covers every IOC operational
// feeds we have onboarded so far.
//
// The regex is written defensively: the observable path is split
// from the value via `=`, then trimmed; any clause that fails the
// shape is dropped silently rather than poisoning the rest of
// the pattern.
// The value regex `((?:[^'\\]|\\.)*)` accepts STIX escape pairs
// (`\\`, `\'`, …) inside the single-quoted string, mirroring the
// STIX 2.1 pattern grammar. The post-extraction unquoteSTIX call
// then collapses the escape pairs back to their literal bytes.
var clauseRegex = regexp.MustCompile(`\[\s*([a-zA-Z0-9_\-]+):([a-zA-Z0-9_\-\.\:'"\\]+)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]`)

func parsePattern(pattern string) []patternClause {
	matches := clauseRegex.FindAllStringSubmatch(pattern, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]patternClause, 0, len(matches))
	for _, m := range matches {
		if len(m) != 4 {
			continue
		}
		objType := strings.ToLower(m[1])
		prop := strings.ToLower(m[2])
		value, err := unquoteSTIX(m[3])
		if err != nil {
			continue
		}
		typ, ok := mapObservable(objType, prop)
		if !ok {
			continue
		}
		out = append(out, patternClause{typ: typ, value: value})
	}
	return out
}

// unquoteSTIX undoes the STIX pattern escapes for single quotes
// and backslashes. The grammar mandates `\\` for `\` and `\'` for
// `'`; everything else is left as-is.
func unquoteSTIX(s string) (string, error) {
	if !strings.ContainsRune(s, '\\') {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("stixtaxii: dangling escape")
		}
		next := s[i+1]
		b.WriteByte(next)
		i++
	}
	return b.String(), nil
}

// mapObservable translates the STIX observable type + property
// pair onto our indicator-type taxonomy. The hashes case carries
// the algorithm name in the property (e.g. `hashes.'SHA-256'`),
// which we strip down to the family.
func mapObservable(objType, prop string) (intel.IndicatorType, bool) {
	switch objType {
	case "domain-name":
		if prop == "value" {
			return intel.IndicatorDomain, true
		}
	case "url":
		if prop == "value" {
			return intel.IndicatorURL, true
		}
	case "ipv4-addr", "ipv6-addr":
		if prop == "value" {
			return intel.IndicatorIP, true
		}
	case "file":
		if strings.Contains(prop, "sha-256") || strings.Contains(prop, "sha256") {
			return intel.IndicatorSHA256, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------
// On-wire shapes — minimal subset of STIX 2.1 / TAXII 2.1.
// ---------------------------------------------------------------------

type envelope struct {
	More    boolish      `json:"more"`
	Next    string       `json:"next"`
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type       string   `json:"type"`
	Pattern    string   `json:"pattern"`
	Confidence int      `json:"confidence,omitempty"`
	Labels     []string `json:"labels,omitempty"`
}

// boolish is the polymorphic shape some TAXII servers emit for
// `more` — depending on the implementation it might be an actual
// boolean, the string "true"/"false", or even integer 1/0. The
// UnmarshalJSON converter coerces all of these into a Go bool.
type boolish bool

// UnmarshalJSON implements json.Unmarshaler.
func (b *boolish) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "true" {
		*b = true
		return nil
	}
	if s == "false" || s == "null" || s == "" {
		*b = false
		return nil
	}
	// Try strings first.
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := strings.ToLower(s[1 : len(s)-1])
		*b = inner == "true" || inner == "1"
		return nil
	}
	// Numeric.
	if n, err := strconv.Atoi(s); err == nil {
		*b = n != 0
		return nil
	}
	return fmt.Errorf("stixtaxii: cannot parse boolish %q", s)
}

// Bool returns the underlying boolean, for tests.
func (b boolish) Bool() bool { return bool(b) }
