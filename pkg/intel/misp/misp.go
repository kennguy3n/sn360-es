// Package misp implements the MISP threat-intel poller for the
// SN360 intel feed layer.
//
// MISP (https://www.misp-project.org/) exposes its events through
// `POST /events/restSearch`. The request body carries a JSON
// search filter; the response is a `{"response":[{ "Event": {...} }]}`
// envelope where each Event has zero or more `Attribute` blobs
// describing IOCs.
//
// Real spec-compliance:
//
//   - Authentication: every request carries an `Authorization: <api-key>`
//     header (MISP does NOT use a Bearer prefix). The key comes from
//     the `INTEL_MISP_API_KEY` environment variable (wired via
//     FeedConfig.APIKey by the scheduler).
//   - Accept: application/json — MISP otherwise returns HTML on
//     pages a logged-in browser would visit, which would
//     short-circuit JSON parsing.
//   - Pagination: the API accepts `page` (1-based) and `limit`
//     fields in the JSON body. Pagination loops in 1000-row pages
//     until an empty response is observed or the safety bound
//     (maxPages) is reached.
//
// Attribute → indicator mapping:
//
//	type='url'                            → IndicatorURL
//	type∈{'domain','hostname'}            → IndicatorDomain
//	type∈{'ip-src','ip-dst','ip'}         → IndicatorIP
//	type='sha256'                         → IndicatorSHA256
//	(other types are dropped — MISP carries many attribute types
//	the Tier 0 gate cannot match on, e.g. mutex, regkey, yara.)
//
// Severity is derived from the per-Attribute `to_ids` boolean and
// the parent Event's `threat_level_id`:
//
//	to_ids=true & threat_level_id=1 → 90  (high)
//	to_ids=true & threat_level_id=2 → 75
//	to_ids=true & threat_level_id=3 → 60
//	to_ids=false                    → 30  (informational)
//
// Tags carry the Attribute's `tag` list (MISP tags namespace, e.g.
// "tlp:amber", "malware_classification:type=ransomware") so the
// Tier 0 audit log preserves the analyst-supplied context.
package misp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// Provider is the registry key.
const Provider = "misp"

// pageSize is the limit per restSearch call. MISP defaults to 25
// when limit is unset which would balloon the round-trip count on
// large feeds; 1000 matches MISP's documented recommended ceiling
// for batch consumers.
const pageSize = 1000

// maxPages bounds the pagination loop. 1000 pages × 1000 rows ⇒
// 1,000,000 attributes per poll. Hitting this cap with a non-empty
// final page yields a fatal poll error so operators can investigate
// the runaway feed rather than silently truncating.
const maxPages = 1000

func init() {
	intel.DefaultRegistry.MustRegister(Provider, New)
}

// Poller is the MISP implementation of intel.Poller.
type Poller struct {
	cfg     intel.FeedConfig
	baseURL *url.URL
}

// New constructs a Poller. FeedConfig.URL must be the MISP base URL
// (e.g. https://misppriv.circl.lu); the constructor appends
// `/events/restSearch` for each call so operators don't have to
// repeat the path in the admin form.
func New(cfg intel.FeedConfig) (intel.Poller, error) {
	if cfg.URL == "" {
		return nil, errors.New("misp: feed url required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("misp: parse url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("misp: url must be absolute")
	}
	if cfg.APIKey == "" {
		return nil, errors.New("misp: api key required (INTEL_MISP_API_KEY)")
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

// Poll fetches every page of /events/restSearch and decodes the
// Attribute lists into Indicators.
//
// The pagination loop terminates when the server returns an empty
// `response` array (the MISP convention for "no more rows"), when
// fewer than `pageSize` rows come back on a page (the alternate
// MISP convention used by older versions), or when ctx is
// cancelled. A non-empty page at index `maxPages` is treated as
// fatal so a misbehaving feed cannot exhaust worker time.
func (p *Poller) Poll(ctx context.Context) (intel.Result, error) {
	endpoint := *p.baseURL
	endpoint.Path = joinPath(endpoint.Path, "/events/restSearch")

	all := make([]intel.Indicator, 0, 1024)
	for page := 1; page <= maxPages; page++ {
		body, err := json.Marshal(searchRequest{
			ReturnFormat: "json",
			Page:         page,
			Limit:        pageSize,
		})
		if err != nil {
			return intel.Result{}, fmt.Errorf("misp: encode request: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
		if err != nil {
			return intel.Result{}, fmt.Errorf("misp: build request: %w", err)
		}
		req.Header.Set("Authorization", p.cfg.APIKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "sn360-es/intel-misp")

		resp, err := p.cfg.HTTPClient.Do(req)
		if err != nil {
			return intel.Result{}, fmt.Errorf("misp: http page %d: %w", page, err)
		}
		// Always drain + close so the underlying connection is
		// returned to the pool even on early returns.
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
		_ = resp.Body.Close()
		if readErr != nil {
			return intel.Result{}, fmt.Errorf("misp: read page %d: %w", page, readErr)
		}
		if resp.StatusCode/100 != 2 {
			truncated := raw
			if len(truncated) > 1024 {
				truncated = truncated[:1024]
			}
			return intel.Result{}, fmt.Errorf("misp: http %d on page %d: %s",
				resp.StatusCode, page, strings.TrimSpace(string(truncated)))
		}
		var env restSearchResponse
		if err := json.Unmarshal(raw, &env); err != nil {
			return intel.Result{}, fmt.Errorf("misp: decode page %d: %w", page, err)
		}
		events := env.Response
		if len(events) == 0 {
			break
		}
		pageIndicators := decodeEvents(events)
		all = append(all, pageIndicators...)
		// The "fewer than pageSize" termination signal: MISP
		// pre-1.2 servers do not return an empty page; the
		// final page is just short. Either signal works.
		if len(events) < pageSize {
			break
		}
		if page == maxPages {
			return intel.Result{}, fmt.Errorf("misp: pagination exceeded %d pages — runaway feed?", maxPages)
		}
	}
	return intel.Result{Indicators: all}, nil
}

// decodeEvents extracts Indicators from a slice of MISP Event
// envelopes. Exported indirectly through Decode (for tests).
func decodeEvents(events []eventEnvelope) []intel.Indicator {
	out := make([]intel.Indicator, 0, len(events)*8)
	for _, ev := range events {
		// MISP nests the actual event under .Event; both shapes
		// appear in the wild (older fixtures use a flat event
		// object). Use whichever is populated.
		event := ev.Event
		if event.UUID == "" && len(event.Attribute) == 0 && len(ev.Attribute) > 0 {
			event = ev.flat()
		}
		baseSeverity := severityFromThreatLevel(event.ThreatLevelID)
		for _, a := range event.Attribute {
			t, ok := mapAttributeType(a.Type)
			if !ok {
				continue
			}
			sev := baseSeverity
			if !boolFromMISP(a.ToIDs) {
				// Non-actionable attributes get a lower
				// severity floor regardless of the parent
				// event's threat_level_id.
				sev = 30
			}
			tags := tagNames(a.Tag)
			tags = append(tags, tagNames(event.Tag)...)
			ind, err := intel.Canonicalise(intel.Indicator{
				Indicator: strings.TrimSpace(a.Value),
				Type:      t,
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

// mapAttributeType translates MISP attribute type to our
// indicator-type taxonomy. Returns ok=false for types the gate
// cannot match on (mutex, yara, regkey, etc.) so they are silently
// dropped — these would otherwise pollute the index with rows the
// gate never looks up.
func mapAttributeType(t string) (intel.IndicatorType, bool) {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "url":
		return intel.IndicatorURL, true
	case "domain", "hostname":
		return intel.IndicatorDomain, true
	case "ip-src", "ip-dst", "ip":
		return intel.IndicatorIP, true
	case "sha256":
		return intel.IndicatorSHA256, true
	}
	return "", false
}

func severityFromThreatLevel(level string) int {
	switch level {
	case "1":
		return 90
	case "2":
		return 75
	case "3":
		return 60
	default:
		return 50
	}
}

// boolFromMISP normalises the polymorphic boolean shape MISP returns:
// some endpoints serialise `to_ids` as the JSON booleans, some as
// the strings "0" / "1", and some as integer 0/1. The wrapper
// accepts any of those.
func boolFromMISP(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "1" || strings.EqualFold(x, "true")
	case float64:
		return x != 0
	case int:
		return x != 0
	case json.Number:
		i, _ := x.Int64()
		return i != 0
	}
	return false
}

// tagNames extracts the `name` field from a MISP tag list.
func tagNames(tags []tagEnvelope) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		n := strings.TrimSpace(t.Name)
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

// joinPath glues two URL path components together, normalising the
// boundary so the caller does not need to care whether the base
// ended in "/".
func joinPath(base, suffix string) string {
	base = strings.TrimRight(base, "/")
	suffix = "/" + strings.TrimLeft(suffix, "/")
	return base + suffix
}

// ---------------------------------------------------------------------
// On-wire shapes.
// ---------------------------------------------------------------------

type searchRequest struct {
	ReturnFormat string `json:"returnFormat"`
	Page         int    `json:"page"`
	Limit        int    `json:"limit"`
}

type restSearchResponse struct {
	Response []eventEnvelope `json:"response"`
}

type eventEnvelope struct {
	Event     event         `json:"Event"`
	Attribute []attribute   `json:"Attribute,omitempty"`
	Tag       []tagEnvelope `json:"Tag,omitempty"`
}

// flat returns a synthetic Event built from the envelope's
// flat-shape fields (older MISP responses). Used when ev.Event is
// empty but ev itself carries attributes directly.
func (e eventEnvelope) flat() event {
	return event{
		Attribute: e.Attribute,
		Tag:       e.Tag,
	}
}

type event struct {
	UUID          string        `json:"uuid"`
	ThreatLevelID string        `json:"threat_level_id"`
	Attribute     []attribute   `json:"Attribute"`
	Tag           []tagEnvelope `json:"Tag"`
}

type attribute struct {
	Type  string        `json:"type"`
	Value string        `json:"value"`
	ToIDs any           `json:"to_ids"`
	Tag   []tagEnvelope `json:"Tag"`
}

type tagEnvelope struct {
	Name string `json:"name"`
}

// Decode parses a MISP /events/restSearch JSON payload from r and
// returns the resulting Indicators. Exported so unit tests can run
// without spinning up an HTTP server.
func Decode(r io.Reader) (intel.Result, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return intel.Result{}, fmt.Errorf("misp: read: %w", err)
	}
	var env restSearchResponse
	if err := json.Unmarshal(raw, &env); err != nil {
		return intel.Result{}, fmt.Errorf("misp: decode: %w", err)
	}
	return intel.Result{Indicators: decodeEvents(env.Response)}, nil
}
