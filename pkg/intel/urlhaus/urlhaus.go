// Package urlhaus implements the URLhaus CSV poller for the threat-
// intel feed layer.
//
// URLhaus (https://urlhaus.abuse.ch/) publishes a recent-URL CSV
// at https://urlhaus.haus.fail/downloads/csv_recent/. The file is
// pipe-noisy with leading comment lines beginning with '#' that
// the parser must skip. Each data row has the columns documented
// at https://urlhaus.abuse.ch/api/#csv :
//
//	id, dateadded, url, url_status, last_online, threat, tags,
//	urlhaus_link, reporter
//
// Every row carries a URL indicator; the URL's host is also emitted
// as a domain indicator so the Tier 0 gate matches both a verbatim
// URL hit and a "any URL on this host" hit. URLhaus rotates
// aggressively (URLs go offline within hours), so the worker's GC
// is what keeps stale indicators from causing false positives.
//
// The constructor registers itself on pkg/intel.DefaultRegistry under
// the key "urlhaus" via init(). Importers do not need to call the
// constructor directly; the registry-driven scheduler dispatches.
package urlhaus

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// Provider is the registry key. Exported so callers can reference
// it by constant rather than by stringly-typed key.
const Provider = "urlhaus"

func init() {
	intel.DefaultRegistry.MustRegister(Provider, New)
}

// Poller is the urlhaus implementation of intel.Poller. The struct
// holds the per-feed config — there are no mutable fields, so the
// poller is safe to keep across calls.
type Poller struct {
	cfg intel.FeedConfig
}

// New constructs a Poller from cfg. The URL field is validated
// against a minimal shape (scheme + host) so a misconfigured feed
// fails at registration time rather than on the first poll.
func New(cfg intel.FeedConfig) (intel.Poller, error) {
	if cfg.URL == "" {
		return nil, errors.New("urlhaus: feed url required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: parse url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("urlhaus: url must be absolute")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = intel.DefaultHTTPDoer
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Poller{cfg: cfg}, nil
}

// Provider returns the registry key.
func (p *Poller) Provider() string { return Provider }

// Poll fetches the URLhaus CSV and decodes it into Indicators.
//
// Two indicators are emitted per row: the URL itself
// (IndicatorURL) and the host portion (IndicatorDomain). The host
// emission is what catches "any phishing kit hosted on this
// throwaway domain" cases — URLhaus URLs rotate within hours but
// the underlying compromised host often stays poisoned for days.
//
// Severity is mapped from the URLhaus `url_status` column:
//   - "online":   80 (high — actively serving payload)
//   - "offline":  40 (lower — host blackholed; keep for retro detection)
//   - other:      60 (default — unknown but listed)
//
// Tags carry the raw threat label (e.g. "malware_download") and
// any reporter tags so audit queries (`tags @> ARRAY['emotet']`)
// stay useful.
func (p *Poller) Poll(ctx context.Context) (intel.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.URL, nil)
	if err != nil {
		return intel.Result{}, fmt.Errorf("urlhaus: build request: %w", err)
	}
	req.Header.Set("Accept", "text/csv,text/plain;q=0.9")
	req.Header.Set("User-Agent", "sn360-es/intel-urlhaus")
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return intel.Result{}, fmt.Errorf("urlhaus: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		// Drain & truncate the body so the error message is
		// useful but bounded.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return intel.Result{}, fmt.Errorf("urlhaus: http %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return Decode(resp.Body)
}

// Decode parses the URLhaus CSV payload from r and returns
// canonicalised Indicators. Exported so unit tests can exercise the
// parser against committed fixture bytes without going through the
// HTTP path.
//
// Behaviour:
//
//   - Lines beginning with '#' (the URLhaus header / comment block)
//     are skipped — these are NOT valid CSV records and the
//     stdlib reader would reject the file otherwise.
//   - The CSV reader is configured FieldsPerRecord=-1 because
//     URLhaus emits an inconsistent column count across rows
//     (the `tags` column is a free-form comma-separated list
//     URLhaus quotes inconsistently; FieldsPerRecord=-1 tells the
//     reader to accept whatever shape each row carries rather
//     than aborting on the first mismatch).
//   - LazyQuotes=true because URLhaus has historically published
//     rows with literal double-quotes inside unquoted fields.
//   - Rows whose URL fails Canonicalise() are skipped, not fatal:
//     a single malformed row from a public feed should not
//     suppress every well-formed row behind it.
func Decode(r io.Reader) (intel.Result, error) {
	// URLhaus prefixes the CSV with a ~30-line "Description"
	// block whose lines begin with '#'. encoding/csv handles
	// these natively when Comment is set, so we just configure
	// the reader instead of pre-stripping.
	cr := csv.NewReader(r)
	cr.LazyQuotes = true
	// FieldsPerRecord=-1 because URLhaus emits inconsistent
	// column counts (the free-form `tags` field is quoted
	// inconsistently); -1 tells encoding/csv to accept whatever
	// shape each row carries rather than aborting on the first
	// mismatch.
	cr.FieldsPerRecord = -1
	cr.Comment = '#'
	cr.ReuseRecord = false

	out := make([]intel.Indicator, 0, 256)
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// One malformed row should not poison the whole feed.
			// csv.Reader returns ErrFieldCount and ErrQuote as
			// errors but advances past them; just skip and
			// continue. A wrapped i/o error (transport reset) is
			// fatal because the stream is no longer usable.
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				continue
			}
			return intel.Result{}, fmt.Errorf("urlhaus: csv: %w", err)
		}
		if len(row) < 6 {
			// Minimum useful row has id, dateadded, url, status,
			// last_online, threat — anything narrower is junk.
			continue
		}
		rawURL := strings.TrimSpace(row[2])
		status := strings.ToLower(strings.TrimSpace(row[3]))
		threat := strings.TrimSpace(row[5])
		var tagList []string
		if len(row) > 6 {
			tagList = splitTags(row[6])
		}
		if threat != "" {
			tagList = append(tagList, threat)
		}
		sev := severityFromStatus(status)
		urlInd, err := intel.Canonicalise(intel.Indicator{
			Indicator: rawURL,
			Type:      intel.IndicatorURL,
			Severity:  sev,
			Tags:      tagList,
		})
		if err == nil {
			out = append(out, urlInd)
			// Emit the host as a separate domain indicator so a
			// later URL on the same host (different path / query)
			// still hits via the domain match.
			if host := extractHost(rawURL); host != "" {
				domInd, dErr := intel.Canonicalise(intel.Indicator{
					Indicator: host,
					Type:      intel.IndicatorDomain,
					Severity:  sev,
					Tags:      tagList,
				})
				if dErr == nil {
					out = append(out, domInd)
				}
			}
		}
	}
	if len(out) == 0 {
		// A successful HTTP 200 with zero parsed rows almost
		// always means the URLhaus CSV format changed; surface
		// it as a poll error so the operator notices via the
		// 3-strike alerter.
		return intel.Result{}, errors.New("urlhaus: feed contained no parseable rows")
	}
	return intel.Result{Indicators: out}, nil
}

// extractHost returns the host portion of rawURL or "" when the URL
// cannot be parsed. The Tier 0 gate's domain lookup hits the bare
// host — port stripping happens in intel.Canonicalise(domain).
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// splitTags splits the URLhaus `tags` column, which is comma-
// separated and frequently double-quoted-with-internal-commas
// when a tag itself contains a comma. Empty / whitespace tags
// are dropped.
func splitTags(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// severityFromStatus maps URLhaus' `url_status` column onto our
// 0-100 severity scale. The numeric choices are documented on the
// struct comment.
func severityFromStatus(status string) int {
	switch status {
	case "online":
		return 80
	case "offline":
		return 40
	default:
		return 60
	}
}

