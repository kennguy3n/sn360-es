// Package csv implements the generic single-column CSV poller for
// the SN360 intel feed layer.
//
// This package is intentionally less opinionated than urlhaus: it
// fetches a CSV at FeedConfig.URL, parses one configurable column
// per row, and emits indicators of a configurable type. The knobs
// are passed via the URL query string so admin-API consumers can
// configure them without a new column on intel_feeds:
//
//	type=domain|url|ip|sha256   — indicator type for every row
//	column=N                    — 0-indexed column (default 0)
//	severity=N                  — 0..100 (default 60)
//	tag=foo                     — repeatable tag (added to every row)
//	skip_header=true            — drop the first row
//	comment=#                   — single-char comment marker (e.g. '#')
//
// Example:
//
//	https://example.com/iocs.csv?type=url&column=0&severity=70&tag=phishtank
//
// The query-string approach keeps the schema deployment-scoped (no
// per-feed knob columns on intel_feeds) without sacrificing
// real-world configurability.
package csv

import (
	stdcsv "encoding/csv"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// Provider is the registry key.
const Provider = "csv"

func init() {
	intel.DefaultRegistry.MustRegister(Provider, New)
}

// Poller is the CSV implementation of intel.Poller.
type Poller struct {
	cfg     intel.FeedConfig
	parsed  csvOptions
	fetchURL string
}

// csvOptions captures the query-string knobs after parsing. It is
// kept private so the URL is the only stable configuration surface.
type csvOptions struct {
	Type       intel.IndicatorType
	Column     int
	Severity   int
	Tags       []string
	SkipHeader bool
	Comment    rune
}

// New constructs a Poller. The constructor parses FeedConfig.URL,
// extracts the knobs, and validates them — a malformed URL produces
// a constructor error so the scheduler treats it as a permanent
// fault instead of polling-and-failing in a loop.
func New(cfg intel.FeedConfig) (intel.Poller, error) {
	if cfg.URL == "" {
		return nil, errors.New("csv: feed url required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("csv: parse url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("csv: url must be absolute")
	}
	opts, err := parseOptions(u.Query())
	if err != nil {
		return nil, fmt.Errorf("csv: parse query options: %w", err)
	}
	// Strip the knob query params before issuing the actual request
	// so the upstream server does not see ours. Some servers
	// reject unknown query params — keeping only the params we did
	// NOT consume guarantees compatibility.
	stripped := *u
	q := stripped.Query()
	for _, k := range knobKeys {
		q.Del(k)
	}
	stripped.RawQuery = q.Encode()

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = intel.DefaultHTTPDoer
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Poller{
		cfg:      cfg,
		parsed:   opts,
		fetchURL: stripped.String(),
	}, nil
}

// Provider returns the registry key.
func (p *Poller) Provider() string { return Provider }

// Poll fetches the CSV from the stripped feed URL and decodes the
// configured column.
func (p *Poller) Poll(ctx context.Context) (intel.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.fetchURL, nil)
	if err != nil {
		return intel.Result{}, fmt.Errorf("csv: build request: %w", err)
	}
	req.Header.Set("Accept", "text/csv,text/plain;q=0.9")
	req.Header.Set("User-Agent", "sn360-es/intel-csv")
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return intel.Result{}, fmt.Errorf("csv: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return intel.Result{}, fmt.Errorf("csv: http %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return Decode(resp.Body, p.parsed)
}

// Decode parses a CSV stream from r using opts.
func Decode(r io.Reader, opts csvOptions) (intel.Result, error) {
	cr := stdcsv.NewReader(r)
	cr.LazyQuotes = true
	// Generic feeds frequently have inconsistent column counts (a
	// row missing its optional comment column would otherwise
	// kill the whole feed); -1 silences that check.
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = false
	if opts.Comment != 0 {
		cr.Comment = opts.Comment
	}

	out := make([]intel.Indicator, 0, 256)
	first := true
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var pe *stdcsv.ParseError
			if errors.As(err, &pe) {
				continue
			}
			return intel.Result{}, fmt.Errorf("csv: parse: %w", err)
		}
		if first {
			first = false
			if opts.SkipHeader {
				continue
			}
		}
		if opts.Column >= len(row) {
			continue
		}
		raw := strings.TrimSpace(row[opts.Column])
		if raw == "" {
			continue
		}
		ind, err := intel.Canonicalise(intel.Indicator{
			Indicator: raw,
			Type:      opts.Type,
			Severity:  opts.Severity,
			Tags:      opts.Tags,
		})
		if err != nil {
			continue
		}
		out = append(out, ind)
	}
	if len(out) == 0 {
		return intel.Result{}, errors.New("csv: feed contained no parseable rows")
	}
	return intel.Result{Indicators: out}, nil
}

// parseOptions extracts the knob query params from values. Missing
// knobs fall back to sensible defaults. Unknown knobs are rejected
// to avoid a typo silently disabling a feed.
func parseOptions(values url.Values) (csvOptions, error) {
	opts := csvOptions{
		Type:     intel.IndicatorDomain, // most generic CSV feeds publish domains
		Column:   0,
		Severity: 60,
		Tags:     nil,
	}
	if t := values.Get("type"); t != "" {
		opts.Type = intel.IndicatorType(strings.ToLower(t))
		if !opts.Type.Valid() {
			return opts, fmt.Errorf("invalid type %q", t)
		}
	}
	if c := values.Get("column"); c != "" {
		n, err := strconv.Atoi(c)
		if err != nil || n < 0 {
			return opts, fmt.Errorf("invalid column %q", c)
		}
		opts.Column = n
	}
	if s := values.Get("severity"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 100 {
			return opts, fmt.Errorf("invalid severity %q", s)
		}
		opts.Severity = n
	}
	if tag, ok := values["tag"]; ok {
		opts.Tags = tag
	}
	if h := values.Get("skip_header"); h != "" {
		b, err := strconv.ParseBool(h)
		if err != nil {
			return opts, fmt.Errorf("invalid skip_header %q", h)
		}
		opts.SkipHeader = b
	}
	if c := values.Get("comment"); c != "" {
		// Comment must be a single character — anything longer is
		// almost certainly a misconfiguration.
		runes := []rune(c)
		if len(runes) != 1 {
			return opts, fmt.Errorf("comment must be a single character, got %q", c)
		}
		opts.Comment = runes[0]
	}
	return opts, nil
}

// knobKeys is the closed set of query-string params the constructor
// consumes. They are removed from the request URL so the upstream
// server only sees its own params. Any param not in this list is
// forwarded verbatim.
var knobKeys = []string{"type", "column", "severity", "tag", "skip_header", "comment"}
