package tier0

import (
	"context"
	"net/mail"
	"regexp"
	"sort"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/intel"
)

// TIChecker is the threat-intel lookup port consumed by the Tier 0
// gate. Implementations resolve a single (canonical) message into a
// list of indicator matches — by canonicalising the sender domain,
// recipient domain (sometimes), and every URL/host in the body, then
// hashing each candidate and issuing a single batched LookupByHash
// against intel_indicators.
//
// The interface stays narrow so the gate stays decoupled from both
// the persistence layer (PgIntelStore) and any caching layer (a
// future Redis-backed implementation can wrap a base TIChecker
// without the gate noticing).
//
// Implementations MUST be safe for concurrent use — the Tier 0 gate
// is called from every message-evaluation path.
type TIChecker interface {
	// Check looks up indicators for the given message. The
	// returned slice is in feed-arbitrary order. Implementations
	// MUST NOT return an error for "no match" — return an empty
	// slice instead. Errors are reserved for upstream failures
	// (DB / cache outages); the gate treats them as soft-fail
	// (no ti_match reason code emitted, the message proceeds to
	// the ML stages as if the lookup had not happened).
	Check(ctx context.Context, req dto.EvaluateRequest, signals dto.RiskSignals) ([]intel.MatchedIndicator, error)
}

// NoopTIChecker is the zero-effort implementation. The gate uses it
// when the deployment has disabled the intel feature.
type NoopTIChecker struct{}

// Check always returns no matches.
func (NoopTIChecker) Check(_ context.Context, _ dto.EvaluateRequest, _ dto.RiskSignals) ([]intel.MatchedIndicator, error) {
	return nil, nil
}

// StoreTIChecker wires a TIChecker against an intel.IntelStore. It is
// the production implementation: it canonicalises every candidate
// indicator surfaced by the message, batches them into a single
// LookupByHash, and returns the matches verbatim.
//
// The store interface is the same one PgIntelStore implements — the
// gate is therefore deployment-scoped (no tenant binder, no RLS) by
// construction.
type StoreTIChecker struct {
	Store intel.IntelStore
	// Cache is the optional negative-cache layer. nil means "no
	// caching — every Check issues a fresh LookupByHash".
	Cache TICache
	// MaxCandidates caps the number of indicators hashed per
	// message. Default 32. Large values still issue a single SQL
	// query but cost more canonicalisation; the cap prevents a
	// 10-MB body with 5,000 link tags from blowing the hot path.
	MaxCandidates int
}

// TICache is the optional negative-cache layer fronting LookupByHash.
// Hits short-circuit the DB; misses fall through and write back the
// result with a configurable TTL.
type TICache interface {
	// GetHashes returns the cached match (or absent flag) for each
	// hash. Implementations MUST return per-hash entries indexed
	// by the order of `hashes`; len(out) == len(hashes).
	GetHashes(ctx context.Context, hashes [][]byte) []TICacheEntry
	// SetHash stores the lookup result for a single hash.
	SetHash(ctx context.Context, hash []byte, matches []intel.MatchedIndicator)
}

// TICacheEntry is one cached lookup result.
type TICacheEntry struct {
	// Present reports whether the cache holds a value for this
	// hash. False means "cache miss; fall through to DB".
	Present bool
	// Matches holds the cached matches. Empty slice + Present==true
	// is the negative cache (hash known to be absent).
	Matches []intel.MatchedIndicator
}

// Check implements TIChecker.
//
// The pipeline:
//  1. Extract candidate indicators (sender domain, every URL/host in
//     the body) from the request.
//  2. Canonicalise each one and SHA-256 hash it. Duplicate hashes
//     are dropped before the lookup so a body with 50 references to
//     the same domain costs one row, not 50.
//  3. Issue ONE batched LookupByHash for the deduplicated hashes.
//
// On any error the function returns the error AND the partial
// matches accumulated so far (callers may opt to still emit
// ti_match if they have at least one hit). Production callers
// always treat err != nil as "soft fail; skip ti_match".
func (s *StoreTIChecker) Check(ctx context.Context, req dto.EvaluateRequest, signals dto.RiskSignals) ([]intel.MatchedIndicator, error) {
	if s == nil || s.Store == nil {
		return nil, nil
	}

	candidates := ExtractCandidates(req, signals)
	maxCand := s.MaxCandidates
	if maxCand <= 0 {
		maxCand = 32
	}
	if len(candidates) > maxCand {
		candidates = candidates[:maxCand]
	}

	hashes := make([][]byte, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		h, err := intel.HashIndicator(c.Type, c.Value)
		if err != nil {
			// Malformed candidate — skip silently. (Body
			// extraction is fuzzy and may emit non-IP
			// strings to the IP slot.)
			continue
		}
		key := string(h)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		hashes = append(hashes, h)
	}
	if len(hashes) == 0 {
		return nil, nil
	}

	// Cache lookup short-circuits hashes that the cache has
	// already classified. We split into resolved-via-cache and
	// hashes-still-to-query.
	//
	// In-place filter: toQuery aliases the same backing array as
	// hashes (toQuery := hashes ; toQuery = toQuery[:0]) and
	// subsequent appends overwrite slots that the loop has already
	// read. This is safe ONLY because the read index i is
	// monotonically increasing and len(toQuery) <= i at every step,
	// i.e. writes never overtake reads. If the loop body is ever
	// refactored to access hashes[j] out of order (e.g. a
	// look-ahead optimisation) this invariant breaks — allocate a
	// fresh slice instead.
	var resolved []intel.MatchedIndicator
	toQuery := hashes
	if s.Cache != nil {
		entries := s.Cache.GetHashes(ctx, hashes)
		toQuery = toQuery[:0]
		for i, e := range entries {
			if !e.Present {
				toQuery = append(toQuery, hashes[i])
				continue
			}
			resolved = append(resolved, e.Matches...)
		}
	}

	if len(toQuery) == 0 {
		return resolved, nil
	}

	matches, err := s.Store.LookupByHash(ctx, toQuery)
	if err != nil {
		return resolved, err
	}

	// Write-back: index matches by hash so SetHash receives a
	// per-hash slice. Hashes with zero matches still write a
	// negative-cache entry.
	if s.Cache != nil {
		byHash := make(map[string][]intel.MatchedIndicator, len(toQuery))
		for _, m := range matches {
			key := string(m.Hash)
			byHash[key] = append(byHash[key], m)
		}
		for _, h := range toQuery {
			s.Cache.SetHash(ctx, h, byHash[string(h)])
		}
	}

	return append(resolved, matches...), nil
}

// IndicatorCandidate is one extracted (uncanonicalised) candidate
// the gate hands to HashIndicator. Type drives which canonicalisation
// rule applies.
type IndicatorCandidate struct {
	Type  intel.IndicatorType
	Value string
}

// ExtractCandidates walks the message and returns every indicator
// the Tier 0 gate should consult for a TI lookup. The order is:
//
//  1. Sender domain (from RiskSignals.SenderDomain, falling back to
//     parsing req.Sender).
//  2. Recipient domain (always — saves an extra SQL query path for
//     deployments that haven't populated SenderDomain yet, AND
//     captures attacks that target the recipient's own domain).
//  3. Every URL extracted from req.Body via the urlPattern regex.
//     Each URL is emitted twice: once as an `url` candidate (matches
//     URL feeds) and once as a `domain` candidate (matches domain
//     feeds), so URLhaus-domain entries and URLhaus-url entries are
//     both hit by the same single batched query.
//
// The function returns a deterministic order so unit tests can
// assert on the exact list.
func ExtractCandidates(req dto.EvaluateRequest, signals dto.RiskSignals) []IndicatorCandidate {
	out := make([]IndicatorCandidate, 0, 8)
	seen := make(map[string]struct{}, 8)
	push := func(t intel.IndicatorType, v string) {
		if v == "" {
			return
		}
		key := string(t) + "|" + v
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, IndicatorCandidate{Type: t, Value: v})
	}

	// Sender domain — prefer the prefilter's parsed value.
	senderDomain := signals.SenderDomain
	if senderDomain == "" {
		senderDomain = domainFromAddress(req.Sender)
	}
	push(intel.IndicatorDomain, senderDomain)

	// Recipient domain (rare but matters for vendor-compromise
	// chains where the attacker uses the recipient's own domain
	// for a lookalike).
	recDomain := signals.RecipientDomain
	if recDomain == "" {
		recDomain = domainFromAddress(req.Recipient)
	}
	push(intel.IndicatorDomain, recDomain)

	// URL / domain extraction from the body. Subject is appended
	// so phishing links in subject lines (rare but real) are also
	// covered.
	corpus := req.Subject + "\n" + req.Body
	for _, raw := range extractURLs(corpus) {
		push(intel.IndicatorURL, raw)
		if host := hostFromURL(raw); host != "" {
			push(intel.IndicatorDomain, host)
		}
	}

	// Sort the slice into a stable order: domain candidates first
	// (cheap canonical), then URL candidates. Within each type
	// the order is insertion-preserving. This is important for
	// the negative-cache eviction order: hot domains (sender,
	// recipient) get cached before long-tail body URLs.
	sort.SliceStable(out, func(i, j int) bool {
		return typeRank(out[i].Type) < typeRank(out[j].Type)
	})
	return out
}

func typeRank(t intel.IndicatorType) int {
	switch t {
	case intel.IndicatorDomain:
		return 0
	case intel.IndicatorIP:
		return 1
	case intel.IndicatorURL:
		return 2
	case intel.IndicatorSHA256:
		return 3
	default:
		return 99
	}
}

// urlBodyPattern is the regex used to harvest URLs from a free-text
// body. It is deliberately permissive — false positives are cheap
// (one extra hash) but false negatives leak through to the ML stages.
var urlBodyPattern = regexp.MustCompile(`https?://[^\s<>"'\)\]]+`)

// extractURLs returns every URL the regex finds in s, trimmed of
// trailing punctuation that the regex's greedy match snags. Hash
// fragments are stripped (they never feature in indicator hashes
// because canonicaliseURL drops them too).
func extractURLs(s string) []string {
	matches := urlBodyPattern.FindAllString(s, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		m = strings.TrimRight(m, ",.;:!?")
		if m == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}

// domainFromAddress returns the domain part of an RFC-5322 address,
// or the input unchanged when it does not parse (the caller may have
// passed a bare domain string).
func domainFromAddress(addr string) string {
	if addr == "" {
		return ""
	}
	if a, err := mail.ParseAddress(addr); err == nil {
		if at := strings.LastIndex(a.Address, "@"); at >= 0 {
			return strings.ToLower(a.Address[at+1:])
		}
	}
	if at := strings.LastIndex(addr, "@"); at >= 0 {
		return strings.ToLower(addr[at+1:])
	}
	return strings.ToLower(addr)
}

// hostFromURL extracts the host portion of a URL. Returns the empty
// string when the URL does not parse.
func hostFromURL(raw string) string {
	const httpsPrefix, httpPrefix = "https://", "http://"
	switch {
	case strings.HasPrefix(raw, httpsPrefix):
		raw = raw[len(httpsPrefix):]
	case strings.HasPrefix(raw, httpPrefix):
		raw = raw[len(httpPrefix):]
	default:
		return ""
	}
	// Strip user-info, port, path, query, fragment.
	if at := strings.IndexByte(raw, '@'); at >= 0 {
		raw = raw[at+1:]
	}
	for _, sep := range []byte{'/', ':', '?', '#'} {
		if i := strings.IndexByte(raw, sep); i >= 0 {
			raw = raw[:i]
		}
	}
	return strings.ToLower(raw)
}

// SeverityTier maps an intel match's [0,100] severity to the gate
// behaviour. The thresholds match the spec — see WS-5B.3 §4.
func SeverityTier(severity int) (constant.Category, bool) {
	switch {
	case severity >= 75:
		// Block-equivalent: ForcedCategory + Bypass.
		return constant.CategoryLikelyPhishing, true
	case severity >= 50:
		// Quarantine-equivalent: ForcedCategory + Bypass; the
		// downstream provider integration maps SuspiciousURL
		// to quarantine in its action policy.
		return constant.CategorySuspiciousURL, true
	default:
		// Flag-only: emit reason code but let the ML stages
		// continue.
		return "", false
	}
}

// PickStrongest scans matches and returns the strongest (highest
// severity) one plus the list of additional feed names that also
// matched something — useful for surfacing a multi-source signal in
// the UI without forcing the caller to walk the matches slice.
func PickStrongest(matches []intel.MatchedIndicator) (intel.MatchedIndicator, []string) {
	if len(matches) == 0 {
		return intel.MatchedIndicator{}, nil
	}
	strongest := matches[0]
	for _, m := range matches[1:] {
		if m.Severity > strongest.Severity {
			strongest = m
		}
	}
	feeds := make([]string, 0, len(matches))
	seen := map[string]struct{}{strongest.FeedID: {}}
	for _, m := range matches {
		if _, dup := seen[m.FeedID]; dup {
			continue
		}
		seen[m.FeedID] = struct{}{}
		feeds = append(feeds, m.FeedName)
	}
	return strongest, feeds
}
