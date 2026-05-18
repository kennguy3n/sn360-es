package ingestion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Pseudonymizer is the subset of pkg/privacy.Pseudonymizer the
// normalizer needs. Keeping it abstract here makes the package easy
// to test without pulling in the privacy package's setup.
type Pseudonymizer interface {
	Pseudonymise(value string) string
}

// FreeDomainSet allows callers to inject a curated free-domain
// list. A nil set means "no domain is treated as free"; the
// normalizer never panics on a nil set.
type FreeDomainSet interface {
	Contains(domain string) bool
}

// staticFreeDomains is the minimal default used when no
// FreeDomainSet is supplied. Production deployments override this
// with the full list from `pkg/privacy/free_domains.go`.
type staticFreeDomains struct {
	domains map[string]struct{}
}

func (s *staticFreeDomains) Contains(d string) bool {
	if s == nil {
		return false
	}
	_, ok := s.domains[strings.ToLower(d)]
	return ok
}

func defaultFreeDomains() FreeDomainSet {
	return &staticFreeDomains{
		domains: map[string]struct{}{
			"gmail.com":      {},
			"yahoo.com":      {},
			"hotmail.com":    {},
			"outlook.com":    {},
			"icloud.com":     {},
			"aol.com":        {},
			"proton.me":      {},
			"protonmail.com": {},
			"yandex.com":     {},
			"mail.com":       {},
		},
	}
}

// DefaultNormalizer is the production Normalizer used by the
// Poller. It is safe for concurrent use.
type DefaultNormalizer struct {
	pseudonymizer Pseudonymizer
	freeDomains   FreeDomainSet
	defaultLocale string
}

// NormalizerOption configures the default normalizer at
// construction time.
type NormalizerOption func(*DefaultNormalizer)

// WithPseudonymizer injects a pseudonymizer used to anonymise the
// recipient field before persistence. The plaintext sender stays
// intact so detection logic can still match against the original
// address.
func WithPseudonymizer(p Pseudonymizer) NormalizerOption {
	return func(n *DefaultNormalizer) { n.pseudonymizer = p }
}

// WithFreeDomains injects the free-domain set used for the
// IsFreeDomain risk signal.
func WithFreeDomains(s FreeDomainSet) NormalizerOption {
	return func(n *DefaultNormalizer) { n.freeDomains = s }
}

// WithDefaultLocale sets the locale used when the message itself
// does not declare one.
func WithDefaultLocale(loc string) NormalizerOption {
	return func(n *DefaultNormalizer) { n.defaultLocale = loc }
}

// NewDefaultNormalizer builds a Normalizer with sensible defaults.
func NewDefaultNormalizer(opts ...NormalizerOption) *DefaultNormalizer {
	n := &DefaultNormalizer{
		freeDomains:   defaultFreeDomains(),
		defaultLocale: "en",
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// Normalize converts a RawEmail into a fully-populated
// dto.EvaluateRequest. The returned request has:
//
//   - HTML stripped, whitespace collapsed body
//   - SHA-256 RawBodyHash + NormalisedHash for cache keys
//   - RiskSignals derived from the Authentication-Results, From,
//     and Content-Type headers
//   - Recipient pseudonymised when a pseudonymizer is wired
func (n *DefaultNormalizer) Normalize(_ context.Context, raw RawEmail) (dto.EvaluateRequest, error) {
	if raw.ProviderMessageID == "" {
		return dto.EvaluateRequest{}, fmt.Errorf("ingestion: raw email is missing provider_message_id")
	}
	bodyText := raw.Body
	if bodyText == "" && raw.HTMLBody != "" {
		bodyText = stripHTML(raw.HTMLBody)
	} else if raw.HTMLBody != "" && containsTags(bodyText) {
		bodyText = stripHTML(bodyText)
	}
	bodyText = collapseWhitespace(bodyText)

	subject := raw.Subject
	combined := strings.TrimSpace(subject + "\n" + bodyText)

	rawHash := sha256Hex([]byte(combined))
	normalised := strings.ToLower(combined)
	normalised = collapseWhitespace(normalised)
	normHash := sha256Hex([]byte(normalised))

	signals := n.buildSignals(raw)

	recipient := raw.Mailbox
	if recipient == "" && len(raw.Recipients) > 0 {
		recipient = raw.Recipients[0]
	}
	if n.pseudonymizer != nil && recipient != "" {
		// Pseudonymise only the recipient header. The detection
		// logic still needs the raw sender for matching.
		recipient = n.pseudonymizer.Pseudonymise(recipient)
	}

	locale := headerLookup(raw.Headers, "Content-Language")
	if locale == "" {
		locale = n.defaultLocale
	}

	req := dto.EvaluateRequest{
		MessageID:      raw.ProviderMessageID,
		TenantID:       raw.TenantID,
		CorrelationID:  raw.ProviderMessageID,
		Sender:         raw.Sender,
		Recipient:      recipient,
		CC:             raw.CC,
		Subject:        subject,
		Body:           bodyText,
		RawBodyHash:    rawHash,
		NormalisedHash: normHash,
		Signals:        signals,
		Locale:         locale,
		ReceivedAt:     raw.ReceivedAt,
	}
	return req, nil
}

// buildSignals derives the RiskSignals from the headers and
// sender/recipient addresses.
func (n *DefaultNormalizer) buildSignals(raw RawEmail) dto.RiskSignals {
	signals := dto.RiskSignals{}
	senderDomain := extractDomain(raw.Sender)
	recipientDomain := extractDomain(firstNonEmpty(raw.Mailbox, firstOf(raw.Recipients)))
	signals.SenderDomain = senderDomain
	signals.RecipientDomain = recipientDomain
	signals.IsExternal = senderDomain != "" && recipientDomain != "" &&
		!strings.EqualFold(senderDomain, recipientDomain)
	if n.freeDomains != nil {
		signals.IsFreeDomain = n.freeDomains.Contains(senderDomain)
	}
	if ct := headerLookup(raw.Headers, "Content-Type"); ct != "" {
		signals.HasAttachment = strings.Contains(strings.ToLower(ct), "multipart/mixed") ||
			strings.Contains(strings.ToLower(ct), "multipart/related")
	}
	if ar := headerLookup(raw.Headers, "Authentication-Results"); ar != "" {
		signals.SPFResult = extractAuthResult(ar, "spf")
		signals.DKIMResult = extractAuthResult(ar, "dkim")
		signals.DMARCResult = extractAuthResult(ar, "dmarc")
	}
	return signals
}

// stripHTML returns the visible text of an HTML fragment using the
// golang.org/x/net/html tokenizer. Scripts and styles are dropped.
func stripHTML(body string) string {
	z := html.NewTokenizer(strings.NewReader(body))
	var out strings.Builder
	skip := 0
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return out.String()
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if tag == "script" || tag == "style" || tag == "head" {
				skip++
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if tag == "script" || tag == "style" || tag == "head" {
				if skip > 0 {
					skip--
				}
			}
		case html.TextToken:
			if skip == 0 {
				out.Write(z.Text())
				out.WriteByte(' ')
			}
		}
	}
}

var (
	whitespaceRE = regexp.MustCompile(`[\s\u00A0]+`)
	authPairRE   = regexp.MustCompile(`(?i)\b(spf|dkim|dmarc)=([a-z]+)`)
	htmlTagRE    = regexp.MustCompile(`<[a-zA-Z!/][^>]*>`)
)

func collapseWhitespace(s string) string {
	return strings.TrimSpace(whitespaceRE.ReplaceAllString(s, " "))
}

func containsTags(s string) bool {
	return htmlTagRE.MatchString(s)
}

// extractAuthResult pulls a single mechanism's verdict from an
// Authentication-Results header. Returns the lowercase verdict
// (e.g. "pass", "fail") or "" when not found.
func extractAuthResult(header, mechanism string) string {
	matches := authPairRE.FindAllStringSubmatch(header, -1)
	mech := strings.ToLower(mechanism)
	for _, m := range matches {
		if len(m) == 3 && strings.EqualFold(m[1], mech) {
			return strings.ToLower(m[2])
		}
	}
	return ""
}

func extractDomain(addr string) string {
	addr = strings.TrimSpace(addr)
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	dom := addr[at+1:]
	dom = strings.TrimRight(dom, ">")
	dom = strings.TrimSpace(dom)
	return strings.ToLower(dom)
}

func headerLookup(h map[string]string, key string) string {
	if h == nil {
		return ""
	}
	if v, ok := h[key]; ok {
		return v
	}
	lk := strings.ToLower(key)
	for k, v := range h {
		if strings.ToLower(k) == lk {
			return v
		}
	}
	return ""
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstOf(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// marshalRequest is exported through the package boundary as a
// helper used by the Poller to serialise an EvaluateRequest for the
// bus. It lives next to the normalizer because the request shape is
// owned here.
func marshalRequest(r dto.EvaluateRequest) ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("ingestion: marshal evaluate request: %w", err)
	}
	// Defensive: empty received_at would round-trip as
	// "0001-01-01T00:00:00Z"; force a current timestamp so the
	// audit log always has a sensible value.
	if r.ReceivedAt.IsZero() {
		// Re-marshal with ReceivedAt = now to keep the payload
		// honest.
		r.ReceivedAt = time.Now().UTC()
		return json.Marshal(r)
	}
	return b, nil
}
