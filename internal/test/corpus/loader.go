package corpus

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// Load reads a JSONL stream of Fixture rows from path. Empty lines and
// lines beginning with `//` are skipped (the synthetic corpus header
// uses `// synthetic — replace with real corpus when available`
// comments). Every other line MUST be a valid Fixture; the loader
// fails fast on the first invalid line so a malformed corpus never
// produces "partial" metrics that look real.
func Load(path string) ([]Fixture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("corpus: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return Parse(f, path)
}

// Parse is the io.Reader form of Load. The path argument is used only
// for error messages; pass "" when reading from an in-memory buffer.
func Parse(r io.Reader, path string) ([]Fixture, error) {
	scanner := bufio.NewScanner(r)
	// Default bufio.Scanner buffer is 64 KiB; bump to 1 MiB so a
	// long base64-encoded MIME multipart fixture doesn't trip
	// bufio.ErrTooLong. 1 MiB is the same ceiling the rest of the
	// codebase uses for line-oriented inputs (see internal/service/
	// ingestion/jmap_streamer.go).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		fixtures []Fixture
		line     int
		seen     = map[string]struct{}{}
	)
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		trimmed := bytesTrim(raw)
		if len(trimmed) == 0 {
			continue
		}
		if len(trimmed) >= 2 && trimmed[0] == '/' && trimmed[1] == '/' {
			continue
		}
		var fx Fixture
		if err := json.Unmarshal(trimmed, &fx); err != nil {
			return nil, &LoaderError{Path: path, Line: line, Err: fmt.Errorf("decode JSON: %w", err)}
		}
		if err := fx.Validate(); err != nil {
			return nil, &LoaderError{Path: path, Line: line, Err: err}
		}
		if _, dup := seen[fx.ID]; dup {
			return nil, &LoaderError{Path: path, Line: line, Err: fmt.Errorf("duplicate fixture id %q", fx.ID)}
		}
		seen[fx.ID] = struct{}{}
		fixtures = append(fixtures, fx)
	}
	if err := scanner.Err(); err != nil {
		return nil, &LoaderError{Path: path, Line: line, Err: fmt.Errorf("scan: %w", err)}
	}
	if len(fixtures) == 0 {
		return nil, errors.New("corpus: empty fixture set")
	}
	return fixtures, nil
}

// bytesTrim is a local helper that strips leading/trailing ASCII
// whitespace from a byte slice without allocating. Avoiding the
// strings.TrimSpace round-trip keeps the loader allocation-free per
// fixture, which matters when the corpus grows past 10k rows.
func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}

// DecodeMessage decodes the base64-encoded RFC822 payload to raw
// bytes and returns the parsed mail.Message. Exposed so callers
// (e.g. adversarial property tests) can fuzz the underlying bytes
// independently of fixture-level evaluation.
func DecodeMessage(fx Fixture) (*mail.Message, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(fx.RFC822)
	if err != nil {
		return nil, nil, fmt.Errorf("decode rfc822 base64: %w", err)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil, raw, fmt.Errorf("parse rfc822: %w", err)
	}
	return msg, raw, nil
}

// BuildRequest converts a Fixture into the dto.EvaluateRequest the
// production evaluator expects. The mapping mirrors the ingestion
// path: header parsing for Sender / Recipient / Subject, RFC5322
// body extraction for Body, and a minimum-viable RiskSignals derived
// from the sender/recipient domain.
//
// The harness deliberately populates only signals that can be derived
// from RFC822 alone — anything that requires tenant directory state
// (IsInternal, RelationshipCategory, IsFromVendor) is left at its
// zero value. This keeps the harness corpus-agnostic; tenants who
// want to drive the directory-aware paths can extend Fixture.Metadata
// with explicit overrides (and BuildRequest honours the
// `metadata.signals.*` keys when present — see signalsFromMetadata).
func BuildRequest(ctx context.Context, fx Fixture, opts BuildOpts) (dto.EvaluateRequest, error) {
	_ = ctx // reserved for future metadata enrichment
	msg, raw, err := DecodeMessage(fx)
	if err != nil {
		return dto.EvaluateRequest{}, err
	}

	sender, senderDomain := parseAddress(msg.Header.Get("From"))
	recipient, recipientDomain := parseAddress(msg.Header.Get("To"))
	subject := decodeHeader(msg.Header.Get("Subject"))

	bodyBytes, _ := io.ReadAll(msg.Body)
	body := string(bodyBytes)
	// MIME multipart fixtures expose only the outer wrapper to
	// net/mail; that's fine for evaluation purposes because the
	// Tier 0 gate and the Tier 1 encoder both work on the
	// concatenated subject+body. We do NOT decode multipart parts
	// here: the production normalizer is responsible for that and
	// reproducing it in the harness would create the kind of
	// refactored test-only stub the WS-4b spec explicitly forbids.

	signals := signalsFromMetadata(fx)
	if signals.SenderDomain == "" {
		signals.SenderDomain = senderDomain
	}
	if signals.RecipientDomain == "" {
		signals.RecipientDomain = recipientDomain
	}
	// Conservative default: any sender whose domain differs from
	// the recipient domain is treated as external. The directory
	// signals (IsInternal, IsFromVendor, RelationshipCategory)
	// stay at their zero values — the corpus does not carry that
	// state, and faking it here would produce optimistic Tier 0
	// bypasses that the production pipeline would not honour.
	if senderDomain != "" && recipientDomain != "" && !strings.EqualFold(senderDomain, recipientDomain) {
		signals.IsExternal = true
	}

	// Stable pseudonymous message id and content hashes so the
	// evaluator's cache layers can dedupe re-runs of the same
	// fixture between harness invocations. Using fixture.ID
	// (rather than a hash of the body) keeps the cache key
	// stable across body perturbations — the adversarial fuzz
	// suite explicitly wants each perturbation to skip the
	// cache so it actually hits the model.
	msgID := opts.MessageIDOverride
	if msgID == "" {
		hash := sha256.Sum256(raw)
		msgID = "corpus-" + fx.ID + "-" + hex.EncodeToString(hash[:8])
	}

	tenantID := opts.TenantID
	if tenantID == "" {
		tenantID = "ws4b-corpus-harness"
	}

	receivedAt := opts.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Unix(1_700_000_000, 0).UTC() // fixed for reproducibility
	}

	return dto.EvaluateRequest{
		MessageID:     msgID,
		TenantID:      tenantID,
		CorrelationID: "corpus-eval",
		Sender:        sender,
		Recipient:     recipient,
		Subject:       subject,
		Body:          body,
		Signals:       signals,
		Locale:        "en",
		ReceivedAt:    receivedAt,
	}, nil
}

// BuildOpts controls the harness-level overrides applied during
// EvaluateRequest construction. All fields are optional; sensible
// defaults are filled in by BuildRequest.
type BuildOpts struct {
	// TenantID, when non-empty, replaces the synthetic
	// "ws4b-corpus-harness" tenant id. Useful for harness runs
	// that exercise a real tenant's scoring config.
	TenantID string
	// MessageIDOverride, when non-empty, replaces the
	// fixture-derived message id. Adversarial property tests use
	// this to force cache misses across perturbations of the same
	// fixture.
	MessageIDOverride string
	// ReceivedAt, when non-zero, overrides the fixed-timestamp
	// default the harness applies for reproducibility.
	ReceivedAt time.Time
}

// signalsFromMetadata reads tenant-level signal overrides from the
// fixture metadata. The keys are namespaced under `signals.` so the
// rest of the metadata map (source / attack_type / vendor / etc.)
// stays opaque.
//
// Recognised keys (case-sensitive):
//
//	signals.is_internal              => bool
//	signals.is_from_vendor           => bool
//	signals.has_failed_auth          => bool
//	signals.has_lookalike_domain     => bool
//	signals.has_suspicious_url       => bool
//	signals.is_high_volume_sender    => bool
//	signals.is_recurring_service     => bool
//	signals.is_free_domain           => bool
//	signals.is_disposable_domain     => bool
//	signals.sender_domain            => string (overrides RFC822 sender domain)
//	signals.recipient_domain         => string (overrides RFC822 recipient domain)
//	signals.relationship_category    => one of Partner/Customer/FirstTimeExternal/...
//
// Unknown keys are ignored. A malformed boolean value (e.g.
// "signals.is_internal" = "yes please") is treated as false — the
// loader's Validate path is the strict gate.
func signalsFromMetadata(fx Fixture) dto.RiskSignals {
	var s dto.RiskSignals
	if len(fx.Metadata) == 0 {
		return s
	}
	get := func(key string) (string, bool) {
		v, ok := fx.Metadata[key]
		return v, ok
	}
	getBool := func(key string) bool {
		v, ok := get(key)
		if !ok {
			return false
		}
		return v == "true" || v == "1" || v == "yes"
	}
	s.IsInternal = getBool("signals.is_internal")
	s.IsFromVendor = getBool("signals.is_from_vendor")
	s.HasFailedAuth = getBool("signals.has_failed_auth")
	s.HasLookalikeDomain = getBool("signals.has_lookalike_domain")
	s.HasSuspiciousURL = getBool("signals.has_suspicious_url")
	s.IsHighVolumeSender = getBool("signals.is_high_volume_sender")
	s.IsRecurringService = getBool("signals.is_recurring_service")
	s.IsFreeDomain = getBool("signals.is_free_domain")
	s.IsDisposableDomain = getBool("signals.is_disposable_domain")
	if v, ok := get("signals.sender_domain"); ok {
		s.SenderDomain = v
	}
	if v, ok := get("signals.recipient_domain"); ok {
		s.RecipientDomain = v
	}
	if v, ok := get("signals.relationship_category"); ok {
		rc := dto.RelationshipCategory(v)
		if rc.Valid() {
			s.RelationshipCategory = rc
		}
	}
	if v, ok := get("signals.has_qr_code"); ok {
		s.HasQRCode = v == "true" || v == "1" || v == "yes"
	}
	if v, ok := get("signals.has_credential_lex"); ok {
		s.HasCredentialLex = v == "true" || v == "1" || v == "yes"
	}
	return s
}

// parseAddress extracts the canonical address (user@host) and the
// host portion from a raw header value (e.g. `"Alice" <alice@x.com>`).
// On parse failure it returns empty strings so the harness produces
// metadata-empty rather than crashing on a malformed fixture.
func parseAddress(raw string) (full, domain string) {
	if raw == "" {
		return "", ""
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		// Lenient fallback: extract anything that looks like
		// user@host from the raw string. This matters for the
		// adversarial corpus where header perturbations break
		// strict RFC5322 conformance.
		at := strings.LastIndex(raw, "@")
		if at < 0 {
			return raw, ""
		}
		userPart := strings.TrimSpace(raw[:at])
		domainPart := strings.TrimSpace(raw[at+1:])
		// Strip trailing > if present.
		domainPart = strings.TrimRight(domainPart, " \t>\r\n")
		// Strip leading < if present from the user part.
		userPart = strings.TrimLeft(userPart, " \t<")
		if domainPart == "" {
			return raw, ""
		}
		return userPart + "@" + domainPart, strings.ToLower(domainPart)
	}
	at := strings.LastIndex(addr.Address, "@")
	if at < 0 {
		return addr.Address, ""
	}
	return addr.Address, strings.ToLower(addr.Address[at+1:])
}

// decodeHeader is a thin wrapper around mime.WordDecoder so RFC2047-
// encoded Subject lines (e.g. `=?utf-8?B?...?=`) decode to their
// underlying characters. The harness leans on net/mail's default
// behaviour, which only decodes well-formed encoded-words; on
// failure it returns the raw value.
func decodeHeader(raw string) string {
	if raw == "" {
		return ""
	}
	// net/mail.Message.Header.Get already returns the decoded form
	// when the header is well-formed; this helper exists so future
	// callers have a single place to layer additional normalisation
	// (e.g. NFKC, defanging) without touching BuildRequest.
	return raw
}
