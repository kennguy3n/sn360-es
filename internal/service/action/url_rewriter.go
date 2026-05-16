package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// URLStore persists the encrypted pre-image of an original URL so the
// interstitial endpoint can look it up after the recipient clicks. The
// contract is the minimal slice of pkg/storage/redis.Client that the
// rewriter needs; tests provide an in-memory fake.
type URLStore interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, bool, error)
}

// URLEncryptor encrypts and decrypts the URL pre-image so a leak of
// the Redis snapshot does not reveal the URLs SN360 users were sent.
// pkg/privacy.Encryptor satisfies the interface; tests may swap in a
// no-op fake.
type URLEncryptor interface {
	Encrypt(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, tenantID string, ciphertext []byte) ([]byte, error)
}

// URLRewriterConfig tunes the rewriter.
type URLRewriterConfig struct {
	// BaseURL is the interstitial endpoint root; tokens are appended
	// as a path segment. Default: https://l.sn360.io.
	BaseURL string
	// PreImageTTL is the TTL on the encrypted pre-image stored in
	// Redis. Default: 30 days.
	PreImageTTL time.Duration
	// SkipSchemes is the set of URL schemes that are never rewritten
	// (mailto:, tel:, file:, javascript:). Defaults are applied if
	// the slice is nil.
	SkipSchemes []string
}

// URLRewriter rewrites HTTP(S) URLs inside an HTML body to opaque
// interstitial links. Each rewritten URL becomes
// `{BaseURL}/{signed-token}`; the recipient lands on the interstitial,
// which decodes the token, re-checks the URL against threat-intel,
// then either redirects or shows a block page.
//
// Rewriting is only invoked for tiers where t.AllowsURLRewrite() is
// true (HighRisk and Blocked); callers should branch on the tier
// before calling Rewrite.
type URLRewriter struct {
	logger    *slog.Logger
	issuer    *privacy.JWTIssuer
	store     URLStore
	encryptor URLEncryptor
	baseURL   string
	preTTL    time.Duration
	skip      map[string]struct{}
}

// NewURLRewriter constructs a rewriter. issuer / store / encryptor are
// all required. Returns an error if any required dependency is nil.
func NewURLRewriter(logger *slog.Logger, issuer *privacy.JWTIssuer, store URLStore, encryptor URLEncryptor, cfg URLRewriterConfig) (*URLRewriter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if issuer == nil {
		return nil, errors.New("url_rewriter: issuer is required")
	}
	if store == nil {
		return nil, errors.New("url_rewriter: store is required")
	}
	if encryptor == nil {
		return nil, errors.New("url_rewriter: encryptor is required")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://l.sn360.io"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.PreImageTTL <= 0 {
		cfg.PreImageTTL = 30 * 24 * time.Hour
	}
	schemes := cfg.SkipSchemes
	if schemes == nil {
		schemes = []string{"mailto", "tel", "file", "javascript", "data", "ftp"}
	}
	skip := make(map[string]struct{}, len(schemes))
	for _, s := range schemes {
		skip[strings.ToLower(s)] = struct{}{}
	}
	return &URLRewriter{
		logger:    logger,
		issuer:    issuer,
		store:     store,
		encryptor: encryptor,
		baseURL:   cfg.BaseURL,
		preTTL:    cfg.PreImageTTL,
		skip:      skip,
	}, nil
}

// RewriteRequest carries the inputs for a single rewrite pass. Tier is
// validated against AllowsURLRewrite so callers cannot accidentally
// rewrite low-tier mail.
type RewriteRequest struct {
	TenantID             string
	PseudonymizedMessage string
	Tier                 constant.Tier
	HTMLBody             string
}

// RewriteResult records what changed.
type RewriteResult struct {
	HTMLBody    string
	RewriteCount int
	// URLHashes lists the hashes of original URLs that were
	// rewritten. Useful for telemetry; carries no PII.
	URLHashes []string
}

// hrefPattern matches `href="..."` (or `href='...'`) attributes,
// including those with whitespace and casing variation. We do not
// rewrite raw text-only URLs since most provider sanitisers wrap
// those in <a> tags during delivery.
var hrefPattern = regexp.MustCompile(`(?i)href\s*=\s*("([^"]+)"|'([^']+)')`)

// Rewrite scans req.HTMLBody for href="..." occurrences and replaces
// each external URL with an interstitial link. The function is a
// no-op when the tier does not allow rewriting.
func (rw *URLRewriter) Rewrite(ctx context.Context, req RewriteRequest) (RewriteResult, error) {
	res := RewriteResult{HTMLBody: req.HTMLBody}
	if !req.Tier.AllowsURLRewrite() {
		return res, nil
	}
	if req.TenantID == "" || req.PseudonymizedMessage == "" {
		return res, errors.New("url_rewriter: tenant_id and pseudo_message_id are required")
	}

	hashes := make([]string, 0, 4)
	out := hrefPattern.ReplaceAllStringFunc(req.HTMLBody, func(match string) string {
		original := extractHrefValue(match)
		if original == "" || rw.shouldSkip(original) {
			return match
		}
		token, hash, err := rw.issueToken(ctx, req.TenantID, req.PseudonymizedMessage, req.Tier, original)
		if err != nil {
			rw.logger.WarnContext(ctx, "url_rewriter: issue token",
				slog.String("tenant_id", req.TenantID),
				slog.Any("error", err))
			return match
		}
		hashes = append(hashes, hash)
		newURL := rw.baseURL + "/" + token
		// Preserve the original quoting style.
		quote := byte('"')
		if strings.Contains(match, "'") && !strings.Contains(match, `"`) {
			quote = '\''
		}
		return `href=` + string(quote) + newURL + string(quote)
	})
	res.HTMLBody = out
	res.RewriteCount = len(hashes)
	res.URLHashes = hashes
	return res, nil
}

// issueToken hashes original, stores the encrypted pre-image, and
// returns the signed token.
func (rw *URLRewriter) issueToken(ctx context.Context, tenantID, pseudoMessage string, tier constant.Tier, original string) (token, hash string, err error) {
	hash = hashURL(original)
	enc, err := rw.encryptor.Encrypt(ctx, tenantID, []byte(original))
	if err != nil {
		return "", "", fmt.Errorf("encrypt: %w", err)
	}
	if err := rw.store.Set(ctx, URLPreImageKey(hash), hex.EncodeToString(enc), rw.preTTL); err != nil {
		return "", "", fmt.Errorf("store: %w", err)
	}
	token, err = rw.issuer.Issue(tenantID, pseudoMessage, privacy.IssueOptions{
		Tier:    string(tier),
		Action:  "url_redirect",
		URLHash: hash,
	})
	if err != nil {
		return "", "", fmt.Errorf("issue: %w", err)
	}
	return token, hash, nil
}

// Resolve verifies a token and returns the decrypted original URL. It
// is consumed by the interstitial HTTP handler.
func (rw *URLRewriter) Resolve(ctx context.Context, token string) (originalURL string, claims *privacy.ActionClaims, err error) {
	claims, err = rw.issuer.Verify(token)
	if err != nil {
		return "", nil, fmt.Errorf("verify: %w", err)
	}
	if claims.OriginalURLHash == "" {
		return "", claims, errors.New("url_rewriter: token has no url hash")
	}
	encHex, ok, err := rw.store.Get(ctx, URLPreImageKey(claims.OriginalURLHash))
	if err != nil {
		return "", claims, fmt.Errorf("store: %w", err)
	}
	if !ok {
		return "", claims, errors.New("url_rewriter: pre-image expired or unknown")
	}
	enc, err := hex.DecodeString(encHex)
	if err != nil {
		return "", claims, fmt.Errorf("decode hex: %w", err)
	}
	plain, err := rw.encryptor.Decrypt(ctx, claims.TenantID, enc)
	if err != nil {
		return "", claims, fmt.Errorf("decrypt: %w", err)
	}
	return string(plain), claims, nil
}

// shouldSkip reports whether u should be left alone (skipped schemes
// or relative URLs).
func (rw *URLRewriter) shouldSkip(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return true
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" {
		// Relative URLs or anchors — leave alone.
		return true
	}
	if _, ok := rw.skip[scheme]; ok {
		return true
	}
	return scheme != "http" && scheme != "https"
}

func extractHrefValue(match string) string {
	// match has shape `href="VALUE"` or `href='VALUE'`. Locate the
	// first `=` and the next quote.
	eq := strings.Index(match, "=")
	if eq < 0 {
		return ""
	}
	rest := strings.TrimSpace(match[eq+1:])
	if len(rest) < 2 {
		return ""
	}
	q := rest[0]
	if q != '"' && q != '\'' {
		return ""
	}
	end := strings.IndexByte(rest[1:], q)
	if end < 0 {
		return ""
	}
	return rest[1 : 1+end]
}

func hashURL(u string) string {
	sum := sha256.Sum256([]byte(u))
	return hex.EncodeToString(sum[:])
}

// URLPreImageKey returns the canonical Redis key for the encrypted
// pre-image of urlHash. Exposed so the interstitial handler can
// invalidate keys after click logging.
func URLPreImageKey(urlHash string) string {
	return "url:" + urlHash
}
