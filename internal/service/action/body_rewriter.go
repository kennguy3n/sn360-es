package action

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// BodyRewriter is the per-provider integration that reads a message's
// HTML body, lets the caller transform it, and writes back the
// result. This is the abstraction the URL rewrite consumer uses —
// Gmail's shadow-copy and Outlook's GET-PATCH are both implementors.
//
// Implementations live in `pkg/email_provider/*`.
type BodyRewriter interface {
	// FetchBody retrieves the HTML body of the given message.
	FetchBody(ctx context.Context, email, messageID string) (htmlBody string, err error)
	// WriteBody writes the modified body back to the provider.
	WriteBody(ctx context.Context, email, messageID, htmlBody string) error
}

// BodyRewriterCacheCleaner is an optional interface that BodyRewriter
// implementations can satisfy to release cached state when WriteBody
// will not be called (e.g., empty body, zero rewritable URLs). The
// Gmail shadow-copy implementation caches raw RFC-2822 bytes between
// FetchBody and WriteBody; this interface lets URLRewriteService
// release that memory on early-return paths without leaking
// provider-specific details into the core interface.
type BodyRewriterCacheCleaner interface {
	EvictCache(email, messageID string)
}

// BodyRewriteRequest carries the inputs for a URL-rewrite operation
// on a message body.
type BodyRewriteRequest struct {
	Tenant    string
	Provider  LabelProviderKind
	Email     string
	MessageID string
}

// Validate returns an error if required fields are missing.
func (r BodyRewriteRequest) Validate() error {
	if r.Tenant == "" {
		return errors.New("body_rewriter: tenant is required")
	}
	if r.MessageID == "" {
		return errors.New("body_rewriter: message_id is required")
	}
	if r.Email == "" {
		return errors.New("body_rewriter: email is required")
	}
	return nil
}

// LoggingBodyRewriter is a no-op fallback that logs requests without
// contacting any provider. Used in dev/test.
type LoggingBodyRewriter struct {
	Logger *slog.Logger

	mu      sync.Mutex
	records []BodyRewriteRequest
}

// NewLoggingBodyRewriter constructs a LoggingBodyRewriter.
func NewLoggingBodyRewriter(logger *slog.Logger) *LoggingBodyRewriter {
	if logger == nil {
		logger = slog.Default()
	}
	return &LoggingBodyRewriter{Logger: logger}
}

// FetchBody returns a placeholder body in logging mode.
func (l *LoggingBodyRewriter) FetchBody(ctx context.Context, email, messageID string) (string, error) {
	l.Logger.InfoContext(ctx, "body_rewriter: fetch (logging mode)",
		slog.String("email", email),
		slog.String("message_id", messageID))
	return "", nil
}

// WriteBody logs the write without contacting any provider.
func (l *LoggingBodyRewriter) WriteBody(ctx context.Context, email, messageID, htmlBody string) error {
	l.Logger.InfoContext(ctx, "body_rewriter: write (logging mode)",
		slog.String("email", email),
		slog.String("message_id", messageID),
		slog.Int("body_bytes", len(htmlBody)))
	return nil
}

// RecordRewrite records a completed rewrite request.
func (l *LoggingBodyRewriter) RecordRewrite(r BodyRewriteRequest) {
	l.mu.Lock()
	l.records = append(l.records, r)
	l.mu.Unlock()
}

// Records returns all recorded requests.
func (l *LoggingBodyRewriter) Records() []BodyRewriteRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]BodyRewriteRequest, len(l.records))
	copy(out, l.records)
	return out
}

// URLRewriteService orchestrates the URL-rewrite pipeline. It reads
// the message body from the provider, rewrites URLs via the
// URLRewriter, and writes the modified body back.
type URLRewriteService struct {
	Rewriter *URLRewriter
	Logger   *slog.Logger
}

// RewriteBody performs the full URL-rewrite cycle on a single message.
func (s *URLRewriteService) RewriteBody(ctx context.Context, bw BodyRewriter, req BodyRewriteRequest, tier string) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if s.Rewriter == nil {
		return errors.New("url_rewrite_service: rewriter not configured")
	}

	htmlBody, err := bw.FetchBody(ctx, req.Email, req.MessageID)
	if err != nil {
		return fmt.Errorf("url_rewrite_service: fetch body: %w", err)
	}
	if htmlBody == "" {
		evictBodyRewriterCache(bw, req.Email, req.MessageID)
		s.Logger.DebugContext(ctx, "url_rewrite_service: empty body, skipping",
			slog.String("tenant_id", req.Tenant),
			slog.String("provider", string(req.Provider)),
			slog.String("message_id", req.MessageID))
		return nil
	}

	tierConstant := parseTier(tier)
	result, err := s.Rewriter.Rewrite(ctx, RewriteRequest{
		TenantID:             req.Tenant,
		PseudonymizedMessage: req.MessageID,
		Tier:                 tierConstant,
		HTMLBody:             htmlBody,
	})
	if err != nil {
		evictBodyRewriterCache(bw, req.Email, req.MessageID)
		return fmt.Errorf("url_rewrite_service: rewrite: %w", err)
	}
	if result.RewriteCount == 0 {
		evictBodyRewriterCache(bw, req.Email, req.MessageID)
		s.Logger.DebugContext(ctx, "url_rewrite_service: no URLs rewritten",
			slog.String("message_id", req.MessageID))
		return nil
	}

	if err := bw.WriteBody(ctx, req.Email, req.MessageID, result.HTMLBody); err != nil {
		return fmt.Errorf("url_rewrite_service: write body: %w", err)
	}
	s.Logger.InfoContext(ctx, "url_rewrite_service: rewritten",
		slog.String("tenant_id", req.Tenant),
		slog.String("provider", string(req.Provider)),
		slog.String("message_id", req.MessageID),
		slog.Int("urls_rewritten", result.RewriteCount))
	return nil
}

// evictBodyRewriterCache releases cached state when WriteBody will not
// be called. Only effective for BodyRewriter implementations that also
// satisfy BodyRewriterCacheCleaner (e.g., Gmail's shadow-copy).
func evictBodyRewriterCache(bw BodyRewriter, email, messageID string) {
	if cc, ok := bw.(BodyRewriterCacheCleaner); ok {
		cc.EvictCache(email, messageID)
	}
}

func parseTier(s string) constant.Tier {
	switch constant.Tier(s) {
	case constant.TierBlocked, constant.TierHighRisk, constant.TierWarning,
		constant.TierCaution, constant.TierInformational, constant.TierTrusted:
		return constant.Tier(s)
	default:
		return constant.TierHighRisk
	}
}
