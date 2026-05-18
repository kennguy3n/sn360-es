package action

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// BannerInjector is the per-provider integration that takes a rendered
// banner HTML blob and writes it into the user's mailbox. The applier
// is decoupled from BannerRenderer so the renderer can stay free of
// provider-specific knowledge (Gmail batchModify, Outlook PATCH on
// /me/messages, SMTP append, etc.).
//
// Implementations live in `pkg/email_provider/*`. The default
// LoggingBannerInjector records the request without contacting any
// provider — useful in dev / test and as a fallback when only one of
// the configured providers is reachable.
type BannerInjector interface {
	InjectBanner(ctx context.Context, req BannerInjectRequest) error
}

// BannerInjectRequest is the typed input to InjectBanner. The HTML
// field is the pre-rendered banner from BannerRenderer; the injector
// is responsible for splicing it into the message body without
// damaging the original Content-Type / MIME structure.
type BannerInjectRequest struct {
	Tenant    string
	Provider  LabelProviderKind
	Email     string
	MessageID string
	HTML      []byte
}

// Validate returns an error if the request is missing fields the
// injector cannot synthesise. Implementations should call it before
// any provider work.
func (r BannerInjectRequest) Validate() error {
	if r.Tenant == "" {
		return errors.New("banner_injector: tenant is required")
	}
	if r.MessageID == "" {
		return errors.New("banner_injector: message_id is required")
	}
	if len(r.HTML) == 0 {
		return errors.New("banner_injector: html is required")
	}
	return nil
}

// LoggingBannerInjector is the default no-op implementation. It logs
// the injection request at Info level so operators can confirm the
// chain is wired even when no real provider client is configured.
// The recorded slice is exposed via Records() for tests.
type LoggingBannerInjector struct {
	Logger *slog.Logger

	mu      sync.Mutex
	records []BannerInjectRequest
}

// NewLoggingBannerInjector constructs a LoggingBannerInjector with the
// supplied logger; nil falls back to slog.Default() so callers do not
// have to guard against it.
func NewLoggingBannerInjector(logger *slog.Logger) *LoggingBannerInjector {
	if logger == nil {
		logger = slog.Default()
	}
	return &LoggingBannerInjector{Logger: logger}
}

// InjectBanner records the request and logs it. It never fails on a
// well-formed input, so callers can chain it with a real provider
// implementation in a fall-through pattern (real first, logging
// second) without worrying about double-failures.
func (l *LoggingBannerInjector) InjectBanner(ctx context.Context, req BannerInjectRequest) error {
	if err := req.Validate(); err != nil {
		return fmt.Errorf("banner_injector: %w", err)
	}
	l.mu.Lock()
	l.records = append(l.records, req)
	l.mu.Unlock()
	l.Logger.InfoContext(ctx, "banner_injector: inject (logging mode)",
		slog.String("tenant", req.Tenant),
		slog.String("provider", string(req.Provider)),
		slog.String("email", req.Email),
		slog.String("message_id", req.MessageID),
		slog.Int("bytes", len(req.HTML)))
	return nil
}

// Records returns a copy of every request InjectBanner has seen since
// construction. Safe for concurrent use.
func (l *LoggingBannerInjector) Records() []BannerInjectRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]BannerInjectRequest, len(l.records))
	copy(out, l.records)
	return out
}
