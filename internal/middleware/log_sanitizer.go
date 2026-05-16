// Package middleware bundles cross-cutting wrappers (logging,
// authentication, observability) used by SN360-ES HTTP handlers and
// services.
package middleware

import (
	"context"
	"log/slog"

	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// LogSanitizer wraps an slog.Handler so PII never reaches the log
// output. It removes / masks string attributes per the privacy.Sanitizer
// rules and elides any subject-shaped key entirely.
type LogSanitizer struct {
	next slog.Handler
	san  *privacy.Sanitizer
}

// NewLogSanitizer wraps next with the given sanitizer (default if nil).
func NewLogSanitizer(next slog.Handler, san *privacy.Sanitizer) *LogSanitizer {
	if san == nil {
		san = privacy.NewSanitizer()
	}
	return &LogSanitizer{next: next, san: san}
}

// Enabled implements slog.Handler.
func (l *LogSanitizer) Enabled(ctx context.Context, level slog.Level) bool {
	return l.next.Enabled(ctx, level)
}

// Handle implements slog.Handler. Attributes are scrubbed in-place
// before being forwarded to the wrapped handler.
func (l *LogSanitizer) Handle(ctx context.Context, rec slog.Record) error {
	clone := slog.NewRecord(rec.Time, rec.Level, l.san.MaskEmails(rec.Message), rec.PC)
	rec.Attrs(func(attr slog.Attr) bool {
		clone.AddAttrs(l.sanitiseAttr(attr))
		return true
	})
	return l.next.Handle(ctx, clone)
}

// WithAttrs implements slog.Handler.
func (l *LogSanitizer) WithAttrs(attrs []slog.Attr) slog.Handler {
	sanitised := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		sanitised = append(sanitised, l.sanitiseAttr(a))
	}
	return &LogSanitizer{next: l.next.WithAttrs(sanitised), san: l.san}
}

// WithGroup implements slog.Handler.
func (l *LogSanitizer) WithGroup(name string) slog.Handler {
	return &LogSanitizer{next: l.next.WithGroup(name), san: l.san}
}

// sanitiseAttr returns a sanitised copy of attr.
func (l *LogSanitizer) sanitiseAttr(attr slog.Attr) slog.Attr {
	if l.san.IsSubjectKey(attr.Key) {
		return slog.Attr{Key: attr.Key, Value: slog.StringValue("***")}
	}
	switch attr.Value.Kind() {
	case slog.KindString:
		return slog.Attr{Key: attr.Key, Value: slog.StringValue(l.san.MaskEmails(attr.Value.String()))}
	case slog.KindGroup:
		group := attr.Value.Group()
		out := make([]slog.Attr, 0, len(group))
		for _, child := range group {
			out = append(out, l.sanitiseAttr(child))
		}
		return slog.Attr{Key: attr.Key, Value: slog.GroupValue(out...)}
	default:
		return attr
	}
}
