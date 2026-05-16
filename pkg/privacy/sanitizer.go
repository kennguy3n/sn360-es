package privacy

import (
	"regexp"
	"strings"
)

// Sanitizer mutates strings to remove or mask PII before they are emitted
// to logs, metrics, or external traces.
//
// The default sanitizer:
//   - replaces email addresses with `***@domain`
//   - blanks out values for any key matching subjectKeyRegex
//   - leaves correlation IDs, timestamps, and error codes untouched
type Sanitizer struct {
	emailRegex     *regexp.Regexp
	subjectKeyRe   *regexp.Regexp
	maskHTTPHeader *regexp.Regexp
}

// emailPattern matches a plausible email address. It is intentionally
// permissive — false positives in sanitisation are safer than false
// negatives because the worst case is a non-email getting masked.
var emailPattern = regexp.MustCompile(`(?i)([a-z0-9._%+\-]+)@([a-z0-9.\-]+\.[a-z]{2,})`)

// subjectKeyPattern matches log keys that should always have their value
// blanked: "subject", "email_subject", "raw_subject", etc.
var subjectKeyPattern = regexp.MustCompile(`(?i)(^|_)subject($|_)`)

// httpHeaderPattern matches authorization / cookie header values.
var httpHeaderPattern = regexp.MustCompile(`(?i)^(authorization|cookie|set-cookie|x-api-key)$`)

// NewSanitizer returns the default sanitizer.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		emailRegex:     emailPattern,
		subjectKeyRe:   subjectKeyPattern,
		maskHTTPHeader: httpHeaderPattern,
	}
}

// MaskEmails returns s with every email-shaped substring rewritten to
// `***@<domain>`. The local-part is masked, the domain is preserved
// because it is still useful for ops diagnostics (e.g. lookalike alerts).
func (s *Sanitizer) MaskEmails(in string) string {
	if in == "" {
		return in
	}
	return s.emailRegex.ReplaceAllString(in, "***@$2")
}

// IsSubjectKey reports whether a log key matches the "subject" pattern.
// Used by the slog handler to decide whether to drop a value entirely.
func (s *Sanitizer) IsSubjectKey(key string) bool {
	return s.subjectKeyRe.MatchString(key)
}

// IsSensitiveHTTPHeader reports whether a header name is sensitive and
// must be masked when logged.
func (s *Sanitizer) IsSensitiveHTTPHeader(name string) bool {
	return s.maskHTTPHeader.MatchString(strings.TrimSpace(name))
}

// Sanitise applies all rules to a single string value. It does not modify
// keys.
func (s *Sanitizer) Sanitise(value string) string {
	return s.MaskEmails(value)
}

// SanitiseMap returns a shallow copy of m with PII values masked. Keys
// matching subjectKeyRe have their values replaced with "***".
func (s *Sanitizer) SanitiseMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if s.IsSubjectKey(k) {
			out[k] = "***"
			continue
		}
		switch val := v.(type) {
		case string:
			out[k] = s.Sanitise(val)
		case map[string]any:
			out[k] = s.SanitiseMap(val)
		default:
			out[k] = v
		}
	}
	return out
}
