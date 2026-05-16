// Package tier0 implements the Tier 0 classification gates that decide
// whether an email needs further ML inspection or can short-circuit
// straight to a verdict.
//
// The gates are intentionally cheap (<1 ms): pure CPU work, no I/O.
package tier0

import (
	"net/mail"
	"regexp"
	"strings"
)

// RecurringDetector identifies senders that almost certainly produce
// transactional, system-generated messages — `noreply@`, `mailer-daemon@`,
// bounce addresses, etc.
//
// Once such a sender is identified, the gate routes the message away from
// ML stages (no need to spend a GPU inference on every Postmark
// confirmation).
type RecurringDetector struct {
	// localPartRegex matches the email local-part. The default value
	// covers the prefixes documented in PROPOSAL.md plus a handful of
	// common variants (no-reply, notifications, system, support, etc.).
	localPartRegex *regexp.Regexp
	// extraDomains is a small set of fully qualified addresses or
	// suffixes that always count as recurring (e.g. "mailer-daemon").
	extraDomains map[string]struct{}
}

var defaultRecurringRegex = regexp.MustCompile(`^(?i)(` +
	`no[-_.]?reply|` +
	`noreply\d*|` +
	`do[-_.]?not[-_.]?reply|` +
	`mailer[-_.]?daemon|` +
	`bounce|` +
	`postmaster|` +
	`notification(s)?|` +
	`alerts?|` +
	`system|` +
	`automated|` +
	`auto[-_.]?reply|` +
	`mail[-_.]?daemon|` +
	`updates?|` +
	`info|` +
	`support[-_.]?bot|` +
	`bot|` +
	`team[-_.]?bot` +
	`)(\+[^@]*)?$`)

// NewRecurringDetector returns the default detector.
func NewRecurringDetector() *RecurringDetector {
	return &RecurringDetector{
		localPartRegex: defaultRecurringRegex,
		extraDomains: map[string]struct{}{
			"mailer-daemon":                 {},
			"daemon":                        {},
			"bounce":                        {},
			"bounce-no-reply":               {},
			"postmaster":                    {},
			"sender_address_does_not_exist": {},
		},
	}
}

// IsRecurring reports whether sender looks like a recurring / system
// service. It accepts either a bare address ("noreply@acme.com") or a
// named address ("Acme Updates <noreply@acme.com>").
func (d *RecurringDetector) IsRecurring(sender string) bool {
	sender = strings.TrimSpace(sender)
	if sender == "" {
		return false
	}
	addr, err := mail.ParseAddress(sender)
	if err != nil {
		// Best-effort fallback: try to chop off "<>" wrappers manually.
		if at := strings.IndexByte(sender, '<'); at >= 0 {
			if end := strings.IndexByte(sender[at:], '>'); end > 0 {
				return d.IsRecurring(sender[at+1 : at+end])
			}
		}
		// Unknown format — be conservative and report false so the gate
		// doesn't suppress real mail.
		return false
	}
	localAt := strings.IndexByte(addr.Address, '@')
	if localAt <= 0 {
		return false
	}
	local := addr.Address[:localAt]
	if d.localPartRegex.MatchString(local) {
		return true
	}
	if _, ok := d.extraDomains[strings.ToLower(local)]; ok {
		return true
	}
	return false
}
