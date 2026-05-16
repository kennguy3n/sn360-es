package action

import (
	"strings"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// AuthVerdict is the aggregate sender-authentication result we display
// in the banner chip.
type AuthVerdict string

const (
	AuthVerified   AuthVerdict = "verified"
	AuthUnverified AuthVerdict = "unverified"
	AuthFailed     AuthVerdict = "failed"
	AuthUnknown    AuthVerdict = "unknown"
)

// Valid reports whether v is a known verdict.
func (v AuthVerdict) Valid() bool {
	switch v {
	case AuthVerified, AuthUnverified, AuthFailed, AuthUnknown:
		return true
	}
	return false
}

// AggregateSenderAuth derives a single AuthVerdict from the Rspamd
// outcome. The mapping is documented at the top of the function.
//
//   - DMARC=pass + SPF=pass + DKIM=pass     → Verified
//   - DMARC=fail OR SPF=fail (hardfail)     → Failed
//   - DKIM=permerror / signature missing AND no DMARC fail → Unverified
//   - Any other combination                  → Unverified
//   - No Rspamd outcome                      → Unknown
//
// Rspamd surfaces these symbols via the symbols map (see
// nges-evaluate-svc for the canonical set we copied).
func AggregateSenderAuth(r *dto.RspamdOutcome) AuthVerdict {
	if r == nil || r.Symbols == nil {
		return AuthUnknown
	}
	spf := classifySymbol(r.Symbols, "R_SPF_ALLOW", "R_SPF_PASS")
	spfFail := classifySymbol(r.Symbols, "R_SPF_FAIL", "R_SPF_SOFTFAIL")
	dkim := classifySymbol(r.Symbols, "R_DKIM_ALLOW", "DKIM_VALID")
	dkimFail := classifySymbol(r.Symbols, "R_DKIM_REJECT", "R_DKIM_PERMFAIL")
	dmarc := classifySymbol(r.Symbols, "DMARC_POLICY_ALLOW")
	dmarcFail := classifySymbol(r.Symbols, "DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE", "DMARC_POLICY_REJECT_MISALIGNED_SPF")

	if dmarcFail || spfFail {
		return AuthFailed
	}
	if dmarc && spf && dkim {
		return AuthVerified
	}
	if dkimFail || (!spf && !dkim) {
		return AuthUnverified
	}
	return AuthUnverified
}

// classifySymbol returns true if any of names is present in symbols.
// Comparison is case-sensitive — Rspamd symbols are conventionally
// upper-case so a strict match is fine.
func classifySymbol(symbols map[string]float64, names ...string) bool {
	if len(symbols) == 0 {
		return false
	}
	for _, n := range names {
		if _, ok := symbols[n]; ok {
			return true
		}
	}
	// Some Rspamd builds prefix with R_; allow case-insensitive fallback
	// to keep us forward-compatible.
	for k := range symbols {
		for _, n := range names {
			if strings.EqualFold(k, n) {
				return true
			}
		}
	}
	return false
}
