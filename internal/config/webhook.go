package config

import (
	"fmt"
	"net/netip"
)

// WebhookEgress configures the per-tenant webhook-sink egress path's
// dial-time SSRF guard. The guard refuses to POST verdict payloads to
// non-public destinations (loopback, RFC 1918 private, link-local —
// including the 169.254.169.254 cloud-metadata endpoint — IPv6 ULA,
// carrier-grade NAT, unspecified, and multicast addresses), closing
// the SSRF/internal-port-probe primitive a tenant admin could
// otherwise reach by registering a sink whose hostname resolves to an
// internal IP.
type WebhookEgress struct {
	// AllowPrivate disables the guard entirely so the dispatcher may
	// POST to private/loopback/link-local destinations. Default false
	// (guard active). The escape hatch for a deployment that
	// legitimately ships verdicts to a private SIEM with no public
	// ingress. Loaded from WEBHOOK_EGRESS_ALLOW_PRIVATE.
	AllowPrivate bool
	// AllowedCIDRs is a narrower escape hatch: destination prefixes
	// permitted even when the guard is active, for an operator who
	// ships to one known internal subnet but wants every other
	// non-public destination blocked. Loaded from
	// WEBHOOK_EGRESS_ALLOWED_CIDRS (comma-separated CIDRs).
	AllowedCIDRs []netip.Prefix
}

// loadWebhookEgress parses the webhook-egress SSRF-guard settings.
// A malformed CIDR fails boot rather than silently widening or
// narrowing the allow-list, matching the fail-fast policy used for the
// other allow-list-style config (PG_REGION_MAP, NATS_SUPERCLUSTER).
func loadWebhookEgress() (WebhookEgress, error) {
	we := WebhookEgress{
		AllowPrivate: getBool("WEBHOOK_EGRESS_ALLOW_PRIVATE", false),
	}
	for _, raw := range parseCSV(getStr("WEBHOOK_EGRESS_ALLOWED_CIDRS", "")) {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return WebhookEgress{}, fmt.Errorf("WEBHOOK_EGRESS_ALLOWED_CIDRS: %q is not a valid CIDR: %w", raw, err)
		}
		we.AllowedCIDRs = append(we.AllowedCIDRs, p.Masked())
	}
	return we, nil
}
