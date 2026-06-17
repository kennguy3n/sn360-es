package webhook

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// cgnatPrefix is RFC 6598 shared address space (100.64.0.0/10). It is
// not RFC 1918 private (so netip.Addr.IsPrivate reports false) but is
// not publicly routable either, and some clouds expose their
// instance-metadata service on it (e.g. Alibaba Cloud's
// 100.100.100.200). Treat it as a blocked egress destination.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// SSRFGuard rejects outbound webhook connections whose resolved
// destination IP is not a publicly routable unicast address —
// loopback, RFC 1918 private, link-local (which includes the
// 169.254.169.254 cloud-metadata endpoint), IPv6 unique-local,
// carrier-grade NAT, unspecified, and multicast addresses are all
// refused.
//
// It is installed as the net.Dialer.Control hook on the publisher's
// HTTP transport, so the check runs after DNS resolution against the
// concrete IP the dialer is about to connect to. That placement is
// deliberate: it is not bypassable by DNS rebinding, where a hostname
// passes a parse-time validation as a public IP but later resolves to
// a private one at dial time.
type SSRFGuard struct {
	// allowPrivate, when true, disables the guard entirely. It is the
	// escape hatch for a deployment that legitimately ships verdicts
	// to a private SIEM with no public ingress at all.
	allowPrivate bool
	// allowed is a narrower escape hatch: specific CIDRs that are
	// permitted even though they would otherwise be blocked, for an
	// operator who wants to keep the guard on but whitelist one
	// internal receiver subnet.
	allowed []netip.Prefix
}

// NewSSRFGuard builds a guard. When allowPrivate is true every
// destination is permitted. allowed lists CIDR prefixes that are
// permitted even when the guard is otherwise active; invalid prefixes
// are dropped (the config layer validates them at boot, so a bad
// entry here would already have failed startup).
func NewSSRFGuard(allowPrivate bool, allowed []netip.Prefix) *SSRFGuard {
	masked := make([]netip.Prefix, 0, len(allowed))
	for _, p := range allowed {
		if p.IsValid() {
			masked = append(masked, p.Masked())
		}
	}
	return &SSRFGuard{allowPrivate: allowPrivate, allowed: masked}
}

// Control implements the net.Dialer.Control hook signature. address is
// the concrete "ip:port" the dialer resolved to.
func (g *SSRFGuard) Control(network, address string, _ syscall.RawConn) error {
	if g == nil || g.allowPrivate {
		return nil
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("webhook: refusing non-tcp dial network %q", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("webhook: cannot parse dial address %q: %w", address, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("webhook: dial address %q is not an IP literal: %w", host, err)
	}
	addr = addr.Unmap()
	for _, p := range g.allowed {
		if p.Contains(addr) {
			return nil
		}
	}
	if reason := blockedReason(addr); reason != "" {
		return fmt.Errorf("webhook: refusing to dial non-public address %s (%s)", addr, reason)
	}
	return nil
}

// blockedReason returns a non-empty, human-readable reason when addr
// is not a publicly routable unicast address, or "" when the dial is
// allowed.
func blockedReason(addr netip.Addr) string {
	switch {
	case !addr.IsValid():
		return "invalid address"
	case addr.IsUnspecified():
		return "unspecified address"
	case addr.IsLoopback():
		return "loopback"
	case addr.IsLinkLocalUnicast():
		return "link-local unicast"
	case addr.IsLinkLocalMulticast():
		return "link-local multicast"
	case addr.IsInterfaceLocalMulticast():
		return "interface-local multicast"
	case addr.IsMulticast():
		return "multicast"
	case addr.IsPrivate():
		return "private (RFC1918/ULA)"
	case cgnatPrefix.Contains(addr):
		return "carrier-grade NAT (RFC6598)"
	}
	return ""
}
