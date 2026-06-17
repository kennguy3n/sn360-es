package config

import (
	"net/netip"
	"strings"
	"testing"
)

// TestLoadWebhookEgress_Defaults: with neither env var set the guard
// is active (AllowPrivate false) and the allow-list is empty.
func TestLoadWebhookEgress_Defaults(t *testing.T) {
	t.Setenv("WEBHOOK_EGRESS_ALLOW_PRIVATE", "")
	t.Setenv("WEBHOOK_EGRESS_ALLOWED_CIDRS", "")

	we, err := loadWebhookEgress()
	if err != nil {
		t.Fatalf("loadWebhookEgress: %v", err)
	}
	if we.AllowPrivate {
		t.Error("AllowPrivate = true; want false by default (guard active)")
	}
	if len(we.AllowedCIDRs) != 0 {
		t.Errorf("AllowedCIDRs = %v; want empty", we.AllowedCIDRs)
	}
}

// TestLoadWebhookEgress_ParsesCIDRs: a comma-separated list is parsed,
// masked, and order-preserved.
func TestLoadWebhookEgress_ParsesCIDRs(t *testing.T) {
	t.Setenv("WEBHOOK_EGRESS_ALLOW_PRIVATE", "true")
	t.Setenv("WEBHOOK_EGRESS_ALLOWED_CIDRS", " 10.20.0.0/16 , 192.0.2.0/24 ")

	we, err := loadWebhookEgress()
	if err != nil {
		t.Fatalf("loadWebhookEgress: %v", err)
	}
	if !we.AllowPrivate {
		t.Error("AllowPrivate = false; want true")
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	if len(we.AllowedCIDRs) != len(want) {
		t.Fatalf("AllowedCIDRs = %v; want %v", we.AllowedCIDRs, want)
	}
	for i := range want {
		if we.AllowedCIDRs[i] != want[i] {
			t.Errorf("AllowedCIDRs[%d] = %v; want %v", i, we.AllowedCIDRs[i], want[i])
		}
	}
}

// TestLoadWebhookEgress_RejectsBadCIDR: a malformed entry must fail
// boot, namespaced under its env var.
func TestLoadWebhookEgress_RejectsBadCIDR(t *testing.T) {
	t.Setenv("WEBHOOK_EGRESS_ALLOWED_CIDRS", "10.0.0.0/8,not-a-cidr")

	_, err := loadWebhookEgress()
	if err == nil {
		t.Fatal("expected error for malformed CIDR, got nil")
	}
	if !strings.Contains(err.Error(), "WEBHOOK_EGRESS_ALLOWED_CIDRS") {
		t.Errorf("error %q must namespace itself under WEBHOOK_EGRESS_ALLOWED_CIDRS", err)
	}
}

// webhookEgressCfg builds a Config in the given environment carrying
// only the webhook-egress settings under test.
func webhookEgressCfg(env Environment, allowPrivate bool, cidrs ...string) Config {
	we := WebhookEgress{AllowPrivate: allowPrivate}
	for _, c := range cidrs {
		we.AllowedCIDRs = append(we.AllowedCIDRs, netip.MustParsePrefix(c).Masked())
	}
	return Config{Environment: env, WebhookEgress: we}
}

// TestSecurityWarnings_NonProdQuiet: the escape hatches are expected in
// dev/local/QA, so SecurityWarnings stays silent there even for the
// most permissive configuration.
func TestSecurityWarnings_NonProdQuiet(t *testing.T) {
	for _, env := range []Environment{EnvironmentLocal, EnvironmentDev, EnvironmentQA} {
		cfg := webhookEgressCfg(env, true, "0.0.0.0/0", "169.254.0.0/16")
		if w := cfg.SecurityWarnings(); len(w) != 0 {
			t.Errorf("env=%s: SecurityWarnings = %v; want none", env, w)
		}
	}
}

// TestSecurityWarnings_AllowPrivate: disabling the guard in production
// emits exactly one warning, and the allow-list is moot (the guard is
// fully off) so additional CIDRs do not multiply the warnings.
func TestSecurityWarnings_AllowPrivate(t *testing.T) {
	for _, env := range []Environment{EnvironmentUAT, EnvironmentProd} {
		cfg := webhookEgressCfg(env, true, "0.0.0.0/0", "169.254.0.0/16")
		w := cfg.SecurityWarnings()
		if len(w) != 1 {
			t.Fatalf("env=%s: SecurityWarnings = %v; want exactly one warning", env, w)
		}
		if !strings.Contains(w[0], "WEBHOOK_EGRESS_ALLOW_PRIVATE=true") {
			t.Errorf("env=%s: warning %q must name WEBHOOK_EGRESS_ALLOW_PRIVATE", env, w[0])
		}
	}
}

// TestSecurityWarnings_DefaultRouteCIDR: a 0.0.0.0/0 (or ::/0) allow-
// list entry effectively disables the guard and must warn.
func TestSecurityWarnings_DefaultRouteCIDR(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		cfg := webhookEgressCfg(EnvironmentProd, false, cidr)
		w := cfg.SecurityWarnings()
		if len(w) != 1 || !strings.Contains(w[0], "entire address space") {
			t.Fatalf("cidr=%s: SecurityWarnings = %v; want a default-route breadth warning", cidr, w)
		}
	}
}

// TestSecurityWarnings_MetadataCIDR: an allow-list entry that re-permits
// the cloud-metadata endpoint must warn.
func TestSecurityWarnings_MetadataCIDR(t *testing.T) {
	for _, cidr := range []string{"169.254.0.0/16", "169.254.169.254/32"} {
		cfg := webhookEgressCfg(EnvironmentProd, false, cidr)
		w := cfg.SecurityWarnings()
		if len(w) != 1 || !strings.Contains(w[0], "169.254.169.254") {
			t.Fatalf("cidr=%s: SecurityWarnings = %v; want a cloud-metadata warning", cidr, w)
		}
	}
}

// TestSecurityWarnings_NarrowSubnetQuiet: a specific internal subnet is
// the intended use of the allow-list and must not warn — including the
// full RFC 1918 /8, which is broad but legitimate and contains no
// metadata endpoint.
func TestSecurityWarnings_NarrowSubnetQuiet(t *testing.T) {
	cfg := webhookEgressCfg(EnvironmentProd, false,
		"10.0.0.0/8", "172.16.0.0/12", "192.168.50.0/24")
	if w := cfg.SecurityWarnings(); len(w) != 0 {
		t.Errorf("SecurityWarnings = %v; want none for narrow/internal subnets", w)
	}
}

// TestSecurityWarnings_MixedAllowList: each offending CIDR contributes
// its own warning while benign entries stay silent.
func TestSecurityWarnings_MixedAllowList(t *testing.T) {
	cfg := webhookEgressCfg(EnvironmentProd, false,
		"10.20.0.0/16", "169.254.0.0/16", "0.0.0.0/0")
	if w := cfg.SecurityWarnings(); len(w) != 2 {
		t.Fatalf("SecurityWarnings = %v; want two warnings (metadata + default-route)", w)
	}
}
