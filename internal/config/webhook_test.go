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
