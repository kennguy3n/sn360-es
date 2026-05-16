package relationship

import (
	"context"
	"testing"
	"time"
)

func TestVendorDiscovery_ProposesRecurringSenders(t *testing.T) {
	d := NewVendorDiscovery(DefaultVendorDiscoveryConfig(), nil)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	d.WithClock(fixedClock(now))
	obs := []SenderObservation{
		// Good vendor candidate.
		{Domain: "saas-vendor.com", InboundCount: 40, OutboundCount: 6, DistinctRecipients: 5,
			FirstSeen: now.Add(-25 * 24 * time.Hour), LastSeen: now},
		// Too noisy / one-off.
		{Domain: "noise.com", InboundCount: 1, DistinctRecipients: 1, FirstSeen: now.Add(-2 * 24 * time.Hour), LastSeen: now},
		// Free domain — excluded.
		{Domain: "gmail.com", InboundCount: 80, DistinctRecipients: 30, FirstSeen: now.Add(-25 * 24 * time.Hour), LastSeen: now},
		// Recent only — fails window.
		{Domain: "fresh.com", InboundCount: 50, DistinctRecipients: 5, FirstSeen: now.Add(-3 * 24 * time.Hour), LastSeen: now},
	}
	proposals, err := d.Propose(context.Background(), "acme", obs)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if len(proposals) != 1 {
		t.Fatalf("proposals: %d (want 1) %+v", len(proposals), proposals)
	}
	if proposals[0].Domain != "saas-vendor.com" {
		t.Fatalf("domain: %q", proposals[0].Domain)
	}
	if !proposals[0].Bidirectional {
		t.Fatal("expected bidirectional")
	}
	if !proposals[0].AutoApprove {
		t.Fatalf("expected auto-approve, got conf=%.2f", proposals[0].Confidence)
	}
}

func TestVendorDiscovery_RequiresTenant(t *testing.T) {
	d := NewVendorDiscovery(DefaultVendorDiscoveryConfig(), nil)
	if _, err := d.Propose(context.Background(), "", nil); err == nil {
		t.Fatal("expected error for empty tenant")
	}
}

func TestVendorDiscovery_LowConfidenceNotAutoApproved(t *testing.T) {
	d := NewVendorDiscovery(DefaultVendorDiscoveryConfig(), nil)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	d.WithClock(fixedClock(now))
	proposals, _ := d.Propose(context.Background(), "acme", []SenderObservation{
		{Domain: "okay.com", InboundCount: 6, DistinctRecipients: 2, OutboundCount: 0,
			FirstSeen: now.Add(-20 * 24 * time.Hour), LastSeen: now},
	})
	if len(proposals) != 1 {
		t.Fatalf("proposals: %d", len(proposals))
	}
	if proposals[0].AutoApprove {
		t.Fatalf("expected no auto-approve, got conf=%.2f", proposals[0].Confidence)
	}
	if proposals[0].Bidirectional {
		t.Fatal("expected no bidirectional flag")
	}
}
