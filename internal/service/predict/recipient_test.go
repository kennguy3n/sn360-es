package predict

import (
	"context"
	"testing"
	"time"
)

func TestRecipient_LookalikeWins(t *testing.T) {
	svc := NewRecipientService(RecipientServiceConfig{
		Lookalike: NewStaticLookalikeChecker(map[string]string{"acm3.com": "acme.com"}),
	})
	res, err := svc.Predict(context.Background(), RecipientRequest{
		TenantID: "acme",
		Recipients: []RecipientCandidate{
			{UserHash: "u1", Domain: "acm3.com", IsExternal: true},
		},
	})
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if res.OverallLevel != WarnHigh {
		t.Fatalf("level: %d", res.OverallLevel)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Code != "lookalike_recipient" {
		t.Fatalf("warnings: %+v", res.Warnings)
	}
}

func TestRecipient_ExternalOnInternalThread(t *testing.T) {
	known := true
	svc := NewRecipientService(RecipientServiceConfig{})
	res, _ := svc.Predict(context.Background(), RecipientRequest{
		TenantID: "acme",
		ThreadIsInternal: true,
		Recipients: []RecipientCandidate{
			{UserHash: "u1", Domain: "outside.com", IsExternal: true, IsKnownContact: &known},
		},
	})
	if res.OverallLevel != WarnWarning {
		t.Fatalf("level: %d", res.OverallLevel)
	}
	if res.Warnings[0].Code != "external_on_internal_thread" {
		t.Fatalf("code: %q", res.Warnings[0].Code)
	}
}

func TestRecipient_UnusualExternalRecipient(t *testing.T) {
	notKnown := false
	svc := NewRecipientService(RecipientServiceConfig{})
	res, _ := svc.Predict(context.Background(), RecipientRequest{
		TenantID: "acme",
		Recipients: []RecipientCandidate{
			{UserHash: "u1", Domain: "fresh.com", IsExternal: true, IsKnownContact: &notKnown},
		},
	})
	if res.OverallLevel != WarnCaution {
		t.Fatalf("level: %d", res.OverallLevel)
	}
}

// TestRecipient_UnknownContactStatusNoWarning verifies that omitting
// IsKnownContact (nil pointer) suppresses unusual_external_recipient.
// This matches the add-in calling convention: clients that have no
// way to determine contact status omit the field and let the server
// fall back to its own contact-store lookup elsewhere.
func TestRecipient_UnknownContactStatusNoWarning(t *testing.T) {
	svc := NewRecipientService(RecipientServiceConfig{})
	res, _ := svc.Predict(context.Background(), RecipientRequest{
		TenantID: "acme",
		Recipients: []RecipientCandidate{
			{UserHash: "u1", Domain: "fresh.com", IsExternal: true, IsKnownContact: nil},
		},
	})
	if res.OverallLevel != WarnNone {
		t.Fatalf("level: %d want=%d", res.OverallLevel, WarnNone)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %+v", res.Warnings)
	}
}

func TestRecipient_KnownContactNoWarning(t *testing.T) {
	known := true
	svc := NewRecipientService(RecipientServiceConfig{})
	res, _ := svc.Predict(context.Background(), RecipientRequest{
		TenantID: "acme",
		Recipients: []RecipientCandidate{
			{UserHash: "u1", Domain: "vendor.com", IsExternal: true, IsKnownContact: &known},
		},
	})
	if res.OverallLevel != WarnNone {
		t.Fatalf("level: %d", res.OverallLevel)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %+v", res.Warnings)
	}
}

func TestRecipient_LatencyBudget(t *testing.T) {
	calls := 0
	svc := NewRecipientService(RecipientServiceConfig{
		Clock: func() time.Time {
			calls++
			return time.Unix(0, int64(calls)*int64(time.Millisecond))
		},
	})
	res, _ := svc.Predict(context.Background(), RecipientRequest{
		TenantID: "acme",
		Recipients: []RecipientCandidate{{UserHash: "u1", Domain: "x.com", IsExternal: true}},
	})
	if res.LatencyMs <= 0 {
		t.Fatalf("latency: %d", res.LatencyMs)
	}
}

func TestRecipient_RejectsInvalid(t *testing.T) {
	svc := NewRecipientService(RecipientServiceConfig{})
	if _, err := svc.Predict(context.Background(), RecipientRequest{}); err == nil {
		t.Fatal("expected error for empty tenant")
	}
	if _, err := svc.Predict(context.Background(), RecipientRequest{TenantID: "acme"}); err == nil {
		t.Fatal("expected error for no recipients")
	}
}

func TestOpen_TierGated(t *testing.T) {
	svc := NewOpenService()
	cases := []struct {
		tier string
		want WarningLevel
		show bool
	}{
		{"trusted", WarnNone, false},
		{"informational", WarnNone, false},
		{"caution", WarnCaution, true},
		{"warning", WarnWarning, true},
		{"high_risk", WarnHigh, true},
		{"blocked", WarnHigh, true},
	}
	for _, c := range cases {
		res, err := svc.Predict(context.Background(), OpenRequest{
			TenantID: "acme", PseudoMessageID: "m1", Tier: c.tier,
		})
		if err != nil {
			t.Fatalf("Predict(%q): %v", c.tier, err)
		}
		if res.ShowWarning != c.show {
			t.Fatalf("tier=%q show=%v want=%v", c.tier, res.ShowWarning, c.show)
		}
		if res.Level != c.want {
			t.Fatalf("tier=%q level=%d want=%d", c.tier, res.Level, c.want)
		}
	}
}

func TestOpen_RejectsInvalid(t *testing.T) {
	svc := NewOpenService()
	if _, err := svc.Predict(context.Background(), OpenRequest{}); err == nil {
		t.Fatal("expected error for empty tenant")
	}
	if _, err := svc.Predict(context.Background(), OpenRequest{TenantID: "acme"}); err == nil {
		t.Fatal("expected error for empty pseudo_message_id")
	}
}
