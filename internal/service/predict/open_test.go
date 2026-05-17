package predict

import (
	"context"
	"errors"
	"testing"
	"time"
)

func openSvc(t *testing.T, lookup OpenLookup) *OpenService {
	t.Helper()
	return NewOpenService(OpenServiceConfig{Lookup: lookup})
}

type fakeLookup struct {
	tier    string
	primary string
	ok      bool
	err     error
	calls   int
}

func (f *fakeLookup) Lookup(_ context.Context, _, _ string) (string, string, bool, error) {
	f.calls++
	return f.tier, f.primary, f.ok, f.err
}

func TestOpen_TierGated(t *testing.T) {
	svc := openSvc(t, nil)
	cases := []struct {
		tier string
		want WarningLevel
		show bool
		code string
	}{
		{"trusted", WarnNone, false, ""},
		{"informational", WarnNone, false, ""},
		{"caution", WarnCaution, true, "tier_caution"},
		{"warning", WarnWarning, true, "tier_warning"},
		{"high_risk", WarnHigh, true, "tier_high_risk"},
		{"highrisk", WarnHigh, true, "tier_high_risk"},
		{"blocked", WarnHigh, true, "tier_blocked"},
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
		if c.show && res.Code != c.code {
			t.Fatalf("tier=%q code=%q want=%q", c.tier, res.Code, c.code)
		}
	}
}

func TestOpen_RejectsInvalid(t *testing.T) {
	svc := openSvc(t, nil)
	if _, err := svc.Predict(context.Background(), OpenRequest{}); err == nil {
		t.Fatal("expected error for empty tenant")
	}
	if _, err := svc.Predict(context.Background(), OpenRequest{TenantID: "acme"}); err == nil {
		t.Fatal("expected error for empty pseudo_message_id")
	}
}

func TestOpen_LookupFillsTier(t *testing.T) {
	lookup := &fakeLookup{tier: "warning", primary: "LIKELY_PHISHING", ok: true}
	svc := openSvc(t, lookup)
	res, err := svc.Predict(context.Background(), OpenRequest{
		TenantID: "acme", PseudoMessageID: "m1",
	})
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if lookup.calls != 1 {
		t.Fatalf("lookup calls=%d", lookup.calls)
	}
	if !res.ShowWarning || res.Level != WarnWarning {
		t.Fatalf("expected warning level, got %+v", res)
	}
	if res.Tier != "Warning" {
		t.Fatalf("tier=%q, want canonical %q", res.Tier, "Warning")
	}
	if res.Reason != "LIKELY_PHISHING" {
		t.Fatalf("reason=%q", res.Reason)
	}
}

func TestOpen_LookupSkippedWhenTierProvided(t *testing.T) {
	lookup := &fakeLookup{tier: "blocked", ok: true}
	svc := openSvc(t, lookup)
	res, err := svc.Predict(context.Background(), OpenRequest{
		TenantID: "acme", PseudoMessageID: "m1", Tier: "informational",
	})
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if lookup.calls != 0 {
		t.Fatalf("lookup called: %d", lookup.calls)
	}
	if res.ShowWarning {
		t.Fatalf("informational must not warn, got %+v", res)
	}
}

func TestOpen_LookupMissingNoWarning(t *testing.T) {
	lookup := &fakeLookup{ok: false}
	svc := openSvc(t, lookup)
	res, err := svc.Predict(context.Background(), OpenRequest{
		TenantID: "acme", PseudoMessageID: "m1",
	})
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if res.ShowWarning {
		t.Fatalf("expected no warning, got %+v", res)
	}
}

func TestOpen_LookupErrorPropagated(t *testing.T) {
	wantErr := errors.New("boom")
	lookup := &fakeLookup{err: wantErr}
	svc := openSvc(t, lookup)
	_, err := svc.Predict(context.Background(), OpenRequest{
		TenantID: "acme", PseudoMessageID: "m1",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err=%v want=%v", err, wantErr)
	}
}

func TestOpen_SanitisesUnknownCategory(t *testing.T) {
	svc := openSvc(t, nil)
	res, err := svc.Predict(context.Background(), OpenRequest{
		TenantID: "acme", PseudoMessageID: "m1",
		Tier: "warning", Category: "<script>alert(1)</script>",
	})
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if res.Reason != "" {
		t.Fatalf("reason should be elided, got %q", res.Reason)
	}
}

func TestOpen_LatencyRecorded(t *testing.T) {
	calls := 0
	svc := NewOpenService(OpenServiceConfig{Clock: func() time.Time {
		calls++
		return time.Unix(0, int64(calls)*int64(time.Millisecond))
	}})
	res, err := svc.Predict(context.Background(), OpenRequest{
		TenantID: "acme", PseudoMessageID: "m1", Tier: "warning",
	})
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if res.LatencyMs <= 0 {
		t.Fatalf("latency=%d", res.LatencyMs)
	}
}
