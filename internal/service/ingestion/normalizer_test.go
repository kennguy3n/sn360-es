package ingestion

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fakePseudo struct{ prefix string }

func (f *fakePseudo) Pseudonymise(v string) string { return f.prefix + ":" + v }

type fakeFreeSet struct{ in map[string]struct{} }

func (f *fakeFreeSet) Contains(d string) bool {
	if f == nil {
		return false
	}
	_, ok := f.in[strings.ToLower(d)]
	return ok
}

func TestNormalize_RejectsMissingProviderMessageID(t *testing.T) {
	n := NewDefaultNormalizer()
	if _, err := n.Normalize(context.Background(), RawEmail{}); err == nil {
		t.Fatal("expected error on empty provider_message_id")
	}
}

func TestNormalize_PopulatesEssentials(t *testing.T) {
	n := NewDefaultNormalizer(
		WithPseudonymizer(&fakePseudo{prefix: "px"}),
		WithFreeDomains(&fakeFreeSet{in: map[string]struct{}{"gmail.com": {}}}),
		WithDefaultLocale("en"),
	)
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	raw := RawEmail{
		ProviderMessageID: "abc",
		TenantID:          "t-1",
		Mailbox:           "user@corp.example",
		Sender:            "alice@gmail.com",
		Recipients:        []string{"user@corp.example"},
		Subject:           "Hello",
		Body:              "Plain body",
		Headers: map[string]string{
			"Authentication-Results": "mx.example.com; spf=pass; dkim=fail; dmarc=pass",
			"Content-Type":           "multipart/mixed; boundary=foo",
			"Content-Language":       "fr",
		},
		ReceivedAt: now,
	}
	req, err := n.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if req.MessageID != "abc" || req.TenantID != "t-1" {
		t.Errorf("ids: %+v", req)
	}
	if req.CorrelationID != "abc" {
		t.Errorf("correlation id: %q", req.CorrelationID)
	}
	if req.Body != "Plain body" {
		t.Errorf("body: %q", req.Body)
	}
	if req.RawBodyHash == "" || req.NormalisedHash == "" {
		t.Error("hashes must be populated")
	}
	if req.Recipient != "px:user@corp.example" {
		t.Errorf("recipient not pseudonymised: %q", req.Recipient)
	}
	if !req.Signals.IsExternal {
		t.Errorf("expected external, got %+v", req.Signals)
	}
	if !req.Signals.IsFreeDomain {
		t.Errorf("expected free domain detection")
	}
	if !req.Signals.HasAttachment {
		t.Errorf("expected attachment signal")
	}
	if req.Signals.SPFResult != "pass" || req.Signals.DKIMResult != "fail" || req.Signals.DMARCResult != "pass" {
		t.Errorf("auth results: %+v", req.Signals)
	}
	if req.Signals.SenderDomain != "gmail.com" {
		t.Errorf("sender domain: %q", req.Signals.SenderDomain)
	}
	if req.Signals.RecipientDomain != "corp.example" {
		t.Errorf("recipient domain: %q", req.Signals.RecipientDomain)
	}
	if req.Locale != "fr" {
		t.Errorf("locale: %q", req.Locale)
	}
	if !req.ReceivedAt.Equal(now) {
		t.Errorf("received_at: got %s want %s", req.ReceivedAt, now)
	}
}

func TestNormalize_HTMLStripping(t *testing.T) {
	n := NewDefaultNormalizer()
	raw := RawEmail{
		ProviderMessageID: "h-1",
		TenantID:          "t-1",
		Mailbox:           "u@x.com",
		Sender:            "ext@y.com",
		HTMLBody:          `<html><head><style>.a{color:red}</style></head><body><p>Visible <b>text</b></p><script>alert(1)</script></body></html>`,
	}
	req, err := n.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if strings.Contains(req.Body, "<") || strings.Contains(req.Body, "alert(") {
		t.Errorf("HTML not stripped: %q", req.Body)
	}
	if !strings.Contains(req.Body, "Visible") || !strings.Contains(req.Body, "text") {
		t.Errorf("visible text not preserved: %q", req.Body)
	}
}

func TestNormalize_HashStability(t *testing.T) {
	n := NewDefaultNormalizer()
	a := RawEmail{ProviderMessageID: "a", Sender: "s@x.com", Subject: "Hi", Body: "Body"}
	b := RawEmail{ProviderMessageID: "b", Sender: "s@x.com", Subject: "Hi", Body: "Body"}
	ra, _ := n.Normalize(context.Background(), a)
	rb, _ := n.Normalize(context.Background(), b)
	if ra.RawBodyHash != rb.RawBodyHash {
		t.Errorf("raw_body_hash should be stable across identical bodies: %q vs %q", ra.RawBodyHash, rb.RawBodyHash)
	}
	if ra.NormalisedHash != rb.NormalisedHash {
		t.Errorf("normalised_hash should be stable: %q vs %q", ra.NormalisedHash, rb.NormalisedHash)
	}
}

func TestNormalize_DomainSignalsForInternal(t *testing.T) {
	n := NewDefaultNormalizer()
	raw := RawEmail{
		ProviderMessageID: "m",
		Sender:            "alice@corp.example",
		Mailbox:           "bob@corp.example",
	}
	req, _ := n.Normalize(context.Background(), raw)
	if req.Signals.IsExternal {
		t.Errorf("same-domain sender should be internal, got external")
	}
}

func TestNormalize_NoPseudonymizerKeepsRecipient(t *testing.T) {
	n := NewDefaultNormalizer()
	raw := RawEmail{
		ProviderMessageID: "x",
		Mailbox:           "rec@dom.com",
		Sender:            "ext@dom2.com",
	}
	req, _ := n.Normalize(context.Background(), raw)
	if req.Recipient != "rec@dom.com" {
		t.Errorf("recipient passthrough: %q", req.Recipient)
	}
}

func TestNormalize_FallsBackToFirstRecipientWhenMailboxEmpty(t *testing.T) {
	n := NewDefaultNormalizer()
	raw := RawEmail{
		ProviderMessageID: "x",
		Recipients:        []string{"first@dom.com", "second@dom.com"},
		Sender:            "ext@other.com",
	}
	req, _ := n.Normalize(context.Background(), raw)
	if req.Recipient != "first@dom.com" {
		t.Errorf("recipient fallback: %q", req.Recipient)
	}
}

func TestNormalize_LocaleDefault(t *testing.T) {
	n := NewDefaultNormalizer(WithDefaultLocale("en-GB"))
	raw := RawEmail{ProviderMessageID: "x"}
	req, _ := n.Normalize(context.Background(), raw)
	if req.Locale != "en-GB" {
		t.Errorf("locale default: %q", req.Locale)
	}
}

func TestExtractAuthResult(t *testing.T) {
	hdr := "mx.example.com; spf=PASS reason=match; dkim=fail; dmarc=Pass action=none"
	if got := extractAuthResult(hdr, "spf"); got != "pass" {
		t.Errorf("spf: %q", got)
	}
	if got := extractAuthResult(hdr, "dkim"); got != "fail" {
		t.Errorf("dkim: %q", got)
	}
	if got := extractAuthResult(hdr, "DMARC"); got != "pass" {
		t.Errorf("dmarc: %q", got)
	}
	if got := extractAuthResult(hdr, "bimi"); got != "" {
		t.Errorf("unknown mechanism should return empty, got %q", got)
	}
}

func TestExtractDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"alice@example.com", "example.com"},
		{"  bob@EXAMPLE.com>", "example.com"},
		{"<carol@x.io>", "x.io"},
		{"noatsign", ""},
		{"@", ""},
		{"@example.com", "example.com"},
		{"user@", ""},
	}
	for _, c := range cases {
		got := extractDomain(c.in)
		if got != c.want {
			t.Errorf("extractDomain(%q): got %q want %q", c.in, got, c.want)
		}
	}
}

func TestCollapseWhitespace(t *testing.T) {
	if got := collapseWhitespace("  hello \n world   "); got != "hello world" {
		t.Errorf("collapseWhitespace: %q", got)
	}
}

func TestMarshalRequestPopulatesReceivedAtFallback(t *testing.T) {
	n := NewDefaultNormalizer()
	raw := RawEmail{ProviderMessageID: "x", Body: "body"}
	req, _ := n.Normalize(context.Background(), raw)
	if !req.ReceivedAt.IsZero() {
		t.Errorf("expected zero received_at after normalize, got %s", req.ReceivedAt)
	}
	payload, err := marshalRequest(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(payload), "received_at") {
		t.Errorf("payload missing received_at: %s", payload)
	}
}
