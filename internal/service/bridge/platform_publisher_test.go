package bridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

// TestKindForVerdict_PrimaryCategoryRouting checks that the
// subject-suffix mapping matches the PRODUCT_PLAN.md WS-5A.1
// subject table for every primary category currently produced by
// the evaluator. The platform's correlation rules subscribe to
// these subjects by name, so any drift here silently re-routes
// events away from the rule that's expecting them.
func TestKindForVerdict_PrimaryCategoryRouting(t *testing.T) {
	cases := []struct {
		name    string
		primary constant.Category
		want    string
	}{
		// Phishing family — the default bucket.
		{"likely phishing", constant.CategoryLikelyPhishing, KindPhishing},
		{"credential harvesting", constant.CategoryCredentialHarvesting, KindPhishing},
		{"lookalike domain", constant.CategoryLookalikeDomain, KindPhishing},
		{"suspicious URL", constant.CategorySuspiciousURL, KindPhishing},
		{"QR phishing", constant.CategoryQRPhishing, KindPhishing},
		{"scam/fraud", constant.CategoryScamFraud, KindPhishing},
		{"auth failed", constant.CategoryAuthFailed, KindPhishing},

		// BEC family — fan into the bec subject.
		{"BEC impersonation", constant.CategoryBECImpersonation, KindBEC},
		{"account takeover", constant.CategoryAccountTakeoverSuspected, KindBEC},
		{"vendor compromise", constant.CategoryVendorCompromise, KindBEC},
		{"invoice fraud", constant.CategoryInvoiceFraud, KindBEC},

		// Malware family — attachment-bearing categories.
		{"suspicious attachment", constant.CategorySuspiciousAttachment, KindMalware},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := &dto.EvaluateResult{Primary: tc.primary, Tier: constant.TierBlocked}
			got := kindForVerdict(res)
			if got != tc.want {
				t.Fatalf("kindForVerdict(%s) = %q, want %q", tc.primary, got, tc.want)
			}
		})
	}
}

// TestKindForVerdict_HighAttachmentScorePromotesToMalware verifies
// the attachment-score fallback: even when the primary category is
// not explicitly attachment-based, an attachment score >= 70
// re-buckets the event into the .malware subject so the platform's
// malware-bearing-attachment rule fires.
func TestKindForVerdict_HighAttachmentScorePromotesToMalware(t *testing.T) {
	score := 90
	res := &dto.EvaluateResult{
		Primary:         constant.CategoryLikelyPhishing,
		AttachmentScore: &score,
		Tier:            constant.TierBlocked,
	}
	if got := kindForVerdict(res); got != KindMalware {
		t.Fatalf("kindForVerdict with attachment score 90 = %q, want %q", got, KindMalware)
	}
}

// TestKindForVerdict_LowAttachmentScoreStaysPhishing keeps the
// promotion gate tight: scores under 70 must NOT trip the malware
// re-bucket. This guards against the malware rule firing on every
// HighRisk message that happens to have a low-score attachment.
func TestKindForVerdict_LowAttachmentScoreStaysPhishing(t *testing.T) {
	score := 50
	res := &dto.EvaluateResult{
		Primary:         constant.CategoryLikelyPhishing,
		AttachmentScore: &score,
		Tier:            constant.TierBlocked,
	}
	if got := kindForVerdict(res); got != KindPhishing {
		t.Fatalf("kindForVerdict with attachment score 50 = %q, want %q", got, KindPhishing)
	}
}

// TestKindForVerdict_NilResult is paranoid coverage: the helper
// should not panic on a nil result and should produce a sensible
// default kind.
func TestKindForVerdict_NilResult(t *testing.T) {
	if got := kindForVerdict(nil); got != KindPhishing {
		t.Fatalf("kindForVerdict(nil) = %q, want %q", got, KindPhishing)
	}
}

// TestRuleIDForVerdict_RangeAndTierStep locks in the 7800-7899
// rule-ID convention documented in the function docstring. Each kind
// owns a 10-ID slice (7800/7810/7820), Blocked is the base ID,
// HighRisk is base+1.
func TestRuleIDForVerdict_RangeAndTierStep(t *testing.T) {
	cases := []struct {
		kind string
		tier constant.Tier
		want string
	}{
		{KindPhishing, constant.TierBlocked, "7800"},
		{KindPhishing, constant.TierHighRisk, "7801"},
		{KindBEC, constant.TierBlocked, "7810"},
		{KindBEC, constant.TierHighRisk, "7811"},
		{KindMalware, constant.TierBlocked, "7820"},
		{KindMalware, constant.TierHighRisk, "7821"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.kind+"_"+string(tc.tier), func(t *testing.T) {
			t.Parallel()
			res := &dto.EvaluateResult{Tier: tc.tier}
			got := ruleIDForVerdict(res, tc.kind)
			if got != tc.want {
				t.Fatalf("ruleIDForVerdict(%s, %s) = %q, want %q", tc.tier, tc.kind, got, tc.want)
			}
		})
	}
}

// TestRuleIDForQuarantineAndEscalation locks the .quarantine and
// .escalation rule IDs (7830/7831 and 7840/7841) so the platform's
// ISM policies and correlation rules stay in sync with the bridge.
func TestRuleIDForQuarantineAndEscalation(t *testing.T) {
	if got := ruleIDForQuarantine(QuarantineActionApplied); got != "7830" {
		t.Fatalf("ruleIDForQuarantine(applied) = %q, want %q", got, "7830")
	}
	if got := ruleIDForQuarantine(QuarantineActionReleased); got != "7831" {
		t.Fatalf("ruleIDForQuarantine(released) = %q, want %q", got, "7831")
	}
	if got := ruleIDForEscalation(EscalationActionCreated); got != "7840" {
		t.Fatalf("ruleIDForEscalation(created) = %q, want %q", got, "7840")
	}
	if got := ruleIDForEscalation(EscalationActionResolved); got != "7841" {
		t.Fatalf("ruleIDForEscalation(resolved) = %q, want %q", got, "7841")
	}
}

// TestRuleLevelForTier locks the tier→Wazuh-level mapping. Blocked
// must land in the level that the platform's ISM policy promotes to
// the `enterprise` retention bucket (>=12), and HighRisk must stay
// at the SOC-investigable-but-not-page-on-call level (8).
func TestRuleLevelForTier(t *testing.T) {
	cases := []struct {
		tier constant.Tier
		want int
	}{
		{constant.TierBlocked, 12},
		{constant.TierHighRisk, 8},
		{constant.TierCaution, 0},
		{constant.TierTrusted, 0},
		{constant.TierWarning, 0},
		{constant.TierInformational, 0},
	}
	for _, tc := range cases {
		if got := ruleLevelForTier(tc.tier); got != tc.want {
			t.Fatalf("ruleLevelForTier(%s) = %d, want %d", tc.tier, got, tc.want)
		}
	}
}

// TestIsTerminalTier locks the bridge's verdict gate: only Blocked
// and HighRisk are forwarded; everything else is dropped. The cost
// model and platform-side correlation depth both depend on this
// gate so any drift must be intentional.
func TestIsTerminalTier(t *testing.T) {
	if !isTerminalTier(constant.TierBlocked) {
		t.Fatal("Blocked must be a terminal tier")
	}
	if !isTerminalTier(constant.TierHighRisk) {
		t.Fatal("HighRisk must be a terminal tier")
	}
	for _, t2 := range []constant.Tier{
		constant.TierCaution,
		constant.TierWarning,
		constant.TierInformational,
		constant.TierTrusted,
	} {
		if isTerminalTier(t2) {
			t.Fatalf("%s must NOT be a terminal tier", t2)
		}
	}
}

// TestHashIdentifier_DeterministicAndTenantScoped checks the
// privacy property the bridge relies on:
//   - same (tenant, email) → same hash (correlation works)
//   - different tenants → different hashes (cross-tenant isolation)
//   - case + whitespace are normalised (User@Example.com == user@example.com)
//   - empty inputs → empty output (no accidental fingerprint of "")
func TestHashIdentifier_DeterministicAndTenantScoped(t *testing.T) {
	const tenantA = "tenant-aaaa-1111"
	const tenantB = "tenant-bbbb-2222"
	const email = "user@example.com"

	h1 := hashIdentifier(tenantA, email)
	h2 := hashIdentifier(tenantA, email)
	if h1 == "" || h1 != h2 {
		t.Fatalf("hashIdentifier must be deterministic; got %q vs %q", h1, h2)
	}
	if h3 := hashIdentifier(tenantB, email); h3 == h1 {
		t.Fatalf("hashIdentifier must be tenant-scoped; tenantA=%q tenantB=%q", h1, h3)
	}
	// 64 hex chars = SHA-256.
	if len(h1) != 64 {
		t.Fatalf("hashIdentifier output length = %d, want 64", len(h1))
	}
	// Case + whitespace normalisation.
	if h := hashIdentifier(tenantA, " User@Example.com "); h != h1 {
		t.Fatalf("hashIdentifier must normalise case+ws; got %q want %q", h, h1)
	}
	// Empty inputs.
	if h := hashIdentifier("", email); h != "" {
		t.Fatalf("hashIdentifier with empty tenant must return empty; got %q", h)
	}
	if h := hashIdentifier(tenantA, ""); h != "" {
		t.Fatalf("hashIdentifier with empty email must return empty; got %q", h)
	}
}

// TestHashIdentifier_NeverEmbedsRawEmail is the contract-level
// privacy assertion: regardless of inputs, the output must never
// contain the raw email (or any substring of the local part) so an
// accidental log of the hash cannot leak the address back.
func TestHashIdentifier_NeverEmbedsRawEmail(t *testing.T) {
	const tenantID = "tenant-priv-0001"
	email := "victim.user.123@bigcompany.example"
	h := hashIdentifier(tenantID, email)
	for _, substr := range []string{"victim", "user", "bigcompany", "@"} {
		if strings.Contains(h, substr) {
			t.Fatalf("hashIdentifier output %q must not contain raw email substring %q", h, substr)
		}
	}
}

// TestDisabledPublisher_AllMethodsNoOp checks the Disabled() return
// is safe to call into for every interface method, including with
// nil arguments. Call sites can then publish unconditionally without
// nil-checking the publisher.
func TestDisabledPublisher_AllMethodsNoOp(t *testing.T) {
	pub := Disabled()
	ctx := context.Background()
	if err := pub.PublishEvaluation(ctx, nil); err != nil {
		t.Fatalf("disabled PublishEvaluation(nil) = %v, want nil", err)
	}
	if err := pub.PublishEvaluation(ctx, &dto.EvaluateResult{}); err != nil {
		t.Fatalf("disabled PublishEvaluation(empty) = %v, want nil", err)
	}
	if err := pub.PublishQuarantine(ctx, QuarantineEvent{}); err != nil {
		t.Fatalf("disabled PublishQuarantine = %v, want nil", err)
	}
	if err := pub.PublishEscalation(ctx, EscalationActionCreated, nil); err != nil {
		t.Fatalf("disabled PublishEscalation(nil) = %v, want nil", err)
	}
	if err := pub.PublishEscalation(ctx, "", &dto.EscalationTicket{}); err != nil {
		t.Fatalf("disabled PublishEscalation(empty) = %v, want nil", err)
	}
	if err := pub.Close(); err != nil {
		t.Fatalf("disabled Close = %v, want nil", err)
	}
}

// TestNew_DisabledFlagReturnsDisabled checks that Enabled=false skips
// the NATS dial entirely and returns the no-op publisher, even when
// URLs are supplied. This is the standalone-deployment path.
func TestNew_DisabledFlagReturnsDisabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pub, err := New(ctx, Config{Enabled: false, URLs: "nats://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatalf("New(disabled) = %v, want nil", err)
	}
	if pub == nil {
		t.Fatal("New(disabled) returned nil publisher")
	}
	if _, ok := pub.(disabledPublisher); !ok {
		t.Fatalf("New(disabled) returned %T, want disabledPublisher", pub)
	}
}

// TestNew_EnabledNoURLsFallsBackToDisabled keeps the bridge from
// hard-failing when an operator turns it on but forgets to set the
// URL list — at boot time we degrade to the no-op publisher and let
// config.validate() flag the misconfiguration with a clear error in
// production. In dev/local where validate is permissive, the bridge
// keeps running with no platform traffic.
func TestNew_EnabledNoURLsFallsBackToDisabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pub, err := New(ctx, Config{Enabled: true, URLs: ""}, nil)
	if err != nil {
		t.Fatalf("New(enabled+no urls) = %v, want nil", err)
	}
	if _, ok := pub.(disabledPublisher); !ok {
		t.Fatalf("New(enabled+no urls) returned %T, want disabledPublisher", pub)
	}
}

// TestConfig_WithDefaults locks in the defaults so a partially-
// populated Config (typical when the operator only sets URLs and
// Enabled) produces sensible runtime values.
func TestConfig_WithDefaults(t *testing.T) {
	c := Config{Enabled: true, URLs: "nats://example:4222"}.withDefaults()
	if c.Name != "sn360-es-bridge" {
		t.Errorf("default Name = %q, want sn360-es-bridge", c.Name)
	}
	if c.Source != "sn360-es" {
		t.Errorf("default Source = %q, want sn360-es", c.Source)
	}
	if c.ClusterID != c.Source {
		t.Errorf("default ClusterID = %q, want = Source %q", c.ClusterID, c.Source)
	}
	if c.ReconnectWait != 2*time.Second {
		t.Errorf("default ReconnectWait = %v, want 2s", c.ReconnectWait)
	}
	if c.MaxReconnects != -1 {
		t.Errorf("default MaxReconnects = %d, want -1", c.MaxReconnects)
	}
	if c.PublishTimeout != 3*time.Second {
		t.Errorf("default PublishTimeout = %v, want 3s", c.PublishTimeout)
	}
	if c.PublishRetries != 3 {
		t.Errorf("default PublishRetries = %d, want 3", c.PublishRetries)
	}
	if c.Stream != defaultPlatformStream {
		t.Errorf("default Stream = %q, want %q", c.Stream, defaultPlatformStream)
	}
}

// TestBuildEnvelope_AlertForwarderShape checks the envelope shape
// the bridge writes matches the JSON the platform's
// services/alert-forwarder/internal/indexer.ParseAlert is already
// indexing. Specifically:
//
//   - the envelope MUST include @timestamp, rule.id, rule.level,
//     and agent.labels.sn360.tenant_id (alert-forwarder reads
//     tenant_id from there)
//   - cluster_id MUST round-trip at the top level when set
//   - data MUST be a JSON object (not a string) so OpenSearch
//     dynamic mapping can index its fields
func TestBuildEnvelope_AlertForwarderShape(t *testing.T) {
	cfg := Config{Source: "sn360-es-unit", ClusterID: "cluster-A"}.withDefaults()
	payload := EvaluationPayload{
		Source:        "sn360-es-unit",
		EventType:     "email.verdict.phishing",
		Action:        "verdict",
		MessageID:     "msg-1",
		Tier:          "Blocked",
		Score:         95,
		EvaluatedAt:   time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
		RecipientHash: "abc",
	}
	env := buildEnvelope(cfg, "tenant-1", "7800", 12, "test", payload)
	blob, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	// Required top-level keys.
	for _, k := range []string{"@timestamp", "cluster_id", "rule", "agent", "data"} {
		if _, ok := got[k]; !ok {
			t.Errorf("envelope missing required key %q; got keys: %v", k, mapKeys(got))
		}
	}
	if got["cluster_id"] != "cluster-A" {
		t.Errorf("cluster_id = %v, want cluster-A", got["cluster_id"])
	}
	rule, _ := got["rule"].(map[string]any)
	if rule["id"] != "7800" {
		t.Errorf("rule.id = %v, want 7800", rule["id"])
	}
	if rule["level"] != float64(12) {
		t.Errorf("rule.level = %v, want 12", rule["level"])
	}
	agent, _ := got["agent"].(map[string]any)
	labels, _ := agent["labels"].(map[string]any)
	sn360, _ := labels["sn360"].(map[string]any)
	if sn360["tenant_id"] != "tenant-1" {
		t.Errorf("agent.labels.sn360.tenant_id = %v, want tenant-1", sn360["tenant_id"])
	}
	if sn360["cluster_id"] != "cluster-A" {
		t.Errorf("agent.labels.sn360.cluster_id = %v, want cluster-A", sn360["cluster_id"])
	}
	// data must be an object, not a string.
	if _, ok := got["data"].(map[string]any); !ok {
		t.Errorf("data must marshal as a JSON object; got %T", got["data"])
	}
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSubject_FollowsPlanFormat keeps the runtime subject string
// matching the WS-5A.1 plan format:
//
//	sn360.events.email.<tenant_id>.<kind>
func TestSubject_FollowsPlanFormat(t *testing.T) {
	p := &natsPlatformPublisher{}
	if got := p.subject("tenant-xyz", KindPhishing); got != "sn360.events.email.tenant-xyz.phishing" {
		t.Errorf("subject(tenant-xyz, phishing) = %q", got)
	}
	if got := p.subject("tenant-xyz", KindBEC); got != "sn360.events.email.tenant-xyz.bec" {
		t.Errorf("subject(tenant-xyz, bec) = %q", got)
	}
	if got := p.subject("tenant-xyz", KindMalware); got != "sn360.events.email.tenant-xyz.malware" {
		t.Errorf("subject(tenant-xyz, malware) = %q", got)
	}
	if got := p.subject("tenant-xyz", KindQuarantine); got != "sn360.events.email.tenant-xyz.quarantine" {
		t.Errorf("subject(tenant-xyz, quarantine) = %q", got)
	}
	if got := p.subject("tenant-xyz", KindEscalation); got != "sn360.events.email.tenant-xyz.escalation" {
		t.Errorf("subject(tenant-xyz, escalation) = %q", got)
	}
}

// TestTimeOrNow returns Now for zero, passes through non-zero in UTC.
func TestTimeOrNow(t *testing.T) {
	if got := timeOrNow(time.Time{}); got.IsZero() {
		t.Fatal("timeOrNow(zero) must return a non-zero time")
	}
	want := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if got := timeOrNow(want); !got.Equal(want) {
		t.Fatalf("timeOrNow(non-zero) = %v, want %v", got, want)
	}
	// Non-UTC input must be converted.
	loc, _ := time.LoadLocation("America/New_York")
	if loc != nil {
		eastern := time.Date(2024, 6, 1, 8, 0, 0, 0, loc)
		if got := timeOrNow(eastern); got.Location() != time.UTC {
			t.Errorf("timeOrNow must return UTC; got %v", got.Location())
		}
	}
}

// TestRuleIDForQuarantine_ReleaseAndApplyDistinct exists so the
// WS-5A.1 review fix that wires PublishQuarantine(Released) into
// handleQuarantineRelease does not accidentally re-use the
// .applied rule ID. The platform's correlation rules pivot on
// (rule.id, data.action) so the two events MUST land on distinct
// rule IDs (7830 vs 7831) AND distinct data.action strings
// ("applied" vs "released"). This locks both halves of that
// contract.
func TestRuleIDForQuarantine_ReleaseAndApplyDistinct(t *testing.T) {
	if got := ruleIDForQuarantine(QuarantineActionApplied); got != "7830" {
		t.Errorf("ruleIDForQuarantine(applied) = %q, want 7830", got)
	}
	if got := ruleIDForQuarantine(QuarantineActionReleased); got != "7831" {
		t.Errorf("ruleIDForQuarantine(released) = %q, want 7831", got)
	}
	if QuarantineActionApplied == QuarantineActionReleased {
		t.Fatalf("QuarantineActionApplied (%q) must differ from QuarantineActionReleased (%q)",
			QuarantineActionApplied, QuarantineActionReleased)
	}
}

// TestNilIfZero returns nil for zero, pointer otherwise.
func TestNilIfZero(t *testing.T) {
	if p := nilIfZero(time.Time{}); p != nil {
		t.Errorf("nilIfZero(zero) = %v, want nil", p)
	}
	want := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	p := nilIfZero(want)
	if p == nil || !p.Equal(want) {
		t.Errorf("nilIfZero(non-zero) = %v, want %v", p, want)
	}
}
