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
		// Phishing family -- the default bucket.
		{"likely phishing", constant.CategoryLikelyPhishing, KindPhishing},
		{"credential harvesting", constant.CategoryCredentialHarvesting, KindPhishing},
		{"lookalike domain", constant.CategoryLookalikeDomain, KindPhishing},
		{"suspicious URL", constant.CategorySuspiciousURL, KindPhishing},
		{"QR phishing", constant.CategoryQRPhishing, KindPhishing},
		{"scam/fraud", constant.CategoryScamFraud, KindPhishing},
		{"auth failed", constant.CategoryAuthFailed, KindPhishing},

		// BEC family -- fan into the bec subject.
		{"BEC impersonation", constant.CategoryBECImpersonation, KindBEC},
		{"account takeover", constant.CategoryAccountTakeoverSuspected, KindBEC},
		{"vendor compromise", constant.CategoryVendorCompromise, KindBEC},
		{"invoice fraud", constant.CategoryInvoiceFraud, KindBEC},

		// Malware family -- attachment-bearing categories.
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

// TestRuleLevelForTier locks the tier->Wazuh-level mapping. Blocked
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
//   - same (tenant, email) -> same hash (correlation works)
//   - different tenants -> different hashes (cross-tenant isolation)
//   - case + whitespace are normalised (User@Example.com == user@example.com)
//   - empty inputs -> empty output (no accidental fingerprint of "")
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
// URL list -- at boot time we degrade to the no-op publisher and let
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

// engineEvent is a minimal local copy of the correlation-engine
// Event struct (services/correlation-engine/internal/engine/engine.go).
// Kept in sync ONLY for the WS-5A.1 bridge interop tests so the
// hybrid envelope contract stays grep-able from the bridge side.
// If the engine struct grows a new required field, the
// corresponding envelope key has to be added AND populated by
// enrichForEngine.
type engineEvent struct {
	TenantID   string         `json:"tenant_id"`
	Subject    string         `json:"subject"`
	EventID    string         `json:"event_id"`
	EventClass string         `json:"event_class"`
	Severity   string         `json:"severity"`
	Timestamp  time.Time      `json:"timestamp,omitempty"`
	Fields     map[string]any `json:"fields,omitempty"`
}

// wazuhProbe is the alert-forwarder ParseAlert decoder
// (services/alert-forwarder/internal/indexer.ParseAlert). The
// bridge MUST keep producing JSON that satisfies BOTH shapes --
// this probe stays grouped with the engineEvent probe to make the
// dual-consumer contract explicit at the test level.
type wazuhProbe struct {
	Timestamp string `json:"@timestamp"`
	ClusterID string `json:"cluster_id"`
	Rule      struct {
		ID    string `json:"id"`
		Level int    `json:"level"`
	} `json:"rule"`
	Agent struct {
		Labels struct {
			SN360 struct {
				TenantID string `json:"tenant_id"`
			} `json:"sn360"`
		} `json:"labels"`
	} `json:"agent"`
	Data json.RawMessage `json:"data"`
}

// TestEnvelope_DeserialisesIntoBothConsumerShapes is the
// load-bearing invariant for WS-5A.2: the same envelope bytes
// must unmarshal cleanly into BOTH the alert-forwarder Wazuh
// probe AND the correlation-engine Event struct. Without that,
// the engine's joinValueFor returns "" for every event and every
// multi-source rule either fires on the empty join or collapses
// unrelated events into one pending bucket.
func TestEnvelope_DeserialisesIntoBothConsumerShapes(t *testing.T) {
	cfg := Config{Source: "sn360-es", ClusterID: "prod-1"}
	payload := EvaluationPayload{
		Source:        "sn360-es",
		EventType:     "email.verdict.phishing",
		Action:        "verdict",
		MessageID:     "msg-123",
		CorrelationID: "corr-abc",
		Tier:          string(constant.TierBlocked),
		Primary:       string(constant.CategoryLikelyPhishing),
		Score:         95,
		RecipientHash: "sha256:rcpt",
		SenderHash:    "sha256:sndr",
		ReasonCodes:   []string{"R_PHISH_KEYWORDS", "R_LOOKALIKE"},
		EvaluatedAt:   time.Now().UTC(),
	}
	env := buildEnvelope(cfg, "tid-1", "7800", 12, "sn360-es: phishing (Blocked)", payload)
	env.enrichForEngine(
		"tid-1",
		"sn360.events.email.tid-1.phishing",
		"evt-1",
		"email.verdict.phishing",
		severityForTier(constant.TierBlocked),
		engineFieldsForVerdict(payload),
	)

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	// Alert-forwarder probe: must still see @timestamp, agent,
	// rule, data -- byte-for-byte compatibility with the
	// pre-hybrid wire is the whole point of keeping both shapes
	// in one struct.
	var wp wazuhProbe
	if err := json.Unmarshal(data, &wp); err != nil {
		t.Fatalf("wazuh probe unmarshal: %v", err)
	}
	if wp.Timestamp == "" {
		t.Error("wazuh probe: @timestamp empty (alert-forwarder will reject)")
	}
	if wp.Agent.Labels.SN360.TenantID != "tid-1" {
		t.Errorf("wazuh probe: agent.labels.sn360.tenant_id = %q, want tid-1", wp.Agent.Labels.SN360.TenantID)
	}
	if wp.Rule.ID != "7800" || wp.Rule.Level != 12 {
		t.Errorf("wazuh probe: rule = %+v", wp.Rule)
	}
	if len(wp.Data) == 0 || string(wp.Data) == "null" {
		t.Errorf("wazuh probe: data missing")
	}

	// Engine probe: must surface tenant_id, event_id, event_class,
	// severity, fields so correlation-engine join_keys resolve.
	var ee engineEvent
	if err := json.Unmarshal(data, &ee); err != nil {
		t.Fatalf("engine event unmarshal: %v", err)
	}
	if ee.TenantID != "tid-1" {
		t.Errorf("engine: tenant_id = %q, want tid-1", ee.TenantID)
	}
	if ee.Subject != "sn360.events.email.tid-1.phishing" {
		t.Errorf("engine: subject = %q", ee.Subject)
	}
	if ee.EventID != "evt-1" {
		t.Errorf("engine: event_id = %q, want evt-1", ee.EventID)
	}
	if ee.EventClass != "email.verdict.phishing" {
		t.Errorf("engine: event_class = %q", ee.EventClass)
	}
	if ee.Severity != "critical" {
		t.Errorf("engine: severity = %q, want critical (Blocked->critical)", ee.Severity)
	}
	if ee.Timestamp.IsZero() {
		t.Error("engine: timestamp empty")
	}
	for _, k := range []string{"recipient_hash", "sender_hash", "message_id", "correlation_id", "tier", "primary", "score", "reason_codes"} {
		if _, ok := ee.Fields[k]; !ok {
			t.Errorf("engine: fields[%q] missing -- multi-source rules joining on this key will not match", k)
		}
	}
	if got, _ := ee.Fields["recipient_hash"].(string); got != "sha256:rcpt" {
		t.Errorf("engine: fields.recipient_hash = %q", got)
	}
}

// TestEnrichForEngine_DropsEmptyAndNilFields keeps the wire
// compact AND prevents a rule joining on e.g. sender_hash from
// matching every event where the value is the empty string --
// the engine's joinValueFor concatenates "string|empty|string"
// and would merge unrelated events into one pending bucket.
func TestEnrichForEngine_DropsEmptyAndNilFields(t *testing.T) {
	env := Envelope{Timestamp: time.Now().UTC()}
	env.enrichForEngine("t", "s", "e", "c", "high", map[string]any{
		"keep_str": "value",
		"keep_int": 42,
		"drop_str": "",
		"drop_nil": nil,
	})
	if _, ok := env.Fields["drop_str"]; ok {
		t.Error("empty string field must be dropped")
	}
	if _, ok := env.Fields["drop_nil"]; ok {
		t.Error("nil field must be dropped")
	}
	if env.Fields["keep_str"] != "value" || env.Fields["keep_int"] != 42 {
		t.Errorf("non-empty fields must survive: got %+v", env.Fields)
	}
}

// TestEnrichForEngine_EngineTimestampMirrorsWazuhTimestamp pins
// the two timestamp fields so a future refactor cannot drift
// them. The engine matches its time window against ev.Timestamp
// (lower-case) while alert-forwarder reads @timestamp -- they
// MUST be the same instant.
func TestEnrichForEngine_EngineTimestampMirrorsWazuhTimestamp(t *testing.T) {
	want := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	env := Envelope{Timestamp: want}
	env.enrichForEngine("t", "s", "e", "c", "high", nil)
	if !env.EngineTimestamp.Equal(want) {
		t.Errorf("EngineTimestamp = %v, want %v (must mirror @timestamp)", env.EngineTimestamp, want)
	}
}

// TestSeverityForTier_MatchesEngineValidatorVocabulary locks the
// mapping into the engine validator's allowed set
// (info|low|medium|high|critical -- see dac.validSeverities).
// A drift here would make every bridge event fail the engine's
// per-event severity weighting.
func TestSeverityForTier_MatchesEngineValidatorVocabulary(t *testing.T) {
	validEngineSeverities := map[string]bool{
		"info": true, "low": true, "medium": true, "high": true, "critical": true,
	}
	cases := []struct {
		tier constant.Tier
		want string
	}{
		{constant.TierBlocked, "critical"},
		{constant.TierHighRisk, "high"},
		{constant.TierWarning, "medium"},
		{constant.TierTrusted, "medium"},
	}
	for _, tc := range cases {
		got := severityForTier(tc.tier)
		if got != tc.want {
			t.Errorf("severityForTier(%s) = %q, want %q", tc.tier, got, tc.want)
		}
		if !validEngineSeverities[got] {
			t.Errorf("severityForTier(%s) = %q, NOT in engine validator vocabulary", tc.tier, got)
		}
	}
}

// TestSeverityForLevel_MapsWazuhLevelsToEngineSeverity locks the
// reverse mapping used for escalation events (where evt.Tier is
// not present and the bridge falls back to rule.level).
func TestSeverityForLevel_MapsWazuhLevelsToEngineSeverity(t *testing.T) {
	cases := []struct {
		level int
		want  string
	}{
		{15, "critical"}, {12, "critical"},
		{10, "high"}, {8, "high"},
		{7, "medium"}, {3, "medium"},
		{2, "low"}, {1, "low"},
		{0, "info"},
	}
	for _, tc := range cases {
		if got := severityForLevel(tc.level); got != tc.want {
			t.Errorf("severityForLevel(%d) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

// TestEngineFieldsForVerdict_ExposesAllJoinCandidates locks the
// keys present in the engine fields map for verdict events. A
// correlation rule joining on a key not listed here would
// silently produce an empty join value and either miss the
// intended match or merge events from unrelated tenants. Adding
// a new rule that joins on a different verdict field MUST extend
// engineFieldsForVerdict at the same time.
func TestEngineFieldsForVerdict_ExposesAllJoinCandidates(t *testing.T) {
	linkScore := 60
	attachScore := 80
	p := EvaluationPayload{
		Source: "sn360-es", EventType: "email.verdict.phishing", Action: "verdict",
		MessageID: "mid", CorrelationID: "cid",
		Tier: string(constant.TierBlocked), Primary: string(constant.CategoryLikelyPhishing),
		Score: 90, LinkScore: &linkScore, AttachmentScore: &attachScore,
		RecipientHash: "r", SenderHash: "s",
		ReasonCodes: []string{"R1"}, Secondary: []string{"X"},
	}
	f := engineFieldsForVerdict(p)
	required := []string{
		"message_id", "correlation_id", "tier", "primary", "score",
		"action", "event_type", "recipient_hash", "sender_hash", "source",
		"link_score", "attachment_score", "reason_codes", "secondary",
	}
	for _, k := range required {
		if _, ok := f[k]; !ok {
			t.Errorf("engineFieldsForVerdict missing key %q", k)
		}
	}
}

// TestEngineFieldsForQuarantine_ExposesAllJoinCandidates locks
// the keys for quarantine events.
func TestEngineFieldsForQuarantine_ExposesAllJoinCandidates(t *testing.T) {
	p := QuarantinePayload{
		Source: "sn360-es", EventType: "email.quarantine.applied", Action: QuarantineActionApplied,
		MessageID: "mid", CorrelationID: "cid",
		Tier: string(constant.TierBlocked), Primary: string(constant.CategoryLikelyPhishing),
		Score: 90, RecipientHash: "r", RequestedBy: "admin", At: time.Now().UTC(),
	}
	f := engineFieldsForQuarantine(p)
	for _, k := range []string{"message_id", "correlation_id", "tier", "primary", "score", "action", "event_type", "recipient_hash", "requested_by", "source"} {
		if _, ok := f[k]; !ok {
			t.Errorf("engineFieldsForQuarantine missing key %q", k)
		}
	}
}

// TestEngineFieldsForEscalation_ExposesAllJoinCandidates locks
// the keys for escalation events.
func TestEngineFieldsForEscalation_ExposesAllJoinCandidates(t *testing.T) {
	p := EscalationPayload{
		Source: "sn360-es", EventType: "email.escalation.created", Action: EscalationActionCreated,
		TicketID: "T-1", MessageID: "mid", Tier: "Tier0", Category: "phishing",
		Score: 90, Reason: "high-risk", AffectedUsers: 3, Indicators: []string{"i-1"},
	}
	f := engineFieldsForEscalation(p)
	for _, k := range []string{"ticket_id", "message_id", "tier", "category", "score", "action", "event_type", "reason", "affected_users", "indicators", "source"} {
		if _, ok := f[k]; !ok {
			t.Errorf("engineFieldsForEscalation missing key %q", k)
		}
	}
}

// TestPublishEvaluation_HybridWire_FullStackUnmarshal verifies
// the full end-to-end path: PublishEvaluation -> publish -> the
// outgoing wire bytes -> both Wazuh probe AND engine Event
// shapes. Catches a regression where a future refactor only
// wires enrichForEngine on the verdict path but not on
// quarantine / escalation.
func TestPublishAllPaths_HybridWire(t *testing.T) {
	cases := []struct {
		name        string
		payload     any
		enrichWith  func(env *Envelope)
		wantSubject string
		wantClass   string
		wantSev     string
	}{
		{
			name:    "verdict",
			payload: EvaluationPayload{Source: "sn360-es", MessageID: "m", RecipientHash: "r", Tier: string(constant.TierBlocked)},
			enrichWith: func(env *Envelope) {
				p := EvaluationPayload{Source: "sn360-es", MessageID: "m", RecipientHash: "r", Tier: string(constant.TierBlocked)}
				env.enrichForEngine("tid", "sn360.events.email.tid.phishing", "evt", "email.verdict.phishing", severityForTier(constant.TierBlocked), engineFieldsForVerdict(p))
			},
			wantSubject: "sn360.events.email.tid.phishing",
			wantClass:   "email.verdict.phishing",
			wantSev:     "critical",
		},
		{
			name:    "quarantine",
			payload: QuarantinePayload{Source: "sn360-es", MessageID: "m", RecipientHash: "r", Action: QuarantineActionApplied, Tier: string(constant.TierHighRisk)},
			enrichWith: func(env *Envelope) {
				p := QuarantinePayload{Source: "sn360-es", MessageID: "m", RecipientHash: "r", Action: QuarantineActionApplied, Tier: string(constant.TierHighRisk)}
				env.enrichForEngine("tid", "sn360.events.email.tid.quarantine", "evt", "email.quarantine.applied", severityForTier(constant.TierHighRisk), engineFieldsForQuarantine(p))
			},
			wantSubject: "sn360.events.email.tid.quarantine",
			wantClass:   "email.quarantine.applied",
			wantSev:     "high",
		},
		{
			name:    "escalation",
			payload: EscalationPayload{Source: "sn360-es", TicketID: "T", MessageID: "m", Action: EscalationActionCreated},
			enrichWith: func(env *Envelope) {
				p := EscalationPayload{Source: "sn360-es", TicketID: "T", MessageID: "m", Action: EscalationActionCreated}
				env.enrichForEngine("tid", "sn360.events.email.tid.escalation", "evt", "email.escalation.created", severityForLevel(12), engineFieldsForEscalation(p))
			},
			wantSubject: "sn360.events.email.tid.escalation",
			wantClass:   "email.escalation.created",
			wantSev:     "critical",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := buildEnvelope(Config{Source: "sn360-es"}, "tid", "7800", 12, "", tc.payload)
			tc.enrichWith(&env)
			data, err := json.Marshal(env)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var wp wazuhProbe
			if err := json.Unmarshal(data, &wp); err != nil {
				t.Fatalf("wazuh probe: %v", err)
			}
			var ee engineEvent
			if err := json.Unmarshal(data, &ee); err != nil {
				t.Fatalf("engine event: %v", err)
			}
			if wp.Agent.Labels.SN360.TenantID != "tid" {
				t.Errorf("wazuh tenant_id = %q", wp.Agent.Labels.SN360.TenantID)
			}
			if ee.Subject != tc.wantSubject {
				t.Errorf("engine subject = %q, want %q", ee.Subject, tc.wantSubject)
			}
			if ee.EventClass != tc.wantClass {
				t.Errorf("engine event_class = %q, want %q", ee.EventClass, tc.wantClass)
			}
			if ee.Severity != tc.wantSev {
				t.Errorf("engine severity = %q, want %q", ee.Severity, tc.wantSev)
			}
		})
	}
}

// TestPublishQuarantineRelease_SeverityMatchesWazuhLevel pins the
// fix for the engine/SIEM severity mismatch on quarantine-release
// events. The release call site in consumers_action.go publishes
// with Tier="" (the action is admin-initiated and not derived from
// an ML verdict), and PublishQuarantine overrides the Wazuh
// rule.level from 0 to 10 in that case. Before this fix the engine
// severity went through severityForTier("") -> "medium" while the
// Wazuh wire carried level 10 (severityForLevel -> "high") -- two
// consumers seeing two different severities for the same event.
// The fix routes engine severity through severityForLevel(level)
// using the SAME post-override level, so both views agree.
func TestPublishQuarantineRelease_SeverityMatchesWazuhLevel(t *testing.T) {
	p := QuarantinePayload{
		Source:        "sn360-es",
		EventType:     "email.quarantine.released",
		Action:        QuarantineActionReleased,
		MessageID:     "mid",
		RecipientHash: "r",
		RequestedBy:   "admin",
		// Tier intentionally left empty -- the release call site
		// in consumers_action.go does not populate it.
	}
	env := buildEnvelope(Config{Source: "sn360-es"}, "tid", ruleIDForQuarantine(QuarantineActionReleased), 10, "sn360-es: quarantine released", p)
	// Mirror PublishQuarantine's level override + severity wiring.
	level := 10
	env.enrichForEngine("tid", "sn360.events.email.tid.quarantine", "evt", "email.quarantine.released", severityForLevel(level), engineFieldsForQuarantine(p))

	if env.Rule.Level != 10 {
		t.Fatalf("wazuh rule.level = %d, want 10 (precondition)", env.Rule.Level)
	}
	if env.Severity != "high" {
		t.Errorf("engine severity = %q, want \"high\" (must match Wazuh level 10)", env.Severity)
	}
	if severityForLevel(env.Rule.Level) != env.Severity {
		t.Errorf("severityForLevel(rule.level)=%q != engine severity=%q -- consumers will disagree on severity",
			severityForLevel(env.Rule.Level), env.Severity)
	}
}
