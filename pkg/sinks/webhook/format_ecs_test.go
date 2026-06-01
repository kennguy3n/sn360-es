package webhook

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// TestFormatECS_BlockedVerdict_GoldenShape pins the wire shape of
// an ECS-formatted blocked verdict so a future refactor can't
// silently break the schema that downstream Splunk HEC / Elastic
// ingest pipelines depend on.
//
// The test re-parses the JSON before comparing fields so a
// whitespace / key-ordering refactor in formatECS doesn't fail
// the assertion.
func TestFormatECS_BlockedVerdict_GoldenShape(t *testing.T) {
	t.Parallel()
	occ := time.Date(2026, 5, 1, 12, 34, 56, 789_000_000, time.UTC)
	ev := &Event{
		EventID:          "evt-1",
		OccurredAt:       occ,
		TenantID:         "tenant-A",
		MessageID:        "msg-1",
		CorrelationID:    "corr-1",
		Score:            87,
		Tier:             constant.TierBlocked,
		Primary:          constant.CategoryLikelyPhishing,
		Secondary:        []constant.Category{constant.CategoryCredentialHarvesting},
		ReasonCodes:      []string{"phish_pattern", "lookalike_domain"},
		SenderHashHex:    "deadbeef",
		RecipientHashHex: "cafebabe",
	}
	body, err := formatECS(ev)
	if err != nil {
		t.Fatalf("formatECS: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\nbody=%s", err, body)
	}
	if got := doc["@timestamp"]; got != "2026-05-01T12:34:56.789Z" {
		t.Errorf("@timestamp = %v; want 2026-05-01T12:34:56.789Z", got)
	}
	ecsBlock, _ := doc["ecs"].(map[string]any)
	if ecsBlock["version"] != ecsDocVersion {
		t.Errorf("ecs.version = %v; want %s", ecsBlock["version"], ecsDocVersion)
	}
	org, _ := doc["organization"].(map[string]any)
	if org["id"] != "tenant-A" {
		t.Errorf("organization.id = %v; want tenant-A", org["id"])
	}
	event, _ := doc["event"].(map[string]any)
	if event["kind"] != "alert" {
		t.Errorf("event.kind = %v; want alert", event["kind"])
	}
	cats, _ := event["category"].([]any)
	if len(cats) != 1 || cats[0] != "email" {
		t.Errorf("event.category = %v; want [email]", cats)
	}
	types, _ := event["type"].([]any)
	if len(types) != 1 || types[0] != "denied" {
		t.Errorf("event.type = %v; want [denied]", types)
	}
	if event["dataset"] == nil {
		t.Errorf("event.dataset must be set; got nil")
	}
	emailBlock, _ := doc["email"].(map[string]any)
	if emailBlock == nil {
		t.Fatalf("email block missing; doc=%v", doc)
	}
	from, _ := emailBlock["from"].(map[string]any)
	if got, _ := from["address"].([]any); len(got) != 1 || got[0] != "deadbeef@pseudo.sn360" {
		t.Errorf("email.from.address = %v; want [deadbeef@pseudo.sn360]", got)
	}
	to, _ := emailBlock["to"].(map[string]any)
	if got, _ := to["address"].([]any); len(got) != 1 || got[0] != "cafebabe@pseudo.sn360" {
		t.Errorf("email.to.address = %v; want [cafebabe@pseudo.sn360]", got)
	}
	sn360Block, _ := doc["sn360"].(map[string]any)
	if sn360Block == nil {
		t.Fatalf("sn360 vendor block missing; doc=%v", doc)
	}
	if sn360Block["tier"] != "Blocked" {
		t.Errorf("sn360.tier = %v; want Blocked", sn360Block["tier"])
	}
	if sn360Block["primary"] != "LIKELY_PHISHING" {
		t.Errorf("sn360.primary = %v; want LIKELY_PHISHING", sn360Block["primary"])
	}
	if got, ok := sn360Block["score"].(float64); !ok || got != 87 {
		t.Errorf("sn360.score = %v (%T); want 87", sn360Block["score"], sn360Block["score"])
	}
	if sn360Block["verdict"] != "malicious" {
		t.Errorf("sn360.verdict = %v; want malicious", sn360Block["verdict"])
	}
	reasons, _ := sn360Block["reason_codes"].([]any)
	if len(reasons) != 2 || reasons[0] != "phish_pattern" || reasons[1] != "lookalike_domain" {
		t.Errorf("sn360.reason_codes = %v; want [phish_pattern lookalike_domain]", reasons)
	}
}

// TestFormatECS_TrustedVerdict_TypeIsInfo cross-checks the
// type-mapping branch the ECS spec separates from "denied".
// Trusted verdicts must surface as `event.type=info` so a SIEM
// rule keyed on `event.type=denied` doesn't spuriously alert on
// benign mail.
func TestFormatECS_TrustedVerdict_TypeIsInfo(t *testing.T) {
	t.Parallel()
	ev := &Event{
		EventID:    "evt-trust",
		OccurredAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		TenantID:   "tenant-A",
		MessageID:  "msg-trust",
		Tier:       constant.TierTrusted,
		Primary:    constant.CategoryInternalTrusted,
	}
	body, err := formatECS(ev)
	if err != nil {
		t.Fatalf("formatECS: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("json: %v", err)
	}
	event, _ := doc["event"].(map[string]any)
	types, _ := event["type"].([]any)
	if len(types) != 1 || types[0] != "info" {
		t.Errorf("event.type for Trusted = %v; want [info]", types)
	}
}

// TestFormatECS_RejectsInvalid checks the formatter declines an
// event that fails Validate() — the dispatcher relies on this
// to prevent malformed payloads from being signed and POSTed.
func TestFormatECS_RejectsInvalid(t *testing.T) {
	t.Parallel()
	if _, err := formatECS(&Event{}); err == nil {
		t.Fatalf("formatECS accepted an empty event; expected validation error")
	}
}

// TestFormatECS_Deterministic ensures the same input produces the
// same bytes — required for the deduplication semantics of the
// DLQ consumer (sha256(body) feeds the dedup_id).
func TestFormatECS_Deterministic(t *testing.T) {
	t.Parallel()
	ev := &Event{
		EventID:       "evt-1",
		OccurredAt:    time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		TenantID:      "tenant-A",
		MessageID:     "msg-1",
		Tier:          constant.TierWarning,
		Primary:       constant.CategoryNewsletter,
		ReasonCodes:   []string{"a", "b"},
		SenderHashHex: "deadbeef",
	}
	for i := 0; i < 10; i++ {
		a, err := formatECS(ev)
		if err != nil {
			t.Fatalf("formatECS: %v", err)
		}
		b, err := formatECS(ev)
		if err != nil {
			t.Fatalf("formatECS: %v", err)
		}
		if string(a) != string(b) {
			t.Fatalf("formatECS is non-deterministic on iter %d:\n%s\nvs\n%s", i, a, b)
		}
	}
}
