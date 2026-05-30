package handler

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestDocsHandler_SpecLoads(t *testing.T) {
	h, err := NewDocsHandler()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(h.Spec()), "openapi: 3.1.0") {
		t.Fatal("expected OpenAPI 3.1 spec")
	}
}

func TestDocsHandler_ServeSwaggerUI(t *testing.T) {
	h, _ := NewDocsHandler()
	rec := httptest.NewRecorder()
	h.ServeSwaggerUI(rec, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type=%s", ct)
	}
	if !strings.Contains(rec.Body.String(), "swagger-ui") {
		t.Fatal("expected swagger-ui markup")
	}
	if !strings.Contains(rec.Body.String(), "/openapi.yaml") {
		t.Fatal("expected reference to openapi.yaml")
	}
}

func TestDocsHandler_ServeOpenAPI(t *testing.T) {
	h, _ := NewDocsHandler()
	rec := httptest.NewRecorder()
	h.ServeOpenAPI(rec, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Fatalf("content-type=%s", ct)
	}
	if !strings.Contains(rec.Body.String(), "/v1/banner/action") {
		t.Fatal("expected banner action path in spec")
	}
}

func TestDocsHandler_MethodNotAllowed(t *testing.T) {
	h, _ := NewDocsHandler()
	rec := httptest.NewRecorder()
	h.ServeOpenAPI(rec, httptest.NewRequest(http.MethodPost, "/openapi.yaml", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}

// TestOpenAPI_EscalationTicketReasonEnumMatchesDTO pins the
// invariant that the EscalationTicket.reason enum in the OpenAPI
// spec MUST contain exactly the set of EscalationReason values the
// Go dto.EscalationReason.Valid() method accepts. A drift here
// (e.g. adding a new EscalationReason* constant in internal/dto
// without updating the OpenAPI enum) produces clients that reject
// valid server responses as schema-invalid — the exact bug Devin
// Review caught for `ops_alert` in round 15. This test fails fast
// on the next drift instead of waiting for review-time discovery.
func TestOpenAPI_EscalationTicketReasonEnumMatchesDTO(t *testing.T) {
	h, err := NewDocsHandler()
	if err != nil {
		t.Fatal(err)
	}
	spec := string(h.Spec())

	// Find the EscalationTicket.reason enum line. The schema is a
	// flat list at the same indentation as the rest of the spec;
	// matching `enum: [...]` on the same logical block as `reason:`
	// is the simplest robust extraction without pulling a full YAML
	// parser into the test binary.
	re := regexp.MustCompile(`(?s)EscalationTicket:.*?reason:\s*\n\s*type:\s*string\s*\n\s*enum:\s*\[([^\]]+)\]`)
	m := re.FindStringSubmatch(spec)
	if m == nil {
		t.Fatalf("could not locate EscalationTicket.reason enum in OpenAPI spec")
	}
	specEnum := make([]string, 0, 8)
	for _, raw := range strings.Split(m[1], ",") {
		v := strings.TrimSpace(raw)
		if v != "" {
			specEnum = append(specEnum, v)
		}
	}
	sort.Strings(specEnum)

	// Canonical set from the dto package — every EscalationReason
	// the Go side considers Valid().
	dtoEnum := []string{
		string(dto.EscalationReasonConfirmedBreach),
		string(dto.EscalationReasonAccountCompromise),
		string(dto.EscalationReasonZeroDayAttachment),
		string(dto.EscalationReasonLowConfidence),
		string(dto.EscalationReasonUserRequested),
		string(dto.EscalationReasonOpsAlert),
	}
	sort.Strings(dtoEnum)

	if strings.Join(specEnum, ",") != strings.Join(dtoEnum, ",") {
		t.Fatalf("EscalationTicket.reason enum drift between OpenAPI spec and internal/dto:\n  spec: %v\n  dto:  %v", specEnum, dtoEnum)
	}
}

// TestOpenAPI_EscalationResolveReturnsTicketSchema pins the
// invariant that the POST /v1/escalation/resolve 200 response
// schema references EscalationTicket (not the legacy
// EscalationResolveResponse wrapper). The handler at
// internal/handler/escalation.go:154 calls
// `writeJSON(w, http.StatusOK, ticket)` with a full
// dto.EscalationTicket value (timeline, outcome, resolved_at,
// resolver_hash, resolution_notes, ...). If the OpenAPI 200
// response points at EscalationResolveResponse (only {status,
// ticket_id}), clients doing schema-driven codegen end up with
// stub types that throw away every field beyond status/ticket_id
// — the exact mismatch Devin Review caught in round 16. This
// test pins the spec-side $ref so any future drift fails locally.
func TestOpenAPI_EscalationResolveReturnsTicketSchema(t *testing.T) {
	h, err := NewDocsHandler()
	if err != nil {
		t.Fatal(err)
	}
	spec := string(h.Spec())

	// Locate the POST /v1/escalation/resolve 200-response block.
	// The regex scopes to the resolve path's responses by anchoring
	// on the unique-in-the-spec literal `/v1/escalation/resolve:`
	// then walking forward to the first `"200":` block. The (?s)
	// flag lets `.` match newlines so the lazy capture spans the
	// intervening request body + parameters sections.
	re := regexp.MustCompile(`(?s)/v1/escalation/resolve:.*?responses:\s*\n\s*"200":.*?\$ref:\s*"#/components/schemas/([A-Za-z0-9_]+)"`)
	m := re.FindStringSubmatch(spec)
	if m == nil {
		t.Fatalf("could not locate POST /v1/escalation/resolve 200 response schema in OpenAPI spec")
	}
	const want = "EscalationTicket"
	if m[1] != want {
		t.Fatalf("POST /v1/escalation/resolve 200 response schema = %q, want %q.\n"+
			"The handler returns a full dto.EscalationTicket; the spec MUST advertise the same shape so generated clients can deserialise every field.",
			m[1], want)
	}
}
