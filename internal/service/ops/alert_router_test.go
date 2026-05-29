package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// fakeRemediator captures Remediate() calls so tests can assert
// which alerts were dispatched.
type fakeRemediator struct {
	mu     sync.Mutex
	calls  []Alert
	failOn string // alertname for which Remediate should return an error
}

func (f *fakeRemediator) Remediate(_ context.Context, a Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, a)
	if f.failOn != "" && a.Labels["alertname"] == f.failOn {
		return errors.New("remediator: simulated failure")
	}
	return nil
}

func (f *fakeRemediator) snapshot() []Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Alert, len(f.calls))
	copy(out, f.calls)
	return out
}

// fakeEscalator captures Escalate() calls.
type fakeEscalator struct {
	mu        sync.Mutex
	incidents []struct {
		tenantID string
		incident dto.EscalationIncident
	}
	failOnCategory string
	nextTicketID   int
}

func (f *fakeEscalator) Escalate(_ context.Context, tenantID string, incident dto.EscalationIncident) (dto.EscalationTicket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.incidents = append(f.incidents, struct {
		tenantID string
		incident dto.EscalationIncident
	}{tenantID, incident})
	if f.failOnCategory != "" && incident.Category == f.failOnCategory {
		return dto.EscalationTicket{}, errors.New("escalator: simulated failure")
	}
	f.nextTicketID++
	return dto.EscalationTicket{
		TicketID:  "tk_test_" + string(rune('A'+f.nextTicketID-1)),
		TenantID:  tenantID,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Reason:    incident.Reason,
		Incident:  incident,
	}, nil
}

func (f *fakeEscalator) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.incidents)
}

func (f *fakeEscalator) snapshot() []dto.EscalationIncident {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]dto.EscalationIncident, 0, len(f.incidents))
	for _, r := range f.incidents {
		out = append(out, r.incident)
	}
	return out
}

// newTestRouter builds a router with stable test wiring: a fixed-clock
// closure, both fakes, and a small remediable-allowlist with the two
// alerts the dispatch tests exercise.
func newTestRouter(t *testing.T, remed *fakeRemediator, esc *fakeEscalator) *AlertRouter {
	t.Helper()
	r, err := NewAlertRouter(RouterConfig{
		Remediator: remed,
		Escalator:  esc,
		TenantID:   "platform-owner",
		RemediableAlerts: map[string]bool{
			"SN360ESWorkerCycleStalled": true,
		},
		Clock: func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewAlertRouter: %v", err)
	}
	return r
}

func TestNewAlertRouter_RequiresEscalator(t *testing.T) {
	if _, err := NewAlertRouter(RouterConfig{TenantID: "x"}); err == nil {
		t.Fatalf("NewAlertRouter(no Escalator) accepted; want error")
	}
}

func TestNewAlertRouter_RequiresTenantID(t *testing.T) {
	esc := &fakeEscalator{}
	if _, err := NewAlertRouter(RouterConfig{Escalator: esc}); err == nil {
		t.Fatalf("NewAlertRouter(no TenantID) accepted; want error")
	}
}

func TestClassify_ResolvedIsSkipped(t *testing.T) {
	r := newTestRouter(t, &fakeRemediator{}, &fakeEscalator{})
	d := r.Classify(Alert{
		Status: "resolved",
		Labels: map[string]string{"alertname": "SN360ESHTTP5xxRising", "severity": "critical"},
	})
	if d.Action != ActionSkip {
		t.Errorf("resolved alert action=%q; want %q", d.Action, ActionSkip)
	}
}

func TestClassify_AllowlistedAlertRemediatesWhenRemediatorPresent(t *testing.T) {
	r := newTestRouter(t, &fakeRemediator{}, &fakeEscalator{})
	d := r.Classify(Alert{
		Status: "firing",
		Labels: map[string]string{"alertname": "SN360ESWorkerCycleStalled", "severity": "critical"},
	})
	if d.Action != ActionRemediate {
		t.Errorf("allowlisted alert action=%q; want %q", d.Action, ActionRemediate)
	}
}

func TestClassify_AllowlistedAlertEscalatesWhenRemediatorNil(t *testing.T) {
	// Remediator=nil + critical -> ActionEscalate, NOT ActionRemediate
	// even though the allow-list says we'd remediate. Defense in depth.
	esc := &fakeEscalator{}
	r, err := NewAlertRouter(RouterConfig{
		Escalator: esc,
		TenantID:  "platform-owner",
		RemediableAlerts: map[string]bool{
			"SN360ESWorkerCycleStalled": true,
		},
	})
	if err != nil {
		t.Fatalf("NewAlertRouter: %v", err)
	}
	d := r.Classify(Alert{
		Status: "firing",
		Labels: map[string]string{"alertname": "SN360ESWorkerCycleStalled", "severity": "critical"},
	})
	if d.Action != ActionEscalate {
		t.Errorf("allowlisted-but-no-remediator action=%q; want %q", d.Action, ActionEscalate)
	}
}

func TestClassify_CriticalWithoutRemediatorEscalates(t *testing.T) {
	r := newTestRouter(t, &fakeRemediator{}, &fakeEscalator{})
	d := r.Classify(Alert{
		Status: "firing",
		Labels: map[string]string{"alertname": "SN360ESHTTP5xxRising", "severity": "critical"},
	})
	if d.Action != ActionEscalate {
		t.Errorf("critical no-remediator action=%q; want %q", d.Action, ActionEscalate)
	}
}

func TestClassify_WarningDefaultsToRunbook(t *testing.T) {
	r := newTestRouter(t, &fakeRemediator{}, &fakeEscalator{})
	d := r.Classify(Alert{
		Status: "firing",
		Labels: map[string]string{"alertname": "SN360ESTier1LatencyHigh", "severity": "warning"},
	})
	if d.Action != ActionRunbook {
		t.Errorf("warning action=%q; want %q", d.Action, ActionRunbook)
	}
}

func TestClassify_InfoDefaultsToRunbook(t *testing.T) {
	r := newTestRouter(t, &fakeRemediator{}, &fakeEscalator{})
	d := r.Classify(Alert{
		Status: "firing",
		Labels: map[string]string{"alertname": "SN360ESTier0BypassRateLow", "severity": "info"},
	})
	if d.Action != ActionRunbook {
		t.Errorf("info action=%q; want %q", d.Action, ActionRunbook)
	}
}

func TestServeHTTP_NonPostReturns405(t *testing.T) {
	r := newTestRouter(t, &fakeRemediator{}, &fakeEscalator{})
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s status=%d; want %d", method, w.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestServeHTTP_MalformedBodyReturns400(t *testing.T) {
	r := newTestRouter(t, &fakeRemediator{}, &fakeEscalator{})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed body status=%d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestServeHTTP_UnsupportedVersionReturns400(t *testing.T) {
	r := newTestRouter(t, &fakeRemediator{}, &fakeEscalator{})
	body, _ := json.Marshal(AlertmanagerPayload{Version: "5", Status: "firing"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("v5 payload status=%d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestServeHTTP_RemediatesAllowlistedAlert(t *testing.T) {
	remed := &fakeRemediator{}
	esc := &fakeEscalator{}
	r := newTestRouter(t, remed, esc)
	payload := AlertmanagerPayload{
		Version: "4",
		Status:  "firing",
		Alerts: []Alert{{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "SN360ESWorkerCycleStalled",
				"severity":  "critical",
				"component": "workers",
			},
			Fingerprint: "abc123",
		}},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(remed.snapshot()) != 1 {
		t.Errorf("remediator calls=%d; want 1", len(remed.snapshot()))
	}
	if esc.count() != 0 {
		t.Errorf("escalator calls=%d on remediation path; want 0", esc.count())
	}
}

func TestServeHTTP_EscalatesCriticalAlert(t *testing.T) {
	remed := &fakeRemediator{}
	esc := &fakeEscalator{}
	r := newTestRouter(t, remed, esc)
	payload := AlertmanagerPayload{
		Version: "4",
		Status:  "firing",
		Alerts: []Alert{{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "SN360ESHTTP5xxRising",
				"severity":  "critical",
				"component": "http",
			},
			Annotations: map[string]string{
				"summary":     "HTTP 5xx error rate above 1%",
				"runbook_url": "https://example.com/runbook",
			},
			StartsAt:    time.Date(2026, 1, 15, 11, 55, 0, 0, time.UTC),
			Fingerprint: "fp-http-5xx",
		}},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if esc.count() != 1 {
		t.Fatalf("escalator count=%d; want 1", esc.count())
	}
	got := esc.snapshot()[0]
	if got.Category != "SN360ESHTTP5xxRising" {
		t.Errorf("escalation Category=%q; want SN360ESHTTP5xxRising", got.Category)
	}
	if got.PseudoMessageID != "fp-http-5xx" {
		t.Errorf("escalation PseudoMessageID=%q; want fp-http-5xx", got.PseudoMessageID)
	}
	if got.Tier != "http" {
		t.Errorf("escalation Tier=%q; want http", got.Tier)
	}
	wantSummary := "HTTP 5xx error rate above 1%"
	if got.AISummary != wantSummary {
		t.Errorf("escalation AISummary=%q; want %q", got.AISummary, wantSummary)
	}
	foundRunbook := false
	for _, ind := range got.Indicators {
		if strings.HasPrefix(ind, "runbook:") {
			foundRunbook = true
		}
	}
	if !foundRunbook {
		t.Errorf("escalation Indicators=%v; want one with runbook: prefix", got.Indicators)
	}
}

func TestServeHTTP_SkipsResolvedAlerts(t *testing.T) {
	remed := &fakeRemediator{}
	esc := &fakeEscalator{}
	r := newTestRouter(t, remed, esc)
	payload := AlertmanagerPayload{
		Version: "4",
		Status:  "resolved",
		Alerts: []Alert{{
			Status: "resolved",
			Labels: map[string]string{
				"alertname": "SN360ESHTTP5xxRising",
				"severity":  "critical",
			},
		}},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if len(remed.snapshot()) != 0 || esc.count() != 0 {
		t.Errorf("resolved alert produced side effects: remediator=%d escalator=%d",
			len(remed.snapshot()), esc.count())
	}
}

func TestServeHTTP_FailedRemediationStillReturns200(t *testing.T) {
	// Alertmanager retries on non-200, which would multiply the
	// remediation failure. The router swallows side-effect errors and
	// surfaces them via logs + metrics, returning 200 so Alertmanager
	// does not retry. For a CRITICAL-severity alert, the router must
	// also fall back to escalation so the incident does not silently
	// vanish — see the defense-in-depth comment in
	// alert_router.go's dispatch() ActionRemediate branch.
	remed := &fakeRemediator{failOn: "SN360ESWorkerCycleStalled"}
	esc := &fakeEscalator{}
	r := newTestRouter(t, remed, esc)
	payload := AlertmanagerPayload{
		Version: "4",
		Alerts: []Alert{{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "SN360ESWorkerCycleStalled",
				"severity":  "critical",
				"component": "workers",
			},
			Annotations: map[string]string{
				"summary":     "Worker stalled",
				"runbook_url": "https://example.com/runbook",
			},
			Fingerprint: "fp-failed-remed-critical",
		}},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d (router must absorb side-effect errors)", w.Code)
	}
	// Remediator was invoked AND failed.
	if got := remed.snapshot(); len(got) != 1 {
		t.Fatalf("remediator calls=%d; want 1", len(got))
	}
	// Critical-severity fallback: the failure must produce an
	// escalation ticket annotated with the remediation-failure
	// context so the human operator sees the autonomous attempt
	// already happened.
	got := esc.snapshot()
	if len(got) != 1 {
		t.Fatalf("escalator calls=%d; want 1 (critical-severity remediation-failure fallback)", len(got))
	}
	if !strings.Contains(got[0].AISummary, "remediation_failed:") {
		t.Errorf("incident.AISummary=%q; want remediation_failed prefix", got[0].AISummary)
	}
	var sawRemedErrIndicator bool
	for _, ind := range got[0].Indicators {
		if strings.HasPrefix(ind, "remediation_error:") {
			sawRemedErrIndicator = true
			break
		}
	}
	if !sawRemedErrIndicator {
		t.Errorf("incident.Indicators=%v; want a remediation_error: entry", got[0].Indicators)
	}
}

// TestServeHTTP_FailedRemediationOnWarningDoesNotEscalate locks in
// the asymmetry between critical and warning severities for failed
// remediation. Warnings stay logged-only; escalating them would page
// humans for transient remediator hiccups, defeating the autonomic
// point of the remediator allow-list.
func TestServeHTTP_FailedRemediationOnWarningDoesNotEscalate(t *testing.T) {
	remed := &fakeRemediator{failOn: "SN360ESWorkerCycleStalled"}
	esc := &fakeEscalator{}
	r := newTestRouter(t, remed, esc)
	payload := AlertmanagerPayload{
		Version: "4",
		Alerts: []Alert{{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "SN360ESWorkerCycleStalled",
				"severity":  "warning",
				"component": "workers",
			},
		}},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if got := remed.snapshot(); len(got) != 1 {
		t.Fatalf("remediator calls=%d; want 1", len(got))
	}
	if got := esc.count(); got != 0 {
		t.Errorf("escalator calls=%d; want 0 (warning-severity failures stay logged)", got)
	}
}

func TestBuildIncidentFromAlert_StartsAtPreserved(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	start := time.Date(2026, 1, 15, 11, 55, 0, 0, time.UTC)
	got := buildIncidentFromAlert(Alert{
		Labels:      map[string]string{"alertname": "X", "component": "tier1"},
		Annotations: map[string]string{"summary": "s", "runbook_url": "u"},
		StartsAt:    start,
		Fingerprint: "fp",
	}, now)
	if !got.DetectedAt.Equal(start) {
		t.Errorf("DetectedAt=%v; want %v", got.DetectedAt, start)
	}
	if got.PseudoMessageID != "fp" {
		t.Errorf("PseudoMessageID=%q; want fp", got.PseudoMessageID)
	}
	if got.Category != "X" || got.Tier != "tier1" || got.AISummary != "s" {
		t.Errorf("incident=%+v", got)
	}
	if len(got.Indicators) == 0 {
		t.Errorf("Indicators empty; want runbook URL captured")
	}
}

func TestBuildIncidentFromAlert_NowFallbackWhenStartsAtZero(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	got := buildIncidentFromAlert(Alert{}, now)
	if !got.DetectedAt.Equal(now) {
		t.Errorf("DetectedAt=%v with zero StartsAt; want fallback to now=%v", got.DetectedAt, now)
	}
}

// TestServeHTTP_ResponseShape pins the response payload so a future
// refactor that drops the `decisions` field on accident is caught.
// The user-facing audit story relies on this body being inspectable.
func TestServeHTTP_ResponseShape(t *testing.T) {
	remed := &fakeRemediator{}
	esc := &fakeEscalator{}
	r := newTestRouter(t, remed, esc)
	payload := AlertmanagerPayload{
		Version: "4",
		Alerts: []Alert{{
			Status: "firing",
			Labels: map[string]string{"alertname": "X", "severity": "info"},
		}},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	respBytes, _ := io.ReadAll(w.Body)
	var resp struct {
		Received  int        `json:"received"`
		Decisions []Decision `json:"decisions"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, respBytes)
	}
	if resp.Received != 1 {
		t.Errorf("Received=%d; want 1", resp.Received)
	}
	if len(resp.Decisions) != 1 {
		t.Fatalf("Decisions len=%d; want 1", len(resp.Decisions))
	}
	if resp.Decisions[0].Action != ActionRunbook {
		t.Errorf("Decision.Action=%q; want %q", resp.Decisions[0].Action, ActionRunbook)
	}
}
