package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

type stubEscalationPublisher struct{}

func (stubEscalationPublisher) Publish(_ context.Context, _ string, _ []byte, _ ...events.PublishOption) error {
	return nil
}

func newTestEscalationService(t *testing.T) *agent.EscalationService {
	t.Helper()
	svc, err := agent.NewEscalationService(agent.EscalationServiceConfig{
		Publisher: stubEscalationPublisher{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:     func() time.Time { return time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("escalation svc: %v", err)
	}
	return svc
}

// seedTicket creates a real ticket via Escalate so the test can later
// resolve / load it without poking at internal store state.
func seedTicket(t *testing.T, svc *agent.EscalationService) dto.EscalationTicket {
	t.Helper()
	tk, err := svc.Escalate(context.Background(), "acme", dto.EscalationIncident{
		PseudoMessageID: "pmid-1",
		Tier:            "HighRisk",
		Category:        "LIKELY_PHISHING",
		Reason:          dto.EscalationReasonConfirmedBreach,
	})
	if err != nil {
		t.Fatalf("escalate: %v", err)
	}
	return tk
}

func TestEscalationHandler_ServeResolve_OK(t *testing.T) {
	svc := newTestEscalationService(t)
	tk := seedTicket(t, svc)
	h := NewEscalationHandler(nil, svc)

	body, _ := json.Marshal(map[string]any{
		"ticket_id":     tk.TicketID,
		"resolver_hash": "secops-1",
		"outcome":       string(dto.OutcomeConfirmedPhishing),
		"notes":         "Verified",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/escalation/resolve", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h.ServeResolve(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp dto.EscalationTicket
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Outcome != dto.OutcomeConfirmedPhishing {
		t.Fatalf("outcome=%q", resp.Outcome)
	}
}

func TestEscalationHandler_ServeResolve_Rejections(t *testing.T) {
	svc := newTestEscalationService(t)
	h := NewEscalationHandler(nil, svc)

	cases := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "wrong method", method: http.MethodGet, body: "", want: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, body: "garbage", want: http.StatusBadRequest},
		{name: "missing ticket_id", method: http.MethodPost, body: `{"outcome":"confirmed_phishing"}`, want: http.StatusBadRequest},
		{name: "invalid outcome", method: http.MethodPost, body: `{"ticket_id":"x","outcome":"bogus"}`, want: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, body: `{"ticket_id":"x","outcome":"closed_no_action","extra":"x"}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/v1/escalation/resolve", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeResolve(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestEscalationHandler_ServeGet_OK(t *testing.T) {
	svc := newTestEscalationService(t)
	tk := seedTicket(t, svc)
	h := NewEscalationHandler(nil, svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/escalation/"+tk.TicketID, nil)
	rec := httptest.NewRecorder()
	h.ServeGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp dto.EscalationTicket
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.TicketID != tk.TicketID {
		t.Fatalf("got %q want %q", resp.TicketID, tk.TicketID)
	}
}

func TestEscalationHandler_ServeGet_Rejections(t *testing.T) {
	svc := newTestEscalationService(t)
	h := NewEscalationHandler(nil, svc)

	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "wrong method", method: http.MethodPost, path: "/v1/escalation/abc", want: http.StatusMethodNotAllowed},
		{name: "missing id", method: http.MethodGet, path: "/v1/escalation/", want: http.StatusBadRequest},
		{name: "not found", method: http.MethodGet, path: "/v1/escalation/missing", want: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeGet(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestEscalationHandler_NilService(t *testing.T) {
	h := NewEscalationHandler(nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/escalation/resolve", strings.NewReader(`{"ticket_id":"x","outcome":"closed_no_action"}`))
	rec := httptest.NewRecorder()
	h.ServeResolve(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rec.Code)
	}
}
