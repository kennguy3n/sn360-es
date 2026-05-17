package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/service/predict"
)

func newTestPredictHandler() *PredictHandler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	recipient := predict.NewRecipientService(predict.RecipientServiceConfig{
		Lookalike: predict.NewStaticLookalikeChecker(map[string]string{
			"acmme.com": "acme.com",
		}),
	})
	open := predict.NewOpenService(predict.OpenServiceConfig{})
	return NewPredictHandler(logger, recipient, open)
}

func TestPredictHandler_ServeRecipient_OK(t *testing.T) {
	h := newTestPredictHandler()
	req := predict.RecipientRequest{
		TenantID: "acme",
		Recipients: []predict.RecipientCandidate{
			{UserHash: "u1", Domain: "acmme.com", IsExternal: true},
		},
	}
	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/predict/recipient", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeRecipient(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp predict.RecipientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.OverallLevel != predict.WarnHigh || len(resp.Warnings) != 1 {
		t.Fatalf("expected lookalike high warning, got %+v", resp)
	}
}

func TestPredictHandler_ServeRecipient_Rejections(t *testing.T) {
	h := newTestPredictHandler()
	cases := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "wrong method", method: http.MethodGet, body: "", want: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, body: "garbage", want: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, body: `{"tenant_id":"t","recipients":[{"user_hash":"u"}],"foo":"bar"}`, want: http.StatusBadRequest},
		{name: "missing tenant", method: http.MethodPost, body: `{"recipients":[{"user_hash":"u","is_external":true}]}`, want: http.StatusBadRequest},
		{name: "empty recipients", method: http.MethodPost, body: `{"tenant_id":"t","recipients":[]}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/v1/predict/recipient", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeRecipient(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestPredictHandler_ServeRecipient_NilService(t *testing.T) {
	h := NewPredictHandler(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/predict/recipient", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeRecipient(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestPredictHandler_ServeOpen_OK(t *testing.T) {
	h := newTestPredictHandler()
	req := predict.OpenRequest{
		TenantID:        "acme",
		PseudoMessageID: "pmid-1",
		Tier:            "warning",
	}
	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/predict/open", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeOpen(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp predict.OpenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.ShowWarning || resp.Level != predict.WarnWarning {
		t.Fatalf("expected warning-level response, got %+v", resp)
	}
}

func TestPredictHandler_ServeOpen_Rejections(t *testing.T) {
	h := newTestPredictHandler()
	cases := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "wrong method", method: http.MethodGet, body: "", want: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, body: "garbage", want: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, body: `{"tenant_id":"t","pseudo_message_id":"p","tier":"warning","extra":"x"}`, want: http.StatusBadRequest},
		{name: "missing tenant", method: http.MethodPost, body: `{"pseudo_message_id":"p"}`, want: http.StatusBadRequest},
		{name: "missing pmid", method: http.MethodPost, body: `{"tenant_id":"t"}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/v1/predict/open", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeOpen(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestPredictHandler_ServeOpen_NilService(t *testing.T) {
	h := NewPredictHandler(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/predict/open", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeOpen(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rec.Code)
	}
}
