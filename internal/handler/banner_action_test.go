package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// stubPublisher captures published events so the test can assert on
// subject and payload without spinning up a real NATS server.
type stubPublisher struct {
	subject string
	data    []byte
	err     error
}

func (s *stubPublisher) Publish(_ context.Context, subject string, data []byte, _ ...events.PublishOption) error {
	s.subject = subject
	s.data = data
	return s.err
}

// newTestFeedback wires a real FeedbackService over a stub publisher so
// the handler exercises the same code path it does in production
// (token verification, action validation, publish).
func newTestFeedback(t *testing.T) (*action.FeedbackService, *privacy.JWTIssuer, *stubPublisher) {
	t.Helper()
	issuer, err := privacy.NewJWTIssuer(privacy.JWTConfig{
		Secret: bytes.Repeat([]byte{0x42}, 32),
		Issuer: "sn360-es",
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	pub := &stubPublisher{}
	svc := action.NewFeedbackService(slog.New(slog.NewTextHandler(io.Discard, nil)), issuer, pub, nil, action.NewInMemorySingleUseStore())
	return svc, issuer, pub
}

func issueBannerToken(t *testing.T, issuer *privacy.JWTIssuer, tenant, pmid, act string) string {
	t.Helper()
	tok, err := issuer.Issue(tenant, pmid, privacy.IssueOptions{
		Action:   act,
		Audience: []string{privacy.AudienceActionFeedback},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

func TestBannerActionHandler_AcceptsValidPost(t *testing.T) {
	svc, issuer, pub := newTestFeedback(t)
	h := NewBannerActionHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), svc)

	tok := issueBannerToken(t, issuer, "acme", "pmid-1", string(action.FeedbackReportPhishing))
	body, _ := json.Marshal(map[string]string{"token": tok, "action": string(action.FeedbackReportPhishing)})
	req := httptest.NewRequest(http.MethodPost, "/v1/banner/action", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp bannerActionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "accepted" || resp.Action != string(action.FeedbackReportPhishing) || resp.PseudonymizedMessage != "pmid-1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if pub.subject != "es.action.feedback.report_phishing" {
		t.Fatalf("publish subject = %q", pub.subject)
	}
}

func TestBannerActionHandler_NormalisesActionCasing(t *testing.T) {
	svc, issuer, _ := newTestFeedback(t)
	h := NewBannerActionHandler(nil, svc)

	tok := issueBannerToken(t, issuer, "acme", "pmid-2", string(action.FeedbackMarkSafe))
	body := []byte(`{"token":"` + tok + `","action":" Mark_Safe "}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/banner/action", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBannerActionHandler_Rejections(t *testing.T) {
	svc, issuer, _ := newTestFeedback(t)
	h := NewBannerActionHandler(nil, svc)

	tok := issueBannerToken(t, issuer, "acme", "pmid-3", string(action.FeedbackReportPhishing))

	cases := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "wrong method", method: http.MethodGet, body: "", want: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, body: "{not json", want: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, body: `{"token":"t","action":"report_phishing","extra":"x"}`, want: http.StatusBadRequest},
		{name: "missing token", method: http.MethodPost, body: `{"action":"report_phishing"}`, want: http.StatusBadRequest},
		{name: "missing action", method: http.MethodPost, body: `{"token":"` + tok + `"}`, want: http.StatusBadRequest},
		{name: "invalid action", method: http.MethodPost, body: `{"token":"` + tok + `","action":"bogus"}`, want: http.StatusBadRequest},
		{name: "invalid token", method: http.MethodPost, body: `{"token":"not.a.jwt","action":"report_phishing"}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/v1/banner/action", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
