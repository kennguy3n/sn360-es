package action

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/events"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

type capturedPublish struct {
	Subject string
	Data    []byte
	Opts    []events.PublishOption
}

type fakePublisher struct {
	mu      sync.Mutex
	calls   []capturedPublish
	failErr error
}

func (p *fakePublisher) Publish(_ context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	if p.failErr != nil {
		return p.failErr
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, capturedPublish{Subject: subject, Data: data, Opts: opts})
	return nil
}

type fakeReEvaluator struct {
	mu    sync.Mutex
	calls []string // pseudo IDs
	err   error
}

func (r *fakeReEvaluator) ReEvaluate(_ context.Context, _, pseudo string) error {
	if r.err != nil {
		return r.err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, pseudo)
	return nil
}

func newFeedbackTestRig(t *testing.T) (*FeedbackService, *privacy.JWTIssuer, *fakePublisher, *fakeReEvaluator) {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i*7 + 3)
	}
	iss, err := privacy.NewJWTIssuer(privacy.JWTConfig{Secret: secret, Issuer: "sn360-test"})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	pub := &fakePublisher{}
	re := &fakeReEvaluator{}
	return NewFeedbackService(nil, iss, pub, re), iss, pub, re
}

func issueTestToken(t *testing.T, iss *privacy.JWTIssuer, tier, action string) string {
	t.Helper()
	tok, err := iss.Issue("tenant-x", "msg-x", privacy.IssueOptions{Tier: tier, Action: action})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

func TestFeedbackServiceRejectsInvalidAction(t *testing.T) {
	svc, iss, pub, _ := newFeedbackTestRig(t)
	tok := issueTestToken(t, iss, "Warning", "")
	_, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: "delete_inbox"})
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
	if len(pub.calls) != 0 {
		t.Errorf("publisher should not be called on invalid action, got %d calls", len(pub.calls))
	}
}

func TestFeedbackServiceRejectsBadToken(t *testing.T) {
	svc, _, _, _ := newFeedbackTestRig(t)
	_, err := svc.Process(context.Background(), FeedbackRequest{Token: "garbage", Action: FeedbackReportPhishing})
	if err == nil {
		t.Error("expected error for bad token")
	}
}

func TestFeedbackServicePublishesEvent(t *testing.T) {
	svc, iss, pub, re := newFeedbackTestRig(t)
	tok := issueTestToken(t, iss, "Warning", "")
	pmid, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if pmid != "msg-x" {
		t.Errorf("pmid = %s, want msg-x", pmid)
	}
	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish, got %d", len(pub.calls))
	}
	call := pub.calls[0]
	if call.Subject != "es.action.feedback.report_phishing" {
		t.Errorf("subject = %s", call.Subject)
	}
	var evt FeedbackEvent
	if err := json.Unmarshal(call.Data, &evt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if evt.TenantID != "tenant-x" || evt.Action != FeedbackReportPhishing {
		t.Errorf("event = %+v", evt)
	}
	if evt.OccurredAt.IsZero() {
		t.Error("OccurredAt should be set")
	}
	// report_phishing must NOT trigger re-evaluation.
	if len(re.calls) != 0 {
		t.Errorf("report_phishing must not trigger re-eval, got %d", len(re.calls))
	}
}

func TestFeedbackServiceTriggersReEvalForMarkSafe(t *testing.T) {
	svc, iss, _, re := newFeedbackTestRig(t)
	tok := issueTestToken(t, iss, "Warning", "")
	if _, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackMarkSafe}); err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(re.calls) != 1 || re.calls[0] != "msg-x" {
		t.Errorf("re-eval calls = %v, want [msg-x]", re.calls)
	}
}

func TestFeedbackServiceTriggersReEvalForTrustSender(t *testing.T) {
	svc, iss, _, re := newFeedbackTestRig(t)
	tok := issueTestToken(t, iss, "Warning", "")
	if _, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackTrustSender}); err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(re.calls) != 1 {
		t.Errorf("trust_sender should trigger re-eval, got %d calls", len(re.calls))
	}
}

func TestFeedbackServiceReEvalErrorIsBestEffort(t *testing.T) {
	svc, iss, pub, re := newFeedbackTestRig(t)
	re.err = errors.New("re-eval down")
	tok := issueTestToken(t, iss, "Warning", "")
	pmid, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackMarkSafe})
	if err != nil {
		t.Errorf("re-eval failure should not fail Process: %v", err)
	}
	if pmid != "msg-x" {
		t.Errorf("pmid should still be returned, got %q", pmid)
	}
	if len(pub.calls) != 1 {
		t.Errorf("event should still be published, got %d", len(pub.calls))
	}
}

func TestFeedbackServicePublishFailurePropagates(t *testing.T) {
	svc, iss, pub, _ := newFeedbackTestRig(t)
	pub.failErr = errors.New("bus down")
	tok := issueTestToken(t, iss, "Warning", "")
	if _, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing}); err == nil {
		t.Error("publisher failure should propagate")
	}
}

func TestFeedbackServiceTokenBoundActionRejected(t *testing.T) {
	svc, iss, _, _ := newFeedbackTestRig(t)
	// Token bound to a different action.
	tok := issueTestToken(t, iss, "Warning", string(FeedbackTrustSender))
	if _, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing}); err == nil {
		t.Error("token bound to a different action must be rejected")
	}
}
