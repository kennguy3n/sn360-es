package action

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

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

// testJWTSecret is the fixed 32-byte HS256 key the feedback test rig
// signs with. It is shared so a test can hand-mint a raw token (e.g. a
// pre-jti legacy token) that the rig's issuer will still verify.
func testJWTSecret() []byte {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i*7 + 3)
	}
	return secret
}

func newFeedbackTestRig(t *testing.T) (*FeedbackService, *privacy.JWTIssuer, *fakePublisher, *fakeReEvaluator) {
	t.Helper()
	secret := testJWTSecret()
	iss, err := privacy.NewJWTIssuer(privacy.JWTConfig{Secret: secret, Issuer: "sn360-test"})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	pub := &fakePublisher{}
	re := &fakeReEvaluator{}
	return NewFeedbackService(nil, iss, pub, re, NewInMemorySingleUseStore()), iss, pub, re
}

func issueTestToken(t *testing.T, iss *privacy.JWTIssuer, tier, action string) string {
	t.Helper()
	tok, err := iss.Issue("tenant-x", "msg-x", privacy.IssueOptions{
		Tier:     tier,
		Action:   action,
		Audience: []string{privacy.AudienceActionFeedback},
	})
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

// TestFeedbackServiceRejectsCrossScopeToken is the regression guard
// for the cross-scope replay gap: a quarantine_release token carries
// an empty Action (so it would slip past the action check) but a
// different scope. The feedback endpoint must refuse it — publishing
// feedback or triggering a re-evaluation under the victim tenant on a
// token minted for the self-release surface would be a scope-confusion
// bug. A valid signature is not enough; the scope must match.
func TestFeedbackServiceRejectsCrossScopeToken(t *testing.T) {
	svc, iss, pub, re := newFeedbackTestRig(t)
	tok, err := iss.Issue("tenant-x", "msg-x", privacy.IssueOptions{
		Scope:             privacy.ScopeQuarantineRelease,
		RecipientUserHash: "deadbeefcafebabe",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing})
	if err == nil {
		t.Fatal("quarantine_release token must be rejected by the banner-action endpoint")
	}
	if !errors.Is(err, privacy.ErrScopeNotPermitted) {
		t.Errorf("error = %v; want errors.Is(privacy.ErrScopeNotPermitted)", err)
	}
	if len(pub.calls) != 0 {
		t.Errorf("publisher must not be called on a cross-scope token, got %d calls", len(pub.calls))
	}
	if len(re.calls) != 0 {
		t.Errorf("re-evaluator must not be called on a cross-scope token, got %d calls", len(re.calls))
	}
}

// TestFeedbackServiceAcceptsExplicitBannerScope confirms the scope
// restriction is transparent for a token that carries an explicit
// ScopeBannerAction (not just the empty-claim default).
func TestFeedbackServiceAcceptsExplicitBannerScope(t *testing.T) {
	svc, iss, pub, _ := newFeedbackTestRig(t)
	tok, err := iss.Issue("tenant-x", "msg-x", privacy.IssueOptions{
		Scope:    privacy.ScopeBannerAction,
		Audience: []string{privacy.AudienceActionFeedback},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing}); err != nil {
		t.Fatalf("explicit banner-scope token must be accepted: %v", err)
	}
	if len(pub.calls) != 1 {
		t.Errorf("expected 1 publish, got %d", len(pub.calls))
	}
}

// TestFeedbackServiceRejectsReplayedToken is the replay-protection
// regression guard: a banner token is single-use. The first redemption
// succeeds and publishes; presenting the same token (same `jti`) again
// is refused with ErrTokenReplayed, and no second event is published.
func TestFeedbackServiceRejectsReplayedToken(t *testing.T) {
	svc, iss, pub, _ := newFeedbackTestRig(t)
	tok := issueTestToken(t, iss, "Warning", "")

	if _, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing}); err != nil {
		t.Fatalf("first redemption must succeed: %v", err)
	}
	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish after first use, got %d", len(pub.calls))
	}

	_, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing})
	if err == nil {
		t.Fatal("replayed token must be rejected")
	}
	if !errors.Is(err, ErrTokenReplayed) {
		t.Errorf("error = %v; want errors.Is(ErrTokenReplayed)", err)
	}
	if len(pub.calls) != 1 {
		t.Errorf("replay must not publish a second event, got %d publishes", len(pub.calls))
	}
}

// TestFeedbackServiceRejectsWrongAudience proves the audience binding:
// a cryptographically valid banner-scope token minted for a different
// `aud` is refused by the feedback endpoint with ErrAudienceNotPermitted
// and never reaches the bus.
func TestFeedbackServiceRejectsWrongAudience(t *testing.T) {
	svc, iss, pub, _ := newFeedbackTestRig(t)
	tok, err := iss.Issue("tenant-x", "msg-x", privacy.IssueOptions{
		Audience: []string{"sn360-es:some-other-endpoint"},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing})
	if err == nil {
		t.Fatal("token bound to a different audience must be rejected")
	}
	if !errors.Is(err, privacy.ErrAudienceNotPermitted) {
		t.Errorf("error = %v; want errors.Is(privacy.ErrAudienceNotPermitted)", err)
	}
	if len(pub.calls) != 0 {
		t.Errorf("wrong-audience token must not publish, got %d", len(pub.calls))
	}
}

// TestFeedbackServiceAcceptsLegacyTokenWithoutAudience documents the
// audience rollout policy: a token minted without an `aud` claim is
// still accepted during the drain window (audienceAllowed permits an
// absent audience), so banners issued before audience binding keep
// working. This token still carries a `jti` — Issue always stamps one
// — so it stays single-use; the distinct no-`jti` legacy path is
// covered by TestFeedbackServiceAcceptsLegacyTokenWithoutJTI.
func TestFeedbackServiceAcceptsLegacyTokenWithoutAudience(t *testing.T) {
	svc, iss, pub, _ := newFeedbackTestRig(t)
	// No aud and no explicit scope: the audience claim is absent,
	// exercising the audienceAllowed backward-compat branch.
	tok, err := iss.Issue("tenant-x", "msg-x", privacy.IssueOptions{})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing}); err != nil {
		t.Fatalf("legacy token without aud must be accepted: %v", err)
	}
	if len(pub.calls) != 1 {
		t.Errorf("expected 1 publish, got %d", len(pub.calls))
	}
}

// TestFeedbackServiceAcceptsLegacyTokenWithoutJTI covers the no-`jti`
// branch of consumeOnce. A token minted before the jti claim existed
// carries no id, so it cannot be deduped: it is accepted (degraded,
// with a warning) during the drain window and, lacking an id, is NOT
// single-use — presenting it twice succeeds both times. This is the
// documented legacy behaviour that disappears once every token carries
// a jti. The token is hand-signed with no `jti` because the current
// Issue always stamps one.
func TestFeedbackServiceAcceptsLegacyTokenWithoutJTI(t *testing.T) {
	svc, _, pub, _ := newFeedbackTestRig(t)
	tok := mintLegacyTokenNoJTI(t, testJWTSecret())

	for i := 1; i <= 2; i++ {
		if _, err := svc.Process(context.Background(), FeedbackRequest{Token: tok, Action: FeedbackReportPhishing}); err != nil {
			t.Fatalf("redemption %d of a no-jti legacy token must be accepted: %v", i, err)
		}
	}
	if len(pub.calls) != 2 {
		t.Errorf("a no-jti token is not deduped; want 2 publishes, got %d", len(pub.calls))
	}
}

// mintLegacyTokenNoJTI hand-signs a banner-scope action token with the
// rig's secret but deliberately leaves the `jti` (and `aud`) unset,
// reproducing a token minted before replay/audience binding existed.
// It cannot be produced via Issue, which always stamps a jti.
func mintLegacyTokenNoJTI(t *testing.T, secret []byte) string {
	t.Helper()
	now := time.Now()
	claims := privacy.ActionClaims{
		TenantID:             "tenant-x",
		PseudonymizedMessage: "msg-x",
		// Scope and Audience left empty (legacy shape); ID omitted.
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "sn360-test",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign legacy token: %v", err)
	}
	return signed
}
