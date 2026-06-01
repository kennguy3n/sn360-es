package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/action"
	"github.com/kennguy3n/sn360-es/internal/service/selfrelease"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// selfReleaseFixture wires a real QuarantineService + ReleaseService
// + selfrelease.Service against the in-memory fakes that already
// power TestQuarantineHandler_*. The reevaluator verdict drives
// what ReleaseAllowed / ReleaseRefused the runner returns; the
// quarantine record's Tier2Malicious bit drives the unconditional
// block.
type selfReleaseFixture struct {
	issuer   *privacy.JWTIssuer
	release  *action.ReleaseService
	q        *action.QuarantineService
	prov     *qhFakeProvider
	srSvc    *selfrelease.Service
	audit    repository.QuarantineReleaseAuditRepository
	policies repository.TenantReleasePolicyRepository
}

func newSelfReleaseFixture(
	t *testing.T,
	verdict dto.EvaluateResult,
	tier2Malicious bool,
	policy repository.TenantReleasePolicy,
) *selfReleaseFixture {
	t.Helper()
	issuer, err := privacy.NewJWTIssuer(privacy.JWTConfig{
		Secret: bytes.Repeat([]byte{0xab}, 32),
		Issuer: "sn360-es",
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	prov := &qhFakeProvider{}
	qsvc, err := action.NewQuarantineService(action.QuarantineConfig{
		Providers: []action.QuarantineProvider{prov},
		Store:     newQHFakeStore(),
		Encryptor: qhFakeEncryptor{},
		Publisher: qhFakePublisher{},
	})
	if err != nil {
		t.Fatalf("quarantine svc: %v", err)
	}
	if _, err := qsvc.Quarantine(context.Background(), action.QuarantineRequest{
		Tenant:               "acme",
		PseudonymizedMessage: "pmid-1",
		Provider:             action.LabelProviderGmail,
		Email:                "user@acme.com",
		MessageID:            "raw-1",
		Tier:                 constant.TierBlocked,
		Primary:              constant.CategoryLikelyPhishing,
		Tier2Malicious:       tier2Malicious,
	}); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
	rsvc, err := action.NewReleaseService(action.ReleaseConfig{
		Quarantine:  qsvc,
		Reevaluator: qhFakeReevaluator{verdict: verdict},
		Publisher:   qhFakePublisher{},
	})
	if err != nil {
		t.Fatalf("release svc: %v", err)
	}
	audit := repository.NewMemoryQuarantineReleaseAudit()
	policies := repository.NewMemoryTenantReleasePolicy()
	if policy.TenantID != "" {
		if err := policies.Upsert(context.Background(), policy); err != nil {
			t.Fatalf("seed policy: %v", err)
		}
	}
	srSvc, err := selfrelease.NewService(selfrelease.Config{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Quarantine: qsvc,
		Runner:     rsvc,
		Audit:      audit,
		Policies:   policies,
	})
	if err != nil {
		t.Fatalf("selfrelease svc: %v", err)
	}
	return &selfReleaseFixture{
		issuer:   issuer,
		release:  rsvc,
		q:        qsvc,
		prov:     prov,
		srSvc:    srSvc,
		audit:    audit,
		policies: policies,
	}
}

// issueSelfReleaseToken mints a scp=quarantine_release token with
// the given (tenant, pmid, recipient_user_hash_hex).
func issueSelfReleaseToken(t *testing.T, issuer *privacy.JWTIssuer, tenant, pmid, recipientHashHex string) string {
	t.Helper()
	tok, err := issuer.Issue(tenant, pmid, privacy.IssueOptions{
		Scope:             privacy.ScopeQuarantineRelease,
		RecipientUserHash: recipientHashHex,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

// tamperJWTSignature returns tok with its signature mutated so the
// JWT no longer verifies. Implemented by base64URL-decoding the
// signature, flipping the first signature byte, and re-encoding.
//
// Naive last-character tampering ("change the final base64 char")
// is unreliable: for an HS256 signature (32 bytes = 43 base64URL
// chars unpadded) the last base64 character carries only 4 real
// bits, so each "top-4-bits" group of four base64URL chars decodes
// to the same trailing 4-bit sequence. For example {w, x, y, z} all
// decode to top-4-bits 0b1100, so swapping one of {w, y, z} for "x"
// produces a *different* base64 string that decodes to the *same*
// signature and verifies cleanly — meaning the test's "invalid
// signature" assertion only fires ~96% of the time. Flipping a
// decoded byte avoids that whole class of issue.
func tamperJWTSignature(tb testing.TB, tok string) string {
	tb.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		tb.Fatalf("tamperJWTSignature: token has %d parts, want 3", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		tb.Fatalf("tamperJWTSignature: decode signature: %v", err)
	}
	if len(sig) == 0 {
		tb.Fatalf("tamperJWTSignature: empty signature")
	}
	sig[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

// postForm is the canonical way the banner posts to the endpoint
// (application/x-www-form-urlencoded with a single token field).
func postForm(t *testing.T, h http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	body := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/v1/quarantine/release",
		strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// postJSON is the alternate path some callers (e.g. unit harnesses)
// take. The handler accepts both.
func postJSON(t *testing.T, h http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": token})
	req := httptest.NewRequest(http.MethodPost, "/v1/quarantine/release", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// decodeSelfReleaseBody parses the JSON body emitted by the
// scp="quarantine_release" path.
type selfReleaseBody struct {
	Outcome  string `json:"outcome"`
	Restored bool   `json:"restored"`
}

func decodeSelfReleaseBody(t *testing.T, rec *httptest.ResponseRecorder) selfReleaseBody {
	t.Helper()
	var b selfReleaseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	return b
}

// listAudit reads all audit entries for the test tenant from the
// in-memory repository.
func listAudit(t *testing.T, fx *selfReleaseFixture, pmid string) []repository.QuarantineReleaseAuditEntry {
	t.Helper()
	entries, err := fx.audit.ListByMessage(context.Background(), "acme", pmid, 50)
	if err != nil {
		t.Fatalf("ListByMessage: %v", err)
	}
	return entries
}

// recipientHashHex is the canonical hex string the banner / token
// would carry — a hex-encoded 32-byte BLAKE2b digest. We use a
// fixed value across tests so audit rows are reproducible.
const recipientHashHex = "deadbeefcafebabe1234567890abcdef"

// TestSelfReleaseHandler_HappyPath exercises the full release
// path. Verdict drops below blocking → ReleaseAllowed → outcome
// released → HTTP 202. Exactly one audit row written.
func TestSelfReleaseHandler_HappyPath(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational},
		false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	h, err := NewQuarantineHandler(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)

	rec := postForm(t, h, tok)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSelfReleaseBody(t, rec)
	if body.Outcome != string(repository.QuarantineReleaseOutcomeReleased) {
		t.Fatalf("outcome=%q", body.Outcome)
	}
	if !body.Restored {
		t.Fatal("expected restored=true")
	}
	if fx.prov.restoreCalls != 1 {
		t.Fatalf("restoreCalls=%d", fx.prov.restoreCalls)
	}
	entries := listAudit(t, fx, "pmid-1")
	if len(entries) != 1 || entries[0].Outcome != repository.QuarantineReleaseOutcomeReleased {
		t.Fatalf("audit entries=%+v", entries)
	}
}

// TestSelfReleaseHandler_Tier2BlockedReturns403 verifies the
// unconditional tier-2 block.
func TestSelfReleaseHandler_Tier2BlockedReturns403(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, // benign re-eval, but Tier2Malicious=true
		true,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})
	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)

	rec := postForm(t, h, tok)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSelfReleaseBody(t, rec)
	if body.Outcome != string(repository.QuarantineReleaseOutcomeTier2Blocked) {
		t.Fatalf("outcome=%q", body.Outcome)
	}
	if body.Restored {
		t.Fatal("expected restored=false")
	}
	if fx.prov.restoreCalls != 0 {
		t.Fatalf("restore should not be called when tier-2 blocked; got %d", fx.prov.restoreCalls)
	}
}

// TestSelfReleaseHandler_RunnerRefusedReturns403ReleaseRefused
// covers the case where Tier2Malicious=false at lookup (so the
// persisted-bit gate doesn't fire) but the runner's re-evaluation
// returns ReleaseRefused (verdict still at/above MinReleaseTier).
// The wire response must be 403 (same as Tier2Blocked) but the
// audit row MUST be `release_refused`, NOT `tier2_blocked` — the
// audit column distinguishes the two safety-stack refusal paths
// for SOC drill-down without leaking which classifier said no to
// the recipient.
func TestSelfReleaseHandler_RunnerRefusedReturns403ReleaseRefused(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		// Re-eval comes back still at TierBlocked (>=
		// default MinReleaseTier=TierBlocked → refused).
		dto.EvaluateResult{Tier: constant.TierBlocked},
		// Persisted Tier2Malicious is FALSE: the persisted
		// gate at lookup time would have let us through.
		false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})
	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)

	rec := postForm(t, h, tok)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSelfReleaseBody(t, rec)
	if body.Outcome != string(repository.QuarantineReleaseOutcomeReleaseRefused) {
		t.Fatalf("outcome=%q want=%q (audit must distinguish runner refusal from persisted tier-2 block)",
			body.Outcome, repository.QuarantineReleaseOutcomeReleaseRefused)
	}
	if body.Restored {
		t.Fatal("expected restored=false on runner refusal")
	}
	if fx.prov.restoreCalls != 0 {
		t.Fatalf("restore must not run when the runner refused; got %d", fx.prov.restoreCalls)
	}
	entries := listAudit(t, fx, "pmid-1")
	if len(entries) != 1 {
		t.Fatalf("audit entries=%+v want exactly one row", entries)
	}
	if entries[0].Outcome != repository.QuarantineReleaseOutcomeReleaseRefused {
		t.Fatalf("audit outcome=%q want=%q (regression guard: do NOT collapse onto tier2_blocked)",
			entries[0].Outcome, repository.QuarantineReleaseOutcomeReleaseRefused)
	}
}

// TestSelfReleaseHandler_RateLimitedReturns429 seeds the audit log
// past the policy cap and verifies the rate-limit gate fires.
func TestSelfReleaseHandler_RateLimitedReturns429(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 1})

	recipientHash := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
		0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
	// Seed one audit row inside the rate-limit window so the
	// next attempt is over budget.
	if _, err := fx.audit.Record(context.Background(), repository.QuarantineReleaseAuditEntry{
		TenantID:          "acme",
		PseudoMessageID:   "pmid-other",
		RecipientUserHash: recipientHash,
		Outcome:           repository.QuarantineReleaseOutcomeReleased,
		RequestedAt:       time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed audit: %v", err)
	}

	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})
	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)

	rec := postForm(t, h, tok)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSelfReleaseBody(t, rec)
	if body.Outcome != string(repository.QuarantineReleaseOutcomeRateLimited) {
		t.Fatalf("outcome=%q", body.Outcome)
	}
}

// TestSelfReleaseHandler_AuthFailuresDoNotBurnRateLimit is the
// handler-level regression guard for the rate-limit poisoning
// attack identified in Devin Review round 2: an attacker who knows
// a recipient's BLAKE2b-256 hash sprays forged JWTs at the endpoint.
// Each rejected token writes an `invalid_token` audit row. If those
// rows counted toward the per-recipient rate-limit bucket, the
// attacker could deny self-release to the legitimate recipient by
// pre-filling the bucket. The fix in the repository's
// CountRecentByRecipient excludes auth-failure outcomes, and this
// test exercises the full handler stack to assert the
// end-to-end behaviour holds.
func TestSelfReleaseHandler_AuthFailuresDoNotBurnRateLimit(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 1})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})

	// Pre-fill the bucket from the attacker's POV: spray N
	// tampered tokens that all carry the legitimate recipient's
	// hash in their unverified claims. Every one results in
	// an audit row.
	const sprayCount = 10
	for i := 0; i < sprayCount; i++ {
		tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)
		// Tamper the signature so the JWT fails to verify.
		// The handler decodes claims from the unverified
		// payload to audit the auth failure, so each call
		// writes one `invalid_token` row.
		tampered := tamperJWTSignature(t, tok)
		rec := postForm(t, h, tampered)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("spray %d: expected 401, got %d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	// Confirm the audit rows landed (visibility for SOC).
	rows, err := fx.audit.ListByMessage(context.Background(), "acme", "pmid-1", sprayCount+5)
	if err != nil {
		t.Fatalf("ListByMessage: %v", err)
	}
	if len(rows) != sprayCount {
		t.Fatalf("audit rows from spray: got %d want %d (auth-fail rows MUST be written for forensics)", len(rows), sprayCount)
	}
	for _, e := range rows {
		if e.Outcome != repository.QuarantineReleaseOutcomeInvalidToken {
			t.Fatalf("spray row outcome=%q want=invalid_token", e.Outcome)
		}
	}

	// Now the legitimate user clicks their valid token. With
	// the fix, the rate-limit count for this recipient is 0
	// (auth-failure rows excluded), so the release succeeds.
	// WITHOUT the fix this would return 429 rate_limited.
	validTok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)
	rec := postForm(t, h, validTok)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("legitimate click after spray: status=%d body=%s (auth-fail rows MUST NOT burn the rate-limit budget)",
			rec.Code, rec.Body.String())
	}
	body := decodeSelfReleaseBody(t, rec)
	if body.Outcome != string(repository.QuarantineReleaseOutcomeReleased) {
		t.Fatalf("outcome=%q want=released", body.Outcome)
	}
	if !body.Restored {
		t.Fatal("expected restored=true after legitimate post-spray click")
	}
}

// TestSelfReleaseHandler_SecondClickAfterReleaseReturnsNotFound
// covers the sequential-replay path: once a token has driven a
// release through to completion, the quarantine record is cleared,
// so a second POST with the SAME token observes "no record" at
// lookup time and the state machine emits `not_found` → HTTP 404.
//
// This is distinct from the `already_released` outcome, which only
// fires on the *concurrent* ClaimReference race (two clicks reach
// the runner before either marks the reference as claimed). The
// race path is covered at the service layer by
// TestService_RunnerOutcomeMapping/already_done -> already_released
// in internal/service/selfrelease/service_test.go (the runner
// returns ReleaseAlreadyDone, the service translates it to
// QuarantineReleaseOutcomeAlreadyReleased, and the handler maps
// that to HTTP 200). Splitting the coverage by layer is
// intentional: the concurrent race needs the action.QuarantineService
// fencing primitive to fire deterministically, which is easier to
// set up at the service level than at the handler level. The
// handler-level guarantee being asserted here is the sequential
// idempotency contract — same token, repeated, produces the
// closed-set outcome rather than e.g. re-invoking the provider.
//
// The previous name (TestSelfReleaseHandler_AlreadyReleasedReturns200)
// confusingly suggested this was the already_released path; rename
// applied to match the actual assertion.
func TestSelfReleaseHandler_SecondClickAfterReleaseReturnsNotFound(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})
	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)

	// First click → released.
	rec1 := postForm(t, h, tok)
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("first click status=%d body=%s", rec1.Code, rec1.Body.String())
	}
	beforeRestoreCalls := fx.prov.restoreCalls

	// Second click → 404 (record cleared) → outcome=not_found.
	// In the WS-3a state machine the not_found branch covers
	// "already cleared after release" — see service.go's
	// not_found handler. The runner doesn't observe this case
	// because the quarantine record is gone by the time we
	// reach the lookup.
	rec2 := postForm(t, h, tok)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("second click status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	body := decodeSelfReleaseBody(t, rec2)
	if body.Outcome != string(repository.QuarantineReleaseOutcomeNotFound) {
		t.Fatalf("outcome=%q", body.Outcome)
	}
	if fx.prov.restoreCalls != beforeRestoreCalls {
		t.Fatalf("provider re-invoked on second click: before=%d after=%d",
			beforeRestoreCalls, fx.prov.restoreCalls)
	}
}

// TestSelfReleaseHandler_CrossTenantReturnsNotFound: a token
// signed for tenant A cannot release a message owned by tenant B.
// The response body must be the same 404 a same-tenant miss
// produces (cross-tenant indistinguishability mirror of WS-3b).
func TestSelfReleaseHandler_CrossTenantReturnsNotFound(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "other", QuarantineSelfReleasePerHour: 5})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})
	// Token signed for tenant=other (which has no quarantine
	// record under pmid-1).
	tok := issueSelfReleaseToken(t, fx.issuer, "other", "pmid-1", recipientHashHex)

	rec := postForm(t, h, tok)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeSelfReleaseBody(t, rec)
	if body.Outcome != string(repository.QuarantineReleaseOutcomeNotFound) {
		t.Fatalf("outcome=%q", body.Outcome)
	}
}

// TestSelfReleaseHandler_ExpiredToken returns 401 (uniform with
// invalid_token) and writes a token_expired audit row.
func TestSelfReleaseHandler_ExpiredToken(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})

	// Issue with tiny TTL and wait past expiry.
	tok, err := fx.issuer.Issue("acme", "pmid-1", privacy.IssueOptions{
		TTL:               5 * time.Millisecond,
		Scope:             privacy.ScopeQuarantineRelease,
		RecipientUserHash: recipientHashHex,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	rec := postForm(t, h, tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	// Body is the uniform error body ({"error":"invalid token"}),
	// NOT the selfRelease outcome body — the handler returns
	// before reaching the state machine.
	if !strings.Contains(rec.Body.String(), "invalid token") {
		t.Fatalf("expected 'invalid token' body, got %q", rec.Body.String())
	}
	// Audit row for token_expired must exist.
	entries := listAudit(t, fx, "pmid-1")
	if len(entries) != 1 || entries[0].Outcome != repository.QuarantineReleaseOutcomeTokenExpired {
		t.Fatalf("audit entries=%+v", entries)
	}
}

// TestSelfReleaseHandler_InvalidSignature also returns 401 with
// the same body, and writes an invalid_token audit row.
func TestSelfReleaseHandler_InvalidSignature(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})

	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)
	// Tamper the signature.
	tampered := tamperJWTSignature(t, tok)
	rec := postForm(t, h, tampered)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	entries := listAudit(t, fx, "pmid-1")
	if len(entries) != 1 || entries[0].Outcome != repository.QuarantineReleaseOutcomeInvalidToken {
		t.Fatalf("audit entries=%+v", entries)
	}
}

// TestSelfReleaseHandler_WrongScope ensures a banner-scope token
// cannot release via the self-release path: the dispatcher
// routes scp="banner_action" to the operator path, which doesn't
// recognise the pmid (no per-pmid lookup with that handler). The
// only safe path is to refuse — but legacy tokens with no scope
// flow to the operator path by design (back-compat), so we test
// the explicit "wrong scope" case where the operator handler
// returns an outcome that proves we did NOT hit the self-release
// path.
func TestSelfReleaseHandler_WrongScopeNotReleased(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})

	// Issue with an unknown scope — handler should refuse with 401.
	tok, err := fx.issuer.Issue("acme", "pmid-1", privacy.IssueOptions{
		Scope: "totally_unknown_scope",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	rec := postJSON(t, h, tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	// Self-release path did not execute → no audit row written
	// (this is the operator-default refusal, not a
	// quarantine_release attempt).
	entries := listAudit(t, fx, "pmid-1")
	if len(entries) != 0 {
		t.Fatalf("unknown scope unexpectedly audited via self-release path: %+v", entries)
	}
	if fx.prov.restoreCalls != 0 {
		t.Fatalf("provider unexpectedly called: %d", fx.prov.restoreCalls)
	}
}

// TestSelfReleaseHandler_NilSelfReleaseSvc verifies a deployment
// without a self-release service refuses scp=quarantine_release
// tokens with a uniform 401.
func TestSelfReleaseHandler_NilSelfReleaseSvc(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	// Construct the handler with selfRelease=nil so the dispatcher
	// reaches the "no self-release service" guard.
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, nil, NopTenantBinder{})
	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)
	rec := postForm(t, h, tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestSelfReleaseHandler_MalformedRecipientHash: a token with an
// odd-length / non-hex `ruh` claim must be rejected with the
// uniform 401, not crash.
func TestSelfReleaseHandler_MalformedRecipientHash(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})

	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", "not-valid-hex!")
	rec := postForm(t, h, tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestSelfReleaseHandler_FormAndJSONInteroperate verifies both
// request-content-types reach the same outcome.
func TestSelfReleaseHandler_FormAndJSONInteroperate(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})

	t.Run("form", func(t *testing.T) {
		h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, NopTenantBinder{})
		tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)
		rec := postForm(t, h, tok)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	// Fresh fixture for the JSON path; the previous run cleared
	// the quarantine record.
	fx2 := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	t.Run("json", func(t *testing.T) {
		h, _ := NewQuarantineHandler(nil, fx2.issuer, fx2.release, fx2.srSvc, NopTenantBinder{})
		tok := issueSelfReleaseToken(t, fx2.issuer, "acme", "pmid-1", recipientHashHex)
		rec := postJSON(t, h, tok)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// stubTenantBinder records every WithTenant invocation so tests
// can assert (a) the handler called the binder at all, and
// (b) it bound to the tenant_id from the verified JWT claim — not
// e.g. the attacker-controlled `tid` of a tampered token. Returns
// the parent ctx unmodified (no real conn is acquired) plus a
// no-op release.
type stubTenantBinder struct {
	binds   []string
	failErr error
}

func (s *stubTenantBinder) WithTenant(ctx context.Context, tenantID string) (context.Context, TenantBinderReleaseFunc, error) {
	if s.failErr != nil {
		return ctx, func() error { return nil }, s.failErr
	}
	s.binds = append(s.binds, tenantID)
	return ctx, func() error { return nil }, nil
}

// TestSelfReleaseHandler_BindsTenantConnFromVerifiedClaim guards
// the WS-3a Round-3 fix: the /v1/quarantine/release endpoint sits
// in defaultAuthSkipPaths(), so JWTAuth + TenantConnBinder
// middleware don't run for it. The handler MUST bind the
// Postgres conn itself, AFTER the JWT verifies, using the
// `tid` claim — otherwise the rate-limit COUNT query against
// `quarantine_release_audit` and the policy SELECT against
// `tenant_release_policies` silently see zero rows under RLS,
// effectively disabling the rate limiter and dropping every
// audit INSERT.
//
// The test wires a stub binder, posts a happy-path self-release,
// and asserts:
//   - the binder was invoked exactly once
//   - the bound tenant_id equals the verified JWT's `tid`
//   - the underlying service call still succeeded (i.e. the bind
//     step is non-fatal in the happy path)
func TestSelfReleaseHandler_BindsTenantConnFromVerifiedClaim(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	binder := &stubTenantBinder{}
	h, err := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, binder)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)
	rec := postForm(t, h, tok)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(binder.binds) != 1 {
		t.Fatalf("expected exactly 1 WithTenant call, got %d: %v",
			len(binder.binds), binder.binds)
	}
	if binder.binds[0] != "acme" {
		t.Fatalf("WithTenant called with tenant_id=%q, want %q (must equal the verified JWT `tid` claim)",
			binder.binds[0], "acme")
	}
}

// TestSelfReleaseHandler_BindFailureReturns503 pins the
// fail-closed contract on the bind step: if the binder cannot
// acquire / configure a Postgres conn for the verified tenant
// (pool exhausted, Postgres dropped the session, etc.) the
// handler MUST reject the request with 503 rather than fall
// through and run the service unbound — running unbound would
// silently see zero rows under RLS and bypass the rate limiter,
// which is strictly worse than a transient unavailability.
func TestSelfReleaseHandler_BindFailureReturns503(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	binder := &stubTenantBinder{failErr: io.ErrUnexpectedEOF}
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, binder)
	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)
	rec := postForm(t, h, tok)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s; want 503 on bind failure",
			rec.Code, rec.Body.String())
	}
	// Provider must NOT have been invoked: the service body
	// never ran because the bind failed first.
	if fx.prov.restoreCalls != 0 {
		t.Fatalf("provider invoked despite bind failure: %d calls",
			fx.prov.restoreCalls)
	}
}

// TestSelfReleaseHandler_AuthFailureBindsTenantBeforeAuditWrite
// guards the same RLS gap on the auth-failure audit path: when a
// quarantine_release token fails JWT verification (expired or
// invalid signature) but its partial claims carry a tenant_id,
// the handler still writes an audit row recording the attempt.
// That INSERT also runs against the RLS-protected
// `quarantine_release_audit` table, so it MUST be inside a
// WithTenant scope — otherwise the WITH CHECK clause rejects the
// INSERT and SOC loses visibility into the spray attempt.
func TestSelfReleaseHandler_AuthFailureBindsTenantBeforeAuditWrite(t *testing.T) {
	fx := newSelfReleaseFixture(t,
		dto.EvaluateResult{Tier: constant.TierInformational}, false,
		repository.TenantReleasePolicy{TenantID: "acme", QuarantineSelfReleasePerHour: 5})
	binder := &stubTenantBinder{}
	h, _ := NewQuarantineHandler(nil, fx.issuer, fx.release, fx.srSvc, binder)
	// Issue a normal token then tamper the signature so the
	// verifier returns ErrTokenInvalid with non-nil partial
	// claims (the WS-3a verifier extracts the unverified claims
	// on signature failure for exactly this audit path).
	tok := issueSelfReleaseToken(t, fx.issuer, "acme", "pmid-1", recipientHashHex)
	tampered := tok[:len(tok)-2] + "XX"
	rec := postForm(t, h, tampered)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s; want 401", rec.Code, rec.Body.String())
	}
	if len(binder.binds) != 1 {
		t.Fatalf("expected exactly 1 WithTenant call on auth-failure audit path, got %d: %v",
			len(binder.binds), binder.binds)
	}
	if binder.binds[0] != "acme" {
		t.Fatalf("WithTenant called with tenant_id=%q, want %q (the partial-claim `tid` of the rejected token)",
			binder.binds[0], "acme")
	}
}
