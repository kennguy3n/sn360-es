package action

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/pkg/privacy"
)

// fakeStore is an in-memory URLStore for tests. Safe for concurrent use.
type fakeStore struct {
	mu sync.Mutex
	m  map[string]string
}

func newFakeStore() *fakeStore { return &fakeStore{m: map[string]string{}} }

func (s *fakeStore) Set(_ context.Context, k, v string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

func (s *fakeStore) Get(_ context.Context, k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}

// reverseEncryptor is a deterministic, key-less encryptor for tests. It
// returns the bytes reversed; that's enough to verify the rewriter calls
// Encrypt / Decrypt correctly without depending on the KMS layer.
type reverseEncryptor struct{}

func (reverseEncryptor) Encrypt(_ context.Context, _ string, p []byte) ([]byte, error) {
	out := make([]byte, len(p))
	for i, b := range p {
		out[len(p)-1-i] = b
	}
	return out, nil
}

func (reverseEncryptor) Decrypt(_ context.Context, _ string, c []byte) ([]byte, error) {
	out := make([]byte, len(c))
	for i, b := range c {
		out[len(c)-1-i] = b
	}
	return out, nil
}

func newTestRewriter(t *testing.T) (*URLRewriter, *fakeStore) {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	iss, err := privacy.NewJWTIssuer(privacy.JWTConfig{Secret: secret, Issuer: "sn360-test"})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	store := newFakeStore()
	rw, err := NewURLRewriter(nil, iss, store, reverseEncryptor{}, URLRewriterConfig{
		BaseURL:     "https://l.sn360.io",
		PreImageTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("rewriter: %v", err)
	}
	return rw, store
}

func TestURLRewriterRequiresAllDeps(t *testing.T) {
	if _, err := NewURLRewriter(nil, nil, newFakeStore(), reverseEncryptor{}, URLRewriterConfig{}); err == nil {
		t.Error("nil issuer should be rejected")
	}
	if _, err := NewURLRewriter(nil, &privacy.JWTIssuer{}, nil, reverseEncryptor{}, URLRewriterConfig{}); err == nil {
		t.Error("nil store should be rejected")
	}
	if _, err := NewURLRewriter(nil, &privacy.JWTIssuer{}, newFakeStore(), nil, URLRewriterConfig{}); err == nil {
		t.Error("nil encryptor should be rejected")
	}
}

func TestURLRewriterSkipsBenignTiers(t *testing.T) {
	rw, _ := newTestRewriter(t)
	body := `<a href="https://attack.example/login">click</a>`
	for _, tier := range []constant.Tier{
		constant.TierTrusted, constant.TierInformational, constant.TierCaution, constant.TierWarning,
	} {
		out, err := rw.Rewrite(context.Background(), RewriteRequest{
			TenantID:             "t1",
			PseudonymizedMessage: "m1",
			Tier:                 tier,
			HTMLBody:             body,
		})
		if err != nil {
			t.Fatalf("rewrite (%s): %v", tier, err)
		}
		if out.RewriteCount != 0 {
			t.Errorf("tier %s should not rewrite, got %d", tier, out.RewriteCount)
		}
		if out.HTMLBody != body {
			t.Errorf("tier %s mutated body: %s", tier, out.HTMLBody)
		}
	}
}

func TestURLRewriterRewritesHighRisk(t *testing.T) {
	rw, store := newTestRewriter(t)
	body := `Click <a href="https://attack.example/login">here</a> for your prize!`
	out, err := rw.Rewrite(context.Background(), RewriteRequest{
		TenantID:             "t1",
		PseudonymizedMessage: "msg-1",
		Tier:                 constant.TierHighRisk,
		HTMLBody:             body,
	})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if out.RewriteCount != 1 {
		t.Fatalf("expected 1 rewrite, got %d (body=%s)", out.RewriteCount, out.HTMLBody)
	}
	if !strings.Contains(out.HTMLBody, "https://l.sn360.io/") {
		t.Errorf("output missing interstitial prefix:\n%s", out.HTMLBody)
	}
	if strings.Contains(out.HTMLBody, "attack.example") {
		t.Errorf("original URL still present in rewritten body:\n%s", out.HTMLBody)
	}
	if len(store.m) != 1 {
		t.Errorf("expected 1 pre-image stored, got %d", len(store.m))
	}
}

func TestURLRewriterPreservesSkippedSchemes(t *testing.T) {
	rw, _ := newTestRewriter(t)
	body := `<a href="mailto:alice@example.com">mail</a>` +
		`<a href="tel:+1-555-1212">call</a>` +
		`<a href="javascript:void(0)">js</a>` +
		`<a href="#section">anchor</a>` +
		`<a href="/relative/path">rel</a>`
	out, err := rw.Rewrite(context.Background(), RewriteRequest{
		TenantID:             "t1",
		PseudonymizedMessage: "m",
		Tier:                 constant.TierBlocked,
		HTMLBody:             body,
	})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if out.RewriteCount != 0 {
		t.Errorf("no rewrites expected, got %d (body=%s)", out.RewriteCount, out.HTMLBody)
	}
	if out.HTMLBody != body {
		t.Errorf("body should be unchanged:\n%s", out.HTMLBody)
	}
}

func TestURLRewriterMultipleURLs(t *testing.T) {
	rw, _ := newTestRewriter(t)
	body := `<a href="https://a.example/">A</a> <a href='https://b.example/'>B</a>` +
		`<a HREF = "https://c.example/x?y=1">C</a>`
	out, err := rw.Rewrite(context.Background(), RewriteRequest{
		TenantID:             "t1",
		PseudonymizedMessage: "m1",
		Tier:                 constant.TierHighRisk,
		HTMLBody:             body,
	})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if out.RewriteCount != 3 {
		t.Errorf("expected 3 rewrites, got %d (body=%s)", out.RewriteCount, out.HTMLBody)
	}
	if len(out.URLHashes) != 3 {
		t.Errorf("expected 3 hashes, got %d", len(out.URLHashes))
	}
}

func TestURLRewriterResolveRoundTrip(t *testing.T) {
	rw, _ := newTestRewriter(t)
	body := `<a href="https://example.com/important?q=1">Click</a>`
	out, err := rw.Rewrite(context.Background(), RewriteRequest{
		TenantID:             "t1",
		PseudonymizedMessage: "m1",
		Tier:                 constant.TierHighRisk,
		HTMLBody:             body,
	})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	// Extract the token from the rewritten URL.
	idx := strings.Index(out.HTMLBody, "https://l.sn360.io/")
	if idx < 0 {
		t.Fatal("interstitial URL not found")
	}
	rest := out.HTMLBody[idx+len("https://l.sn360.io/"):]
	endQuote := strings.IndexAny(rest, `"'`)
	if endQuote < 0 {
		t.Fatal("could not isolate token")
	}
	token := rest[:endQuote]

	orig, claims, err := rw.Resolve(context.Background(), token)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if orig != "https://example.com/important?q=1" {
		t.Errorf("resolved URL = %s, want original", orig)
	}
	if claims.TenantID != "t1" {
		t.Errorf("tid = %s, want t1", claims.TenantID)
	}
	if claims.Tier != string(constant.TierHighRisk) {
		t.Errorf("tier = %s, want HighRisk", claims.Tier)
	}
}

func TestURLRewriterPreservesQuoteStyle(t *testing.T) {
	rw, _ := newTestRewriter(t)
	bodyDouble := `<a href="https://x.example/">x</a>`
	bodySingle := `<a href='https://y.example/'>y</a>`
	outD, err := rw.Rewrite(context.Background(), RewriteRequest{
		TenantID: "t1", PseudonymizedMessage: "m",
		Tier: constant.TierHighRisk, HTMLBody: bodyDouble,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outD.HTMLBody, `href="https://l.sn360.io/`) {
		t.Errorf("double-quoted href should remain double-quoted: %s", outD.HTMLBody)
	}
	outS, err := rw.Rewrite(context.Background(), RewriteRequest{
		TenantID: "t1", PseudonymizedMessage: "m",
		Tier: constant.TierHighRisk, HTMLBody: bodySingle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outS.HTMLBody, `href='https://l.sn360.io/`) {
		t.Errorf("single-quoted href should remain single-quoted: %s", outS.HTMLBody)
	}
}

func TestURLRewriterRequiresTenantAndMessageIDs(t *testing.T) {
	rw, _ := newTestRewriter(t)
	if _, err := rw.Rewrite(context.Background(), RewriteRequest{
		Tier:     constant.TierHighRisk,
		HTMLBody: `<a href="https://x">x</a>`,
	}); err == nil {
		t.Error("missing tenant should error")
	}
}
