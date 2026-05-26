package onboarding

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeTokenStore struct {
	mu      sync.Mutex
	tokens  map[string]Token
	saveErr error
	loadErr error
	delErr  error
}

func newFakeTokenStore() *fakeTokenStore {
	return &fakeTokenStore{tokens: map[string]Token{}}
}

func key(tenantID string, p ProviderType) string {
	return tenantID + ":" + string(p)
}

func (s *fakeTokenStore) Save(_ context.Context, tenantID string, p ProviderType, tok Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.tokens[key(tenantID, p)] = tok
	return nil
}

func (s *fakeTokenStore) Load(_ context.Context, tenantID string, p ProviderType) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return Token{}, s.loadErr
	}
	tok, ok := s.tokens[key(tenantID, p)]
	if !ok {
		return Token{}, errors.New("not found")
	}
	return tok, nil
}

func (s *fakeTokenStore) Delete(_ context.Context, tenantID string, p ProviderType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.delErr != nil {
		return s.delErr
	}
	delete(s.tokens, key(tenantID, p))
	return nil
}

type fakeExchanger struct {
	exchToken    Token
	exchErr      error
	refreshToken Token
	refreshErr   error
	exchCalls    int
	refreshCalls int
}

func (f *fakeExchanger) ExchangeCode(_ context.Context, _ ProviderConfig, _ string) (Token, error) {
	f.exchCalls++
	return f.exchToken, f.exchErr
}

func (f *fakeExchanger) RefreshToken(_ context.Context, _ ProviderConfig, _ string) (Token, error) {
	f.refreshCalls++
	return f.refreshToken, f.refreshErr
}

type fakeTrigger struct {
	calls    int
	tenantID string
	provider ProviderType
	err      error
}

func (t *fakeTrigger) StartOnboarding(_ context.Context, tenantID string, provider ProviderType) error {
	t.calls++
	t.tenantID = tenantID
	t.provider = provider
	return t.err
}

func googleConfig() ProviderConfig {
	return ProviderConfig{
		ClientID:     "cid",
		ClientSecret: "csec",
		AuthURL:      "https://accounts.example.com/auth",
		TokenURL:     "https://oauth2.example.com/token",
		Scopes:       []string{"a", "b"},
		RedirectURL:  "https://app/cb",
	}
}

func TestProviderConfig_Validate(t *testing.T) {
	if err := googleConfig().Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	cases := []ProviderConfig{
		{ClientID: "", ClientSecret: "x", AuthURL: "a", TokenURL: "t", RedirectURL: "r", Scopes: []string{"s"}},
		{ClientID: "c", ClientSecret: "", AuthURL: "a", TokenURL: "t", RedirectURL: "r", Scopes: []string{"s"}},
		{ClientID: "c", ClientSecret: "x", AuthURL: "", TokenURL: "t", RedirectURL: "r", Scopes: []string{"s"}},
		{ClientID: "c", ClientSecret: "x", AuthURL: "a", TokenURL: "", RedirectURL: "r", Scopes: []string{"s"}},
		{ClientID: "c", ClientSecret: "x", AuthURL: "a", TokenURL: "t", RedirectURL: "", Scopes: []string{"s"}},
		{ClientID: "c", ClientSecret: "x", AuthURL: "a", TokenURL: "t", RedirectURL: "r"},
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}

func TestToken_IsExpired(t *testing.T) {
	if (Token{}).IsExpired() {
		t.Fatal("zero ExpiresAt should not be expired")
	}
	if !(Token{ExpiresAt: time.Now().Add(-time.Hour)}).IsExpired() {
		t.Fatal("past token should be expired")
	}
	// Within 60-second skew, treat as expired.
	if !(Token{ExpiresAt: time.Now().Add(30 * time.Second)}).IsExpired() {
		t.Fatal("token within skew should be expired")
	}
	if (Token{ExpiresAt: time.Now().Add(10 * time.Minute)}).IsExpired() {
		t.Fatal("future token should not be expired")
	}
}

func TestStateSigner_RequiresSecret(t *testing.T) {
	if _, err := NewStateSigner([]byte("short")); err == nil {
		t.Fatal("expected error for short secret")
	}
	if _, err := NewStateSigner([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatalf("32-byte secret should be valid: %v", err)
	}
}

func TestStateSigner_RoundTrip(t *testing.T) {
	s, _ := NewStateSigner([]byte("0123456789abcdef"))
	tok, err := s.Sign(StatePayload{TenantID: "acme", Provider: ProviderGoogle})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.Contains(tok, ".") {
		t.Fatalf("token format: %q", tok)
	}
	p, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.TenantID != "acme" || p.Provider != ProviderGoogle {
		t.Fatalf("payload: %+v", p)
	}
	if p.Nonce == "" {
		t.Fatal("Nonce should auto-populate")
	}
	if p.IssuedAt == 0 || p.ExpiresAt == 0 {
		t.Fatalf("timestamps: %+v", p)
	}
}

func TestStateSigner_VerifyRejectsTamper(t *testing.T) {
	s, _ := NewStateSigner([]byte("0123456789abcdef"))
	tok, _ := s.Sign(StatePayload{TenantID: "acme", Provider: ProviderGoogle})

	parts := strings.SplitN(tok, ".", 2)
	tampered := parts[0] + "x." + parts[1]
	if _, err := s.Verify(tampered); err == nil {
		t.Fatal("expected HMAC mismatch")
	}
	if _, err := s.Verify(parts[0]); err == nil {
		t.Fatal("expected format error")
	}
}

func TestStateSigner_VerifyRejectsExpired(t *testing.T) {
	s, _ := NewStateSigner([]byte("0123456789abcdef"))
	tok, _ := s.Sign(StatePayload{
		TenantID:  "acme",
		Provider:  ProviderGoogle,
		IssuedAt:  time.Now().Add(-time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-30 * time.Minute).Unix(),
	})
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestNewService_RequiresDependencies(t *testing.T) {
	signer, _ := NewStateSigner([]byte("0123456789abcdef"))
	cases := []ServiceConfig{
		{},
		{Store: newFakeTokenStore()},
		{Store: newFakeTokenStore(), Exch: &fakeExchanger{}},
		{Store: newFakeTokenStore(), Exch: &fakeExchanger{}, State: signer},
	}
	for i, c := range cases {
		if _, err := NewService(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestNewService_RejectsBadProvider(t *testing.T) {
	signer, _ := NewStateSigner([]byte("0123456789abcdef"))
	bad := googleConfig()
	bad.ClientID = ""
	_, err := NewService(ServiceConfig{
		Providers: map[ProviderType]ProviderConfig{ProviderGoogle: bad},
		Store:     newFakeTokenStore(),
		Exch:      &fakeExchanger{},
		State:     signer,
	})
	if err == nil || !strings.Contains(err.Error(), "client credentials") {
		t.Fatalf("err: %v", err)
	}
}

func newServiceForTest(t *testing.T) (*Service, *fakeTokenStore, *fakeExchanger, *fakeTrigger) {
	t.Helper()
	signer, _ := NewStateSigner([]byte("0123456789abcdef"))
	store := newFakeTokenStore()
	exch := &fakeExchanger{}
	trig := &fakeTrigger{}
	svc, err := NewService(ServiceConfig{
		Providers: map[ProviderType]ProviderConfig{ProviderGoogle: googleConfig()},
		Store:     store,
		Exch:      exch,
		State:     signer,
		Trigger:   trig,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store, exch, trig
}

func TestService_AuthURL_BuildsConsent(t *testing.T) {
	svc, _, _, _ := newServiceForTest(t)
	authURL, err := svc.AuthURL(ProviderGoogle, "acme")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if u.Host == "" {
		t.Fatalf("missing host: %s", authURL)
	}
	q := u.Query()
	if q.Get("client_id") != "cid" {
		t.Fatalf("client_id: %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://app/cb" {
		t.Fatalf("redirect_uri: %q", q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type: %q", q.Get("response_type"))
	}
	if !strings.Contains(q.Get("scope"), "a") || !strings.Contains(q.Get("scope"), "b") {
		t.Fatalf("scope: %q", q.Get("scope"))
	}
	if q.Get("state") == "" {
		t.Fatal("state not set")
	}
}

func TestService_AuthURL_UnknownProvider(t *testing.T) {
	svc, _, _, _ := newServiceForTest(t)
	if _, err := svc.AuthURL("hotmail", "acme"); err == nil {
		t.Fatal("expected unknown-provider error")
	}
}

func TestService_HandleCallback_HappyPath(t *testing.T) {
	svc, store, exch, trig := newServiceForTest(t)
	exch.exchToken = Token{
		AccessToken:  "at",
		RefreshToken: "rt",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	stateTok, _ := svc.state.Sign(StatePayload{TenantID: "acme", Provider: ProviderGoogle})

	tid, prov, err := svc.HandleCallback(context.Background(), stateTok, "auth-code")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if tid != "acme" || prov != ProviderGoogle {
		t.Fatalf("tid=%q prov=%q", tid, prov)
	}
	if exch.exchCalls != 1 {
		t.Fatalf("exchCalls=%d", exch.exchCalls)
	}
	if trig.calls != 1 || trig.tenantID != "acme" {
		t.Fatalf("trigger: %+v", trig)
	}
	if _, ok := store.tokens[key("acme", ProviderGoogle)]; !ok {
		t.Fatalf("token not persisted: %+v", store.tokens)
	}
}

func TestService_HandleCallback_BadState(t *testing.T) {
	svc, _, _, _ := newServiceForTest(t)
	if _, _, err := svc.HandleCallback(context.Background(), "garbage", "c"); err == nil {
		t.Fatal("expected state error")
	}
}

func TestService_HandleCallback_ExchangeFailure(t *testing.T) {
	svc, _, exch, _ := newServiceForTest(t)
	exch.exchErr = errors.New("bad code")
	stateTok, _ := svc.state.Sign(StatePayload{TenantID: "acme", Provider: ProviderGoogle})
	if _, _, err := svc.HandleCallback(context.Background(), stateTok, "x"); err == nil {
		t.Fatal("expected exchange error")
	}
}

func TestService_HandleCallback_PersistFailure(t *testing.T) {
	svc, store, exch, _ := newServiceForTest(t)
	exch.exchToken = Token{AccessToken: "at"}
	store.saveErr = errors.New("kms boom")
	stateTok, _ := svc.state.Sign(StatePayload{TenantID: "acme", Provider: ProviderGoogle})
	if _, _, err := svc.HandleCallback(context.Background(), stateTok, "x"); err == nil {
		t.Fatal("expected persist error")
	}
}

func TestService_HandleCallback_TriggerErrorIsNonFatal(t *testing.T) {
	svc, _, exch, trig := newServiceForTest(t)
	exch.exchToken = Token{AccessToken: "at"}
	trig.err = errors.New("agent down")
	stateTok, _ := svc.state.Sign(StatePayload{TenantID: "acme", Provider: ProviderGoogle})
	if _, _, err := svc.HandleCallback(context.Background(), stateTok, "x"); err != nil {
		t.Fatalf("trigger error should not propagate: %v", err)
	}
}

func TestService_TokenFor_NonExpiredReturnsCached(t *testing.T) {
	svc, store, exch, _ := newServiceForTest(t)
	store.tokens[key("acme", ProviderGoogle)] = Token{
		AccessToken: "fresh",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	tok, err := svc.TokenFor(context.Background(), "acme", ProviderGoogle)
	if err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	if tok.AccessToken != "fresh" {
		t.Fatalf("token: %+v", tok)
	}
	if exch.refreshCalls != 0 {
		t.Fatalf("refreshCalls=%d", exch.refreshCalls)
	}
}

func TestService_TokenFor_ExpiredTriggersRefresh(t *testing.T) {
	svc, store, exch, _ := newServiceForTest(t)
	store.tokens[key("acme", ProviderGoogle)] = Token{
		AccessToken:  "stale",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(-time.Minute),
	}
	exch.refreshToken = Token{
		AccessToken: "rotated",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	tok, err := svc.TokenFor(context.Background(), "acme", ProviderGoogle)
	if err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	if tok.AccessToken != "rotated" {
		t.Fatalf("token: %+v", tok)
	}
	// Refresh token should be preserved when provider doesn't roll it.
	saved := store.tokens[key("acme", ProviderGoogle)]
	if saved.RefreshToken != "rt" {
		t.Fatalf("RefreshToken should be preserved: %+v", saved)
	}
}

func TestService_TokenFor_ExpiredNoRefreshFails(t *testing.T) {
	svc, store, _, _ := newServiceForTest(t)
	store.tokens[key("acme", ProviderGoogle)] = Token{
		AccessToken: "stale",
		ExpiresAt:   time.Now().Add(-time.Minute),
	}
	if _, err := svc.TokenFor(context.Background(), "acme", ProviderGoogle); err == nil {
		t.Fatal("expected error when no refresh token")
	}
}

func TestService_TokenFor_LoadFailure(t *testing.T) {
	svc, store, _, _ := newServiceForTest(t)
	store.loadErr = errors.New("kms boom")
	if _, err := svc.TokenFor(context.Background(), "acme", ProviderGoogle); err == nil {
		t.Fatal("expected load error")
	}
}

func TestService_Revoke_DelegatesToStore(t *testing.T) {
	svc, store, _, _ := newServiceForTest(t)
	store.tokens[key("acme", ProviderGoogle)] = Token{AccessToken: "x"}
	if err := svc.Revoke(context.Background(), "acme", ProviderGoogle); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := store.tokens[key("acme", ProviderGoogle)]; ok {
		t.Fatal("token still present")
	}
}

func zohoConfig() ProviderConfig {
	return ProviderConfig{
		ClientID:     "zcid",
		ClientSecret: "zcsec",
		AuthURL:      "https://accounts.zoho.com/oauth/v2/auth",
		TokenURL:     "https://accounts.zoho.com/oauth/v2/token",
		Scopes:       []string{"ZohoMail.messages.ALL", "ZohoMail.accounts.READ"},
		RedirectURL:  "https://app/cb",
	}
}

// TestService_AuthURL_Zoho_OfflineAccess covers the Zoho-specific
// AuthURL branch: Zoho only issues a refresh token when
// access_type=offline is set on the consent URL, so the service must
// add that parameter.
func TestService_AuthURL_Zoho_OfflineAccess(t *testing.T) {
	signer, _ := NewStateSigner([]byte("0123456789abcdef"))
	svc, err := NewService(ServiceConfig{
		Providers: map[ProviderType]ProviderConfig{ProviderZoho: zohoConfig()},
		Store:     newFakeTokenStore(),
		Exch:      &fakeExchanger{},
		State:     signer,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	authURL, err := svc.AuthURL(ProviderZoho, "acme")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	q := u.Query()
	if q.Get("access_type") != "offline" {
		t.Errorf("Zoho consent URL missing access_type=offline: %q", q.Get("access_type"))
	}
	if q.Get("prompt") != "consent" {
		t.Errorf("Zoho consent URL missing prompt=consent: %q", q.Get("prompt"))
	}
	if q.Get("client_id") != "zcid" {
		t.Errorf("Zoho consent URL client_id = %q", q.Get("client_id"))
	}
}

// TestService_AuthURL_FastmailWorkmail_RejectedAsNonOAuth verifies
// the service rejects AuthURL for the two non-OAuth providers with a
// helpful explanatory error rather than silently producing a bogus
// consent URL.
func TestService_AuthURL_FastmailWorkmail_RejectedAsNonOAuth(t *testing.T) {
	signer, _ := NewStateSigner([]byte("0123456789abcdef"))
	// Providers map keys: even though Fastmail/WorkMail do not run
	// OAuth, ProviderConfig.Validate requires placeholder URLs and
	// scopes; that's all this test cares about.
	stub := ProviderConfig{
		ClientID: "x", ClientSecret: "y",
		AuthURL: "https://example.invalid/", TokenURL: "https://example.invalid/",
		Scopes: []string{"s"}, RedirectURL: "https://app/cb",
	}
	svc, err := NewService(ServiceConfig{
		Providers: map[ProviderType]ProviderConfig{
			ProviderFastmail: stub,
			ProviderWorkmail: stub,
		},
		Store: newFakeTokenStore(),
		Exch:  &fakeExchanger{},
		State: signer,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	for _, p := range []ProviderType{ProviderFastmail, ProviderWorkmail} {
		_, err := svc.AuthURL(p, "acme")
		if err == nil {
			t.Errorf("AuthURL(%q) expected error", p)
			continue
		}
		if !strings.Contains(err.Error(), "not OAuth2") && !strings.Contains(err.Error(), "AWS IAM") {
			t.Errorf("AuthURL(%q) error did not explain non-OAuth nature: %v", p, err)
		}
	}
}
