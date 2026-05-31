package onboarding

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

type testEncryptor struct{}

func (e *testEncryptor) Encrypt(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ 0x42
	}
	return out, nil
}

func (e *testEncryptor) Decrypt(data []byte) ([]byte, error) {
	return e.Encrypt(data) // XOR is its own inverse.
}

func TestPgTokenStore_NewRequiresDB(t *testing.T) {
	_, err := NewPgTokenStore(nil, &testEncryptor{})
	if err == nil {
		t.Error("expected error when db is nil")
	}
}

func TestPgTokenStore_NewRequiresEncryptor(t *testing.T) {
	_, err := NewPgTokenStore(nil, nil)
	if err == nil {
		t.Error("expected error when both db and encryptor are nil")
	}
}

func TestTokenEncryptor_RoundTrip(t *testing.T) {
	enc := &testEncryptor{}

	plaintext := []byte(`{"access_token":"abc","refresh_token":"def","expires_at":"2025-01-01T00:00:00Z"}`)
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(ciphertext) == string(plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}
	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

// memoryTokenStore provides a simple in-memory TokenStore for unit tests.
type memoryTokenStore struct {
	tokens map[string]Token
}

func newMemoryTokenStore() *memoryTokenStore {
	return &memoryTokenStore{tokens: make(map[string]Token)}
}

func (m *memoryTokenStore) Save(_ context.Context, tenantID string, provider ProviderType, tok Token) error {
	m.tokens[tenantID+"|"+string(provider)] = tok
	return nil
}

func (m *memoryTokenStore) Load(_ context.Context, tenantID string, provider ProviderType) (Token, error) {
	tok, ok := m.tokens[tenantID+"|"+string(provider)]
	if !ok {
		return Token{}, fmt.Errorf("token not found for %s/%s", tenantID, provider)
	}
	return tok, nil
}

func (m *memoryTokenStore) Delete(_ context.Context, tenantID string, provider ProviderType) error {
	delete(m.tokens, tenantID+"|"+string(provider))
	return nil
}

func TestMemoryTokenStore_SaveLoadDelete(t *testing.T) {
	store := newMemoryTokenStore()
	ctx := context.Background()

	tok := Token{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	if err := store.Save(ctx, "tenant-1", ProviderGoogle, tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load(ctx, "tenant-1", ProviderGoogle)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken = %q, want %q", loaded.AccessToken, tok.AccessToken)
	}
	if loaded.RefreshToken != tok.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", loaded.RefreshToken, tok.RefreshToken)
	}

	_, err = store.Load(ctx, "tenant-1", ProviderMicrosoft)
	if err == nil {
		t.Error("expected error for non-existent provider, got nil")
	}

	if err := store.Delete(ctx, "tenant-1", ProviderGoogle); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = store.Load(ctx, "tenant-1", ProviderGoogle)
	if err == nil {
		t.Error("expected error after Delete, got nil")
	}
}

func TestStoredTokenRef(t *testing.T) {
	ref := StoredTokenRef{TenantID: "t1", Provider: "google_workspace"}
	if ref.TenantID != "t1" {
		t.Errorf("TenantID = %q, want %q", ref.TenantID, "t1")
	}
	if ref.Provider != "google_workspace" {
		t.Errorf("Provider = %q, want %q", ref.Provider, "google_workspace")
	}
}

// TestPgTokenStore_RejectsEmptyTenantID asserts the tenant-id
// validation Save / Load / Delete share via the bindTenantIfNeeded
// helper. The helper would otherwise call WithTenant with an empty
// string, which postgres.DB.WithTenant rejects explicitly — but the
// caller-facing error message becomes "postgres: WithTenant: tenantID
// is empty" which loses the onboarding-layer signal. Validating up
// front returns the same `tenant_id is required` shape callers
// already handle.
func TestPgTokenStore_RejectsEmptyTenantID(t *testing.T) {
	// db can be nil here because the empty-tenant validation runs
	// before any db method is touched — Save / Load / Delete each
	// early-return on the empty tenantID check.
	s := &PgTokenStore{db: nil, encryptor: &testEncryptor{}}
	ctx := context.Background()

	if err := s.Save(ctx, "", ProviderGoogle, Token{}); err == nil {
		t.Error("Save with empty tenantID must error")
	}
	if _, err := s.Load(ctx, "", ProviderGoogle); err == nil {
		t.Error("Load with empty tenantID must error")
	}
	if err := s.Delete(ctx, "", ProviderGoogle); err == nil {
		t.Error("Delete with empty tenantID must error")
	}
}

// TestPgTokenStore_ListAll_RejectsBoundCtx asserts the defensive
// guard added in response to Devin Review on PR #50. ListAll is
// genuinely cross-tenant — it returns rows for every tenant — and
// it MUST NOT be called from a ctx that already pins a per-tenant
// bound conn. Two failure modes the guard prevents:
//
//  1. Resource leak / latent deadlock — acquiring a fresh conn via
//     WithCrossTenant while the caller's conn is still pinned holds
//     two pool slots simultaneously. Under MaxOpenConns=1 (test
//     harnesses, low-tier deployments) this deadlocks: the second
//     acquire blocks waiting for the conn that only the calling
//     goroutine can release.
//
//  2. Semantic confusion — calling a cross-tenant function from
//     inside a single-tenant scope is a category error; the row set
//     the caller gets back has nothing to do with the binding they
//     thought they were operating under.
//
// We seed ctx with a sentinel *sql.Conn (the value never gets used
// for SQL — the guard short-circuits before any conn methods run)
// and assert the error mentions both "ListAll" and "bound conn" so
// future regressions are caught with a high-signal failure mode.
func TestPgTokenStore_ListAll_RejectsBoundCtx(t *testing.T) {
	s := &PgTokenStore{db: nil, encryptor: &testEncryptor{}}
	// The guard inspects postgres.BoundConnFromContext(ctx) and
	// returns immediately on a non-nil conn — the conn is never
	// dereferenced. A bare (*sql.Conn)(nil) typed as *sql.Conn
	// would be nil-equivalent for the guard, so we use a heap
	// address via new() to ensure BoundConnFromContext returns
	// non-nil. This is the same trick the integration test in
	// pkg/storage/postgres uses; it does not bind a real Postgres
	// session because we are testing the GUARD, not the query.
	ctx := postgres.WithBoundConn(context.Background(), new(sql.Conn))
	_, err := s.ListAll(ctx)
	if err == nil {
		t.Fatal("ListAll under a bound ctx must error; got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ListAll") {
		t.Errorf("error message %q does not mention ListAll", msg)
	}
	if !strings.Contains(msg, "bound conn") {
		t.Errorf("error message %q does not explain the bound-conn precondition", msg)
	}
}
