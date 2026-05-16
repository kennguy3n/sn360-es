package privacy

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestPseudonymizerHashDeterministic(t *testing.T) {
	p := NewPseudonymizer("sn360")
	k := mustKey(t)
	a, err := p.Hash(k, "alice@example.com")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	b, err := p.Hash(k, "alice@example.com")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if a != b {
		t.Fatalf("non-deterministic: %s vs %s", a, b)
	}
	// Case-insensitive + trim.
	c, _ := p.Hash(k, "  ALICE@example.com  ")
	if a != c {
		t.Fatalf("hash not case/whitespace-insensitive: %s vs %s", a, c)
	}
}

func TestPseudonymizerDifferentKeysProduceDifferentHashes(t *testing.T) {
	p := NewPseudonymizer("")
	k1, k2 := mustKey(t), mustKey(t)
	a, _ := p.Hash(k1, "alice@example.com")
	b, _ := p.Hash(k2, "alice@example.com")
	if a == b {
		t.Fatal("two distinct tenant keys should produce distinct hashes")
	}
}

func TestPseudonymizerRejectsBadKey(t *testing.T) {
	p := NewPseudonymizer("")
	if _, err := p.Hash(nil, "x"); !errors.Is(err, ErrMissingTenantKey) {
		t.Errorf("expected ErrMissingTenantKey, got %v", err)
	}
	if _, err := p.Hash([]byte("short"), "x"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestPseudonymizerHashOrEmpty(t *testing.T) {
	p := NewPseudonymizer("")
	k := mustKey(t)
	if got := p.HashOrEmpty(k, ""); got != "" {
		t.Errorf("HashOrEmpty(\"\") = %q, want empty", got)
	}
	if got := p.HashOrEmpty(nil, "alice"); got != "" {
		t.Errorf("HashOrEmpty with no key should return empty, got %q", got)
	}
	if got := p.HashOrEmpty(k, "alice"); got == "" {
		t.Error("HashOrEmpty should return a hex pseudonym")
	}
}

func TestPseudonymizeStruct(t *testing.T) {
	type User struct {
		Email    string `privacy:"pii"`
		Display  string
		Nested   *User
		Friends  []*User
		ByDomain map[string]User
	}
	k := mustKey(t)
	u := &User{
		Email:   "alice@example.com",
		Display: "Alice",
		Nested:  &User{Email: "bob@example.com"},
		Friends: []*User{{Email: "carol@example.com"}},
		ByDomain: map[string]User{
			"example.com": {Email: "dave@example.com"},
		},
	}
	if err := NewPseudonymizer("").Pseudonymize(k, u); err != nil {
		t.Fatalf("pseudonymize: %v", err)
	}
	if u.Email == "alice@example.com" {
		t.Error("Email should have been hashed")
	}
	if u.Display != "Alice" {
		t.Errorf("Display should not change: %s", u.Display)
	}
	if u.Nested == nil || u.Nested.Email == "bob@example.com" {
		t.Error("Nested.Email should have been hashed")
	}
	if u.Friends[0].Email == "carol@example.com" {
		t.Error("Friends[0].Email should have been hashed")
	}
	if v, ok := u.ByDomain["example.com"]; !ok || v.Email == "dave@example.com" {
		t.Error("ByDomain[example.com].Email should have been hashed")
	}
}

func TestPseudonymizeRejectsMissingKey(t *testing.T) {
	type User struct {
		Email string `privacy:"pii"`
	}
	if err := NewPseudonymizer("").Pseudonymize(nil, &User{Email: "x"}); !errors.Is(err, ErrMissingTenantKey) {
		t.Errorf("expected ErrMissingTenantKey, got %v", err)
	}
}

func TestPseudonymizerHashOutputLength(t *testing.T) {
	p := NewPseudonymizer("")
	k := mustKey(t)
	out, err := p.Hash(k, "alice")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// blake2b-256 hex = 64 characters
	if len(out) != 64 {
		t.Errorf("expected 64-char hex output, got %d chars: %s", len(out), out)
	}
	// And it must be hex (no high-bit bytes).
	if bytes.ContainsAny([]byte(out), "ghijklmnopqrstuvwxyz") {
		t.Errorf("output contains non-hex characters: %s", out)
	}
}
