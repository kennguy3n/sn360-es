package webhook

import (
	"bytes"
	"strings"
	"testing"
)

// TestSign_RFC4231_TestCase1 anchors the HMAC-SHA256 implementation
// to an RFC 4231 published test vector so a future change to the
// signer can't silently break the customer-side verifier.
//
// Vector source: RFC 4231 §4.2 ("Test Case 1").
//
//	Key:    0x0b * 20
//	Data:   "Hi There"
//	Expected MAC (hex):
//	  b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
func TestSign_RFC4231_TestCase1(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x0b}, 20)
	body := []byte("Hi There")
	const want = "sha256=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	got, err := Sign(key, body)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got != want {
		t.Fatalf("Sign(RFC4231 TC1) = %q; want %q", got, want)
	}
}

// TestSign_EmptyBody covers the corner case of a 0-byte payload —
// e.g. the dispatcher's preflight ping, where the receiver expects
// a valid HMAC over an empty body.
func TestSign_EmptyBody(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0xaa}, SecretBytes)
	body := []byte{}
	got, err := Sign(key, body)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.HasPrefix(got, "sha256=") {
		t.Fatalf("Sign result missing sha256= prefix: %q", got)
	}
	if len(got) != len("sha256=")+64 {
		t.Fatalf("Sign(empty) length = %d; want %d (sha256= + 64 hex chars)",
			len(got), len("sha256=")+64)
	}
	// Sanity-check by re-verifying.
	if !Verify(key, body, got) {
		t.Fatalf("Verify failed to round-trip Sign(empty) output")
	}
}

// TestSign_RejectsEmptySecret ensures the signer fails closed when
// the caller has not unsealed the per-sink secret yet. The
// dispatcher relies on this to prevent an empty-key signature from
// being posted to the customer.
func TestSign_RejectsEmptySecret(t *testing.T) {
	t.Parallel()
	if _, err := Sign(nil, []byte("body")); err == nil {
		t.Fatalf("Sign(nil-secret) succeeded; want error")
	}
	if _, err := Sign([]byte{}, []byte("body")); err == nil {
		t.Fatalf("Sign(empty-secret) succeeded; want error")
	}
}

// TestVerify_ConstantTimeOnPrefixedHeader cross-checks that Verify
// accepts the canonical sha256=<hex> shape, rejects anything else
// (including the same MAC without the prefix), and round-trips
// Sign output.
func TestVerify_ConstantTimeOnPrefixedHeader(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, SecretBytes)
	body := []byte("payload-payload-payload")
	sig, err := Sign(key, body)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(key, body, sig) {
		t.Errorf("Verify(sign output) = false; want true")
	}
	// Tampered body: verify fails.
	if Verify(key, []byte("payload-payload-payload!"), sig) {
		t.Errorf("Verify accepted tampered body; want false")
	}
	// Wrong key: verify fails.
	if Verify(bytes.Repeat([]byte{0x99}, SecretBytes), body, sig) {
		t.Errorf("Verify accepted wrong key; want false")
	}
	// Missing prefix: verify fails (raw hex is not a valid header value).
	raw := strings.TrimPrefix(sig, "sha256=")
	if Verify(key, body, raw) {
		t.Errorf("Verify accepted bare hex (no sha256= prefix); want false")
	}
	// Empty header: verify fails.
	if Verify(key, body, "") {
		t.Errorf("Verify accepted empty header; want false")
	}
	// Non-hex content after prefix: verify fails.
	if Verify(key, body, "sha256=notahex") {
		t.Errorf("Verify accepted non-hex value; want false")
	}
}

// TestGenerateSecret_LengthAndUniqueness validates the secret
// generator's interface contract: 32-byte output and overwhelmingly
// likely uniqueness across calls.
func TestGenerateSecret_LengthAndUniqueness(t *testing.T) {
	t.Parallel()
	const n = 16
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		s, err := GenerateSecret()
		if err != nil {
			t.Fatalf("GenerateSecret: %v", err)
		}
		if len(s) != SecretBytes {
			t.Fatalf("GenerateSecret length = %d; want %d", len(s), SecretBytes)
		}
		key := string(s)
		if _, dup := seen[key]; dup {
			t.Fatalf("GenerateSecret collision on iteration %d", i)
		}
		seen[key] = struct{}{}
	}
}
