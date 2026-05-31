package privacy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func TestJWKFromECDSAPublicKey_ShapeAndFields(t *testing.T) {
	priv := mustGenerateP256(t)
	jwk, err := JWKFromECDSAPublicKey(&priv.PublicKey, "my-kid-1")
	if err != nil {
		t.Fatalf("JWKFromECDSAPublicKey: %v", err)
	}
	if jwk.KeyType != "EC" {
		t.Errorf("kty = %q, want EC", jwk.KeyType)
	}
	if jwk.Curve != "P-256" {
		t.Errorf("crv = %q, want P-256", jwk.Curve)
	}
	if jwk.Use != "sig" {
		t.Errorf("use = %q, want sig", jwk.Use)
	}
	if jwk.Algorithm != "ES256" {
		t.Errorf("alg = %q, want ES256", jwk.Algorithm)
	}
	if jwk.KeyID != "my-kid-1" {
		t.Errorf("kid = %q, want my-kid-1", jwk.KeyID)
	}

	// x and y must decode to exactly 32 bytes each (RFC 7518 §6.2.1.2).
	for name, enc := range map[string]string{"x": jwk.X, "y": jwk.Y} {
		raw, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			t.Errorf("%s not base64url: %v", name, err)
			continue
		}
		if len(raw) != 32 {
			t.Errorf("%s length = %d, want 32", name, len(raw))
		}
	}
}

func TestJWKFromECDSAPublicKey_RejectsNilAndWrongCurve(t *testing.T) {
	if _, err := JWKFromECDSAPublicKey(nil, ""); err == nil {
		t.Error("expected error for nil key")
	}
	wrong := &ecdsa.PublicKey{Curve: elliptic.P384()}
	if _, err := JWKFromECDSAPublicKey(wrong, ""); err == nil {
		t.Error("expected error for P-384 key")
	}
}

// TestJWKFromECDSAPublicKey_DefaultsKidToThumbprint pins the contract
// that an empty kid falls back to the RFC 7638 thumbprint of the key.
// This is the property JWKS-pinning consumers rely on for stable kid
// across rotations.
func TestJWKFromECDSAPublicKey_DefaultsKidToThumbprint(t *testing.T) {
	priv := mustGenerateP256(t)
	jwk, err := JWKFromECDSAPublicKey(&priv.PublicKey, "")
	if err != nil {
		t.Fatalf("JWKFromECDSAPublicKey: %v", err)
	}
	if jwk.KeyID == "" {
		t.Fatal("default kid is empty; expected RFC 7638 thumbprint")
	}
	if jwk.KeyID != jwk.Thumbprint() {
		t.Errorf("default kid = %q, want thumbprint %q", jwk.KeyID, jwk.Thumbprint())
	}
}

// TestJWKThumbprint_StableAcrossInstances ensures any two JWKs derived
// from the same public key produce the same thumbprint.
func TestJWKThumbprint_StableAcrossInstances(t *testing.T) {
	priv := mustGenerateP256(t)
	a, err := JWKFromECDSAPublicKey(&priv.PublicKey, "")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := JWKFromECDSAPublicKey(&priv.PublicKey, "ignored-kid-override")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a.Thumbprint() != b.Thumbprint() {
		t.Errorf("thumbprint mismatch on same key: %q vs %q",
			a.Thumbprint(), b.Thumbprint())
	}
}

// TestJWKThumbprint_RFC7638CanonicalForm pins the RFC 7638 §3.1
// canonical-JSON shape used as the SHA-256 input. The expected hash
// is computed from the canonical bytes
//
//	{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}
//
// (members in lexicographic order, no whitespace, no escaping
// beyond JSON minimum). We compute the same hash here so the test
// can also assert that the implementation produces THIS exact
// canonical form — not a Go-quoted near-miss. Synthetic but
// well-formed x/y values are used so the assertion is independent
// of which curve.Point happens to be picked at random.
func TestJWKThumbprint_RFC7638CanonicalForm(t *testing.T) {
	jwk := JWK{
		KeyType: "EC",
		Curve:   "P-256",
		// 32-byte all-zero coordinates encoded as base64url
		// (43 chars). Their semantic invalidity as an ECDSA
		// point is irrelevant — Thumbprint() does not interpret
		// the coordinates, only encodes them.
		X: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Y: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	canonical := []byte(`{"crv":"P-256","kty":"EC","x":"` + jwk.X + `","y":"` + jwk.Y + `"}`)
	expectedHash := sha256.Sum256(canonical)
	expected := base64.RawURLEncoding.EncodeToString(expectedHash[:])
	if got := jwk.Thumbprint(); got != expected {
		t.Fatalf("thumbprint does not match canonical RFC 7638 form:\n  got      %q\n  expected %q\n  canonical input was %q",
			got, expected, canonical)
	}
}

// TestJWKShortCoordinateGetsLeftPadded pins the leftPadBytes guard.
// math/big.Int.Bytes() strips leading zeros, so a coordinate whose
// MSB happens to be 0x00 would encode to 31 bytes without padding.
// We synthesize such a coordinate explicitly here.
func TestJWKShortCoordinateGetsLeftPadded(t *testing.T) {
	// Construct a fake public key whose X coordinate is a small
	// number (one byte). The Curve check inside
	// JWKFromECDSAPublicKey only inspects Curve.Params().Name, so
	// we can use the real P-256 curve while keeping the X scalar
	// tiny. We do NOT pass this through ecdsa.Verify; the test is
	// purely about encoding length.
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0x01),
		Y:     big.NewInt(0x02),
	}
	jwk, err := JWKFromECDSAPublicKey(pub, "test")
	if err != nil {
		t.Fatalf("JWKFromECDSAPublicKey: %v", err)
	}
	xb, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	yb, _ := base64.RawURLEncoding.DecodeString(jwk.Y)
	if len(xb) != 32 || len(yb) != 32 {
		t.Errorf("padded lengths = (%d, %d), want (32, 32)", len(xb), len(yb))
	}
	if xb[31] != 0x01 || yb[31] != 0x02 {
		t.Errorf("padded coordinates lost source bytes: x=%x y=%x", xb, yb)
	}
}

func TestJWKSMarshalJSON_EmitsKeysArray(t *testing.T) {
	priv := mustGenerateP256(t)
	jwk, err := JWKFromECDSAPublicKey(&priv.PublicKey, "k1")
	if err != nil {
		t.Fatalf("jwk: %v", err)
	}
	out, err := json.Marshal(JWKS{Keys: []JWK{jwk}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundTrip struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(out, &roundTrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(roundTrip.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(roundTrip.Keys))
	}
	for _, mustHave := range []string{"kty", "crv", "x", "y", "kid", "use", "alg"} {
		if _, ok := roundTrip.Keys[0][mustHave]; !ok {
			t.Errorf("JWK missing field %q", mustHave)
		}
	}
}
