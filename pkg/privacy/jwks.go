package privacy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// JWK is the RFC 7517 JSON Web Key representation of a single public
// key. Only the fields required to verify an ES256 token are exposed:
//
//   - kty: key type — always "EC" for ECDSA keys.
//   - crv: curve — always "P-256" for the ES256 algorithm.
//   - x, y: base64url-encoded affine coordinates of the public point.
//   - kid: optional key identifier; consumers use it to select the
//     correct key when the JWKS contains multiple entries.
//   - use: optional key-use parameter (RFC 7517 §4.2); we always emit
//     "sig" because every key we publish is for signature
//     verification.
//   - alg: optional algorithm parameter (RFC 7517 §4.4); we always
//     emit "ES256" so the consumer doesn't have to infer it from
//     (kty, crv).
//
// Other JWK fields (key_ops, x5*) are intentionally not emitted.
// Their absence is the right default: key_ops is redundant when use
// is set, and x5* would imply we are publishing a certificate chain,
// which we are not.
type JWK struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
	KeyID     string `json:"kid,omitempty"`
	Use       string `json:"use,omitempty"`
	Algorithm string `json:"alg,omitempty"`
}

// JWKS is the RFC 7517 JSON Web Key Set — the wire shape served at
// /.well-known/jwks.json. A JWKS may contain multiple keys to
// support rotation: during a key roll, the JWKS publishes both the
// new and the old key for the duration of the maximum token TTL so
// tokens issued under the old key can still be verified by clients
// that have already refreshed.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// MarshalJSON keeps the JWKS body deterministic — `json.Marshal`
// already preserves struct-field order, so this is mostly a hook
// for future extension (e.g. enforcing a stable key ordering during
// rotation). Today it just delegates to the default encoder.
func (s JWKS) MarshalJSON() ([]byte, error) {
	type alias JWKS
	return json.Marshal(alias(s))
}

// JWKFromECDSAPublicKey converts an ECDSA P-256 public key into a
// JWK ready to publish. Other curves are rejected because the ES256
// algorithm we use is bound to P-256 (RFC 7518 §3.4).
//
// The kid argument is optional. When empty, the function derives a
// stable thumbprint per RFC 7638 §3 — the SHA-256 hash of the JSON
// representation of the minimal JWK (kty, crv, x, y in lex order),
// base64url-encoded. This makes kid stable across process restarts
// and across replicas of the same deployment, so clients can cache
// it safely.
//
// The use and alg fields are always set to "sig" / "ES256" because
// this package only publishes signing keys for ES256. Adding RS256
// or Ed25519 support later would require a parallel constructor.
func JWKFromECDSAPublicKey(pub *ecdsa.PublicKey, kid string) (JWK, error) {
	if pub == nil {
		return JWK{}, errors.New("privacy/jwks: nil public key")
	}
	if pub.Curve == nil || pub.Curve.Params().Name != "P-256" {
		return JWK{}, fmt.Errorf("privacy/jwks: unsupported curve %q (want P-256)", curveName(pub))
	}

	// P-256 coordinates are exactly 32 bytes when left-padded — the
	// JWK encoding (RFC 7518 §6.2.1.2) mandates this fixed length,
	// so we must NOT use the variable-length math/big representation.
	xBytes := leftPadBytes(pub.X.Bytes(), 32)
	yBytes := leftPadBytes(pub.Y.Bytes(), 32)

	jwk := JWK{
		KeyType:   "EC",
		Curve:     "P-256",
		X:         base64.RawURLEncoding.EncodeToString(xBytes),
		Y:         base64.RawURLEncoding.EncodeToString(yBytes),
		Use:       "sig",
		Algorithm: "ES256",
	}
	if kid != "" {
		jwk.KeyID = kid
	} else {
		jwk.KeyID = jwk.Thumbprint()
	}
	return jwk, nil
}

// Thumbprint computes the RFC 7638 JWK Thumbprint of this key. The
// thumbprint is the base64url-encoded SHA-256 of the canonical JSON
// representation of the JWK's required members in lexicographic
// order — for an EC key these are crv, kty, x, y.
//
// The thumbprint is stable: any two parties that derive a JWK from
// the same public key will get the same kid, which makes it the
// canonical key identifier for clients that need to pin a specific
// key across rotations.
func (j JWK) Thumbprint() string {
	// Use the encoding/json encoder (with HTML escaping disabled) on
	// a struct whose field order matches the RFC 7638-required
	// lexicographic ordering of an EC JWK's mandatory members
	// (crv, kty, x, y). json.Marshal escapes strings per the JSON
	// spec, so any future extension to non-ASCII metadata produces
	// interoperable thumbprints — earlier code used fmt.Sprintf
	// with %q, whose Go-escape rules diverge from JSON for
	// characters such as \x.. and embedded NULs. The Encoder also
	// strips no whitespace by default, matching RFC 7638's "no
	// whitespace and no line breaks" requirement.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Encode the four mandatory members in lexicographic order on
	// the JSON name. The struct-tag ordering is authoritative for
	// Go's json package, so an EC-only payload is produced here;
	// extending to RSA/OKP would require a sibling helper.
	_ = enc.Encode(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{
		Crv: j.Curve,
		Kty: j.KeyType,
		X:   j.X,
		Y:   j.Y,
	})
	// json.Encoder.Encode appends a trailing newline. RFC 7638
	// requires the hash input be the canonical JSON with no
	// trailing whitespace, so we trim it.
	canonical := bytes.TrimRight(buf.Bytes(), "\n")
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// leftPadBytes returns b left-padded with zero bytes to the requested
// length. Used to enforce the fixed-width encoding required by RFC
// 7518 §6.2.1.2 for EC key coordinates — math/big's Bytes() strips
// leading zeros, which would yield a 31-byte (or shorter) coordinate
// roughly 1/256 of the time and produce a JWK that other libraries
// fail to verify against. If b is already at least the requested
// length, it is returned unchanged.
func leftPadBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// curveName returns the curve name of pub for use in error
// messages, returning "<nil>" when pub or its curve is nil.
func curveName(pub *ecdsa.PublicKey) string {
	if pub == nil || pub.Curve == nil {
		return "<nil>"
	}
	return pub.Curve.Params().Name
}
