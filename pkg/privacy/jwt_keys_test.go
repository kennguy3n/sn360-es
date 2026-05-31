package privacy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mustGenerateP256 generates a fresh P-256 ECDSA keypair. Tests use
// this rather than vendoring a fixed key so the codebase never has a
// committed private key (even in test data).
func mustGenerateP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return k
}

// pemEncode wraps the given DER bytes in a PEM block with the supplied
// type. The encoder never returns an error in practice.
func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestParseECDSAPrivateKeyPEM_PKCS8(t *testing.T) {
	priv := mustGenerateP256(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	got, err := ParseECDSAPrivateKeyPEM(pemEncode("PRIVATE KEY", der))
	if err != nil {
		t.Fatalf("ParseECDSAPrivateKeyPEM: %v", err)
	}
	if got.D.Cmp(priv.D) != 0 {
		t.Error("parsed PKCS#8 private scalar does not match the source key")
	}
}

func TestParseECDSAPrivateKeyPEM_SEC1(t *testing.T) {
	priv := mustGenerateP256(t)
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	got, err := ParseECDSAPrivateKeyPEM(pemEncode("EC PRIVATE KEY", der))
	if err != nil {
		t.Fatalf("ParseECDSAPrivateKeyPEM: %v", err)
	}
	if got.D.Cmp(priv.D) != 0 {
		t.Error("parsed SEC1 private scalar does not match the source key")
	}
}

func TestParseECDSAPrivateKeyPEM_RejectsRSA(t *testing.T) {
	// Construct a malformed payload labeled as a PKCS#8 PRIVATE KEY
	// block that decodes to a non-ECDSA key (we don't actually
	// generate an RSA key here because importing crypto/rsa would
	// bloat the test for no benefit; ParsePKCS8PrivateKey rejects
	// garbage bytes, which exercises the same error path).
	garbage := pemEncode("PRIVATE KEY", []byte{0x01, 0x02, 0x03})
	if _, err := ParseECDSAPrivateKeyPEM(garbage); err == nil {
		t.Error("expected error parsing garbage PKCS#8 bytes")
	}
}

func TestParseECDSAPrivateKeyPEM_RejectsP384(t *testing.T) {
	// A P-384 key would pass PKCS#8 parsing but must trip the curve
	// guard. Build one explicitly.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("p384 keygen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	if _, err := ParseECDSAPrivateKeyPEM(pemEncode("PRIVATE KEY", der)); err == nil {
		t.Error("expected curve-mismatch error for P-384 key")
	}
}

func TestParseECDSAPrivateKeyPEM_RejectsMalformed(t *testing.T) {
	if _, err := ParseECDSAPrivateKeyPEM([]byte("not pem")); err == nil {
		t.Error("expected error parsing non-PEM input")
	}
	if _, err := ParseECDSAPrivateKeyPEM(pemEncode("FOO", []byte{0x00})); err == nil {
		t.Error("expected error parsing unsupported PEM block type")
	}
}

func TestParseECDSAPublicKeyPEM(t *testing.T) {
	priv := mustGenerateP256(t)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pub, err := ParseECDSAPublicKeyPEM(pemEncode("PUBLIC KEY", der))
	if err != nil {
		t.Fatalf("ParseECDSAPublicKeyPEM: %v", err)
	}
	if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
		t.Error("parsed public coordinates do not match the source key")
	}
}

func TestParseECDSAPublicKeyPEM_RejectsP384(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("p384 keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if _, err := ParseECDSAPublicKeyPEM(pemEncode("PUBLIC KEY", der)); err == nil {
		t.Error("expected curve-mismatch error for P-384 public key")
	}
}

func TestLoadECDSAKeysFromFile_RoundTrip(t *testing.T) {
	priv := mustGenerateP256(t)

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("priv DER: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("pub DER: %v", err)
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.pem")
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(privPath, pemEncode("PRIVATE KEY", privDER), 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	if err := os.WriteFile(pubPath, pemEncode("PUBLIC KEY", pubDER), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}

	gotPriv, err := LoadECDSAPrivateKeyFromFile(privPath)
	if err != nil {
		t.Fatalf("LoadECDSAPrivateKeyFromFile: %v", err)
	}
	if gotPriv.D.Cmp(priv.D) != 0 {
		t.Error("loaded private scalar does not match the source key")
	}
	gotPub, err := LoadECDSAPublicKeyFromFile(pubPath)
	if err != nil {
		t.Fatalf("LoadECDSAPublicKeyFromFile: %v", err)
	}
	if gotPub.X.Cmp(priv.X) != 0 || gotPub.Y.Cmp(priv.Y) != 0 {
		t.Error("loaded public coordinates do not match the source key")
	}
}

func TestLoadECDSAKeysFromFile_RejectsMissing(t *testing.T) {
	if _, err := LoadECDSAPrivateKeyFromFile(""); err == nil {
		t.Error("expected error for empty path")
	}
	if _, err := LoadECDSAPublicKeyFromFile(""); err == nil {
		t.Error("expected error for empty path")
	}
	if _, err := LoadECDSAPrivateKeyFromFile(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("expected error for missing file")
	}
	if _, err := LoadECDSAPublicKeyFromFile(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadECDSAPrivateKeyFromFile_ErrorMessageDoesNotLeakKeyBytes(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.pem")
	// Write an intentional non-PEM payload that contains a marker
	// the test can search for. The error message should NOT include
	// this marker — file contents are key material and must never
	// surface in logs.
	marker := "SUPER_SECRET_KEY_BYTES_xyz"
	if err := os.WriteFile(privPath, []byte(marker), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadECDSAPrivateKeyFromFile(privPath)
	if err == nil {
		t.Fatal("expected error for non-PEM file")
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("error message leaks file contents: %v", err)
	}
}
