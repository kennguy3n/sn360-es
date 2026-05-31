package privacy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadECDSAPrivateKeyFromFile reads a PEM-encoded ECDSA P-256 private
// key from disk and returns it.
//
// Two PEM block types are accepted, in this priority order:
//
//  1. "PRIVATE KEY" — PKCS#8 (the modern default, produced by
//     `openssl pkcs8 -topk8` or `openssl genpkey -algorithm EC
//     -pkeyopt ec_paramgen_curve:P-256`).
//
//  2. "EC PRIVATE KEY" — SEC 1 (the legacy default, produced by
//     `openssl ecparam -genkey -name prime256v1`).
//
// Other key types and curves are rejected: only ECDSA P-256 is
// permitted, matching the JOSE ES256 algorithm identifier (RFC 7518
// §3.4 — "ECDSA using P-256 and SHA-256"). This means the issuer
// will fail boot loudly if an operator accidentally points
// JWT_PRIVATE_KEY_PATH at an RSA, Ed25519, or P-384 key — that is
// the right failure mode for a security-sensitive config knob.
//
// The function never logs the key material; an empty / unreadable
// file returns a generic wrapping error so logs do not leak path
// information that might reveal mount layouts.
func LoadECDSAPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("privacy/jwt: ECDSA private key path is empty")
	}
	// Filepath.Clean defeats `..` traversal in the env var; we don't
	// permit traversal because production deployments mount the key
	// at a fixed location and the operator either typed the path
	// right or didn't.
	pemBytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("privacy/jwt: read ECDSA private key: %w", err)
	}
	return ParseECDSAPrivateKeyPEM(pemBytes)
}

// ParseECDSAPrivateKeyPEM is the in-memory counterpart of
// LoadECDSAPrivateKeyFromFile. Extracted so tests can stamp a key
// without writing it to /tmp first.
func ParseECDSAPrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("privacy/jwt: ECDSA private key PEM is malformed (no decodable block)")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("privacy/jwt: parse SEC1 EC private key: %w", err)
		}
		return validateP256(key)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("privacy/jwt: parse PKCS#8 private key: %w", err)
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("privacy/jwt: PKCS#8 key is %T, want *ecdsa.PrivateKey", key)
		}
		return validateP256(ec)
	default:
		return nil, fmt.Errorf("privacy/jwt: unsupported PEM block type %q (want PRIVATE KEY or EC PRIVATE KEY)", block.Type)
	}
}

// LoadECDSAPublicKeyFromFile reads a PEM-encoded ECDSA P-256 public
// key from disk. Accepts the standard PKIX "PUBLIC KEY" block type
// produced by `openssl ec -in priv.pem -pubout`.
func LoadECDSAPublicKeyFromFile(path string) (*ecdsa.PublicKey, error) {
	if path == "" {
		return nil, errors.New("privacy/jwt: ECDSA public key path is empty")
	}
	pemBytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("privacy/jwt: read ECDSA public key: %w", err)
	}
	return ParseECDSAPublicKeyPEM(pemBytes)
}

// ParseECDSAPublicKeyPEM is the in-memory counterpart of
// LoadECDSAPublicKeyFromFile.
func ParseECDSAPublicKeyPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("privacy/jwt: ECDSA public key PEM is malformed (no decodable block)")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("privacy/jwt: unsupported PEM block type %q (want PUBLIC KEY)", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("privacy/jwt: parse PKIX public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("privacy/jwt: PKIX public key is %T, want *ecdsa.PublicKey", pub)
	}
	if ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("privacy/jwt: ECDSA public key uses curve %q, want P-256", ec.Curve.Params().Name)
	}
	return ec, nil
}

// validateP256 returns key untouched if it is a P-256 ECDSA key,
// otherwise rejects with a clear error. Centralised so both PEM
// block-type branches enforce the same curve constraint.
func validateP256(key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("privacy/jwt: ECDSA private key uses curve %q, want P-256", key.Curve.Params().Name)
	}
	return key, nil
}
