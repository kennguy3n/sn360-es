package privacy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// Encryptor encrypts and decrypts data with per-tenant Data Encryption
// Keys (DEKs). DEKs are wrapped by a KMS-managed Customer Master Key
// (envelope encryption): the KMSClient holds the CMK, the Encryptor
// caches plaintext DEKs in memory, and at-rest blobs include the
// wrapped DEK alongside the AES-GCM ciphertext.
//
// Blob layout (all little-endian, no spec version yet because the layout
// is internal):
//
//	[2 bytes wrappedLen][wrappedLen bytes wrapped DEK]
//	[12 bytes nonce][ciphertext]
//
// The Encryptor is safe for concurrent use.
type Encryptor interface {
	// Encrypt returns the ciphertext blob for plaintext under tenantID's
	// DEK. The blob is self-contained — Decrypt does not need any other
	// state.
	Encrypt(ctx context.Context, tenantID string, plaintext []byte) (ciphertext []byte, err error)
	// Decrypt returns the plaintext from a ciphertext blob produced by
	// Encrypt under the same tenantID.
	Decrypt(ctx context.Context, tenantID string, ciphertext []byte) (plaintext []byte, err error)
	// Forget removes any cached DEK for tenantID. Combined with
	// KMSClient.ForgetKey, this performs cryptographic erasure.
	Forget(tenantID string)
}

// EncryptorConfig holds the dependencies needed by the default Encryptor.
type EncryptorConfig struct {
	// KMS provides the master key under which per-tenant DEKs are
	// wrapped.
	KMS KMSClient
	// KeyIDFor returns the KMS key ID for a tenant. The default uses
	// "sn360-tenant-<tenantID>" so different tenants always wrap under
	// different CMK aliases.
	KeyIDFor func(tenantID string) string
}

// kmsEncryptor implements Encryptor on top of any KMSClient.
type kmsEncryptor struct {
	kms      KMSClient
	keyIDFor func(string) string

	mu    sync.RWMutex
	cache map[string]cachedKey // tenantID → cached DEK
}

type cachedKey struct {
	dek     []byte
	wrapped []byte
}

// NewEncryptor returns the default envelope encryptor.
func NewEncryptor(cfg EncryptorConfig) (Encryptor, error) {
	if cfg.KMS == nil {
		return nil, errors.New("privacy: encryptor requires a KMSClient")
	}
	if cfg.KeyIDFor == nil {
		cfg.KeyIDFor = func(t string) string { return "sn360-tenant-" + t }
	}
	return &kmsEncryptor{
		kms:      cfg.KMS,
		keyIDFor: cfg.KeyIDFor,
		cache:    make(map[string]cachedKey),
	}, nil
}

// Encrypt encrypts plaintext under tenantID's DEK.
func (e *kmsEncryptor) Encrypt(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error) {
	if tenantID == "" {
		return nil, errors.New("privacy: tenant ID is required")
	}
	dek, wrapped, err := e.dekFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("privacy: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("privacy: cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("privacy: rand: %w", err)
	}
	body := aead.Seal(nil, nonce, plaintext, []byte(tenantID))

	out := make([]byte, 0, 2+len(wrapped)+len(nonce)+len(body))
	wrappedLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(wrappedLen, uint16(len(wrapped)))
	out = append(out, wrappedLen...)
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, body...)
	return out, nil
}

// Decrypt reverses Encrypt.
func (e *kmsEncryptor) Decrypt(ctx context.Context, tenantID string, blob []byte) ([]byte, error) {
	if tenantID == "" {
		return nil, errors.New("privacy: tenant ID is required")
	}
	if len(blob) < 2 {
		return nil, errors.New("privacy: blob too short")
	}
	wrappedLen := int(binary.LittleEndian.Uint16(blob[:2]))
	if len(blob) < 2+wrappedLen+12 {
		return nil, errors.New("privacy: blob length mismatch")
	}
	wrapped := blob[2 : 2+wrappedLen]
	body := blob[2+wrappedLen:]

	dek, err := e.kms.Decrypt(ctx, wrapped)
	if err != nil {
		return nil, fmt.Errorf("privacy: unwrap DEK: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("privacy: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("privacy: cipher.NewGCM: %w", err)
	}
	if len(body) < aead.NonceSize() {
		return nil, errors.New("privacy: body shorter than nonce")
	}
	nonce, ct := body[:aead.NonceSize()], body[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, []byte(tenantID))
	if err != nil {
		return nil, fmt.Errorf("privacy: aead.Open: %w", err)
	}
	return pt, nil
}

// Forget evicts the DEK cache for tenantID. Combined with
// KMSClient.ForgetKey it cryptographically erases the tenant.
func (e *kmsEncryptor) Forget(tenantID string) {
	e.mu.Lock()
	delete(e.cache, tenantID)
	e.mu.Unlock()
}

// dekFor returns the cached or freshly-fetched DEK for a tenant.
func (e *kmsEncryptor) dekFor(ctx context.Context, tenantID string) (plain, wrapped []byte, err error) {
	e.mu.RLock()
	if k, ok := e.cache[tenantID]; ok {
		e.mu.RUnlock()
		return k.dek, k.wrapped, nil
	}
	e.mu.RUnlock()

	keyID := e.keyIDFor(tenantID)
	pt, ct, err := e.kms.GenerateDataKey(ctx, keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("privacy: GenerateDataKey for tenant %q: %w", tenantID, err)
	}

	e.mu.Lock()
	e.cache[tenantID] = cachedKey{dek: pt, wrapped: ct}
	e.mu.Unlock()
	return pt, ct, nil
}
