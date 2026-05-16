package privacy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// KMSClient is the minimal contract the privacy package needs from a KMS
// implementation. AWS KMS, GCP KMS, or a local mock implementation can
// satisfy it. The interface is intentionally narrow: encrypt a Data
// Encryption Key (DEK) with the Customer Master Key (CMK), decrypt an
// encrypted DEK back to plaintext, and generate a fresh DEK.
type KMSClient interface {
	// GenerateDataKey returns a fresh 32-byte plaintext DEK plus its
	// ciphertext under the CMK.
	GenerateDataKey(ctx context.Context, keyID string) (plaintext, ciphertext []byte, err error)
	// Encrypt encrypts arbitrary data under the CMK.
	Encrypt(ctx context.Context, keyID string, plaintext []byte) (ciphertext []byte, err error)
	// Decrypt decrypts ciphertext that was previously produced by Encrypt
	// or GenerateDataKey under the same CMK.
	Decrypt(ctx context.Context, ciphertext []byte) (plaintext []byte, err error)
}

// MockKMS is a fully in-process KMS implementation that uses AES-GCM
// under a fixed root key. It is used by tests and any deployment that
// disables real KMS (e.g. local docker-compose runs).
//
// The mock is deterministic-on-output only when given a deterministic
// rand source; otherwise outputs vary per call which is correct AES-GCM
// behaviour.
type MockKMS struct {
	mu       sync.Mutex
	rootKey  []byte
	aead     cipher.AEAD
	keyStore map[string][]byte // logical key ID → plaintext DEK
}

// NewMockKMS constructs a MockKMS with the given 32-byte root key. If
// rootKey is nil, a random key is generated (test-only — losing it
// means losing every encrypted blob).
func NewMockKMS(rootKey []byte) (*MockKMS, error) {
	if rootKey == nil {
		rootKey = make([]byte, 32)
		if _, err := rand.Read(rootKey); err != nil {
			return nil, fmt.Errorf("privacy: read random root key: %w", err)
		}
	}
	if len(rootKey) != 32 {
		return nil, fmt.Errorf("%w: mock KMS root key must be 32 bytes (got %d)", ErrInvalidKey, len(rootKey))
	}
	block, err := aes.NewCipher(rootKey)
	if err != nil {
		return nil, fmt.Errorf("privacy: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("privacy: cipher.NewGCM: %w", err)
	}
	return &MockKMS{
		rootKey:  rootKey,
		aead:     aead,
		keyStore: make(map[string][]byte),
	}, nil
}

// GenerateDataKey implements KMSClient.
func (m *MockKMS) GenerateDataKey(_ context.Context, keyID string) (plaintext, ciphertext []byte, err error) {
	if keyID == "" {
		return nil, nil, errors.New("privacy/mockkms: keyID is required")
	}
	plaintext = make([]byte, 32)
	if _, err = rand.Read(plaintext); err != nil {
		return nil, nil, fmt.Errorf("privacy/mockkms: rand: %w", err)
	}
	ciphertext, err = m.Encrypt(nil, keyID, plaintext)
	if err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	m.keyStore[keyID] = plaintext
	m.mu.Unlock()
	return plaintext, ciphertext, nil
}

// Encrypt implements KMSClient. The keyID is encoded in the AAD so a
// blob encrypted for one CMK cannot be decrypted under another.
func (m *MockKMS) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	if keyID == "" {
		return nil, errors.New("privacy/mockkms: keyID is required")
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("privacy/mockkms: rand: %w", err)
	}
	ct := m.aead.Seal(nil, nonce, plaintext, []byte(keyID))
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt implements KMSClient. The mock encodes the key ID inside the
// AAD via every Encrypt call, so the caller must supply the same key ID
// for decryption — which it does implicitly through the encryptor's
// stored DEK. For mock purposes we walk the known key IDs to find one
// that decrypts cleanly.
func (m *MockKMS) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < m.aead.NonceSize() {
		return nil, errors.New("privacy/mockkms: ciphertext too short")
	}
	nonce, body := ciphertext[:m.aead.NonceSize()], ciphertext[m.aead.NonceSize():]
	m.mu.Lock()
	keyIDs := make([]string, 0, len(m.keyStore)+1)
	for id := range m.keyStore {
		keyIDs = append(keyIDs, id)
	}
	m.mu.Unlock()
	// Fall back to no-AAD attempt for the global "default" KMS context.
	keyIDs = append(keyIDs, "")
	for _, id := range keyIDs {
		pt, err := m.aead.Open(nil, nonce, body, []byte(id))
		if err == nil {
			return pt, nil
		}
	}
	return nil, errors.New("privacy/mockkms: decrypt failed")
}

// ForgetKey removes a logical key from the in-memory keystore. After
// ForgetKey, any blob encrypted under that key cannot be decrypted —
// this is the mechanism behind cryptographic erasure.
func (m *MockKMS) ForgetKey(keyID string) {
	m.mu.Lock()
	delete(m.keyStore, keyID)
	m.mu.Unlock()
}
