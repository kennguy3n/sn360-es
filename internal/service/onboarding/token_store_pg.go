package onboarding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// TokenEncryptor is the encryption interface used by PgTokenStore.
// It mirrors the simple encrypt/decrypt contract without coupling to
// the full privacy.Encryptor (which requires tenant-scoped KMS keys).
type TokenEncryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// PgTokenStore persists OAuth tokens in the oauth_tokens table with
// AES-256-GCM encryption. Tokens are encrypted at rest; only the
// ciphertext is stored. Decryption happens on Load.
type PgTokenStore struct {
	db        *postgres.DB
	encryptor TokenEncryptor
}

// NewPgTokenStore constructs a PgTokenStore. Both db and encryptor
// are required.
func NewPgTokenStore(db *postgres.DB, enc TokenEncryptor) (*PgTokenStore, error) {
	if db == nil {
		return nil, errors.New("onboarding: PgTokenStore requires a database")
	}
	if enc == nil {
		return nil, errors.New("onboarding: PgTokenStore requires an encryptor")
	}
	return &PgTokenStore{db: db, encryptor: enc}, nil
}

// Save encrypts the token and upserts it into oauth_tokens.
func (s *PgTokenStore) Save(ctx context.Context, tenantID string, provider ProviderType, tok Token) error {
	if tenantID == "" {
		return errors.New("onboarding: tenant_id is required")
	}
	plain, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("onboarding: marshal token: %w", err)
	}
	ct, err := s.encryptor.Encrypt(plain)
	if err != nil {
		return fmt.Errorf("onboarding: encrypt token: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO oauth_tokens (tenant_id, provider, ciphertext, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
ON CONFLICT (tenant_id, provider) DO UPDATE SET
    ciphertext = EXCLUDED.ciphertext,
    updated_at = EXCLUDED.updated_at
`, tenantID, string(provider), ct, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("onboarding: save token: %w", err)
	}
	return nil
}

// Load decrypts and returns the token for (tenantID, provider).
func (s *PgTokenStore) Load(ctx context.Context, tenantID string, provider ProviderType) (Token, error) {
	var ct []byte
	err := s.db.QueryRowContext(ctx, `
SELECT ciphertext FROM oauth_tokens WHERE tenant_id=$1 AND provider=$2`,
		tenantID, string(provider)).Scan(&ct)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, fmt.Errorf("onboarding: token not found for tenant %q provider %q", tenantID, provider)
	}
	if err != nil {
		return Token{}, fmt.Errorf("onboarding: load token: %w", err)
	}
	plain, err := s.encryptor.Decrypt(ct)
	if err != nil {
		return Token{}, fmt.Errorf("onboarding: decrypt token: %w", err)
	}
	var tok Token
	if err := json.Unmarshal(plain, &tok); err != nil {
		return Token{}, fmt.Errorf("onboarding: unmarshal token: %w", err)
	}
	return tok, nil
}

// Delete removes the token for (tenantID, provider).
func (s *PgTokenStore) Delete(ctx context.Context, tenantID string, provider ProviderType) error {
	_, err := s.db.ExecContext(ctx, `
DELETE FROM oauth_tokens WHERE tenant_id=$1 AND provider=$2`,
		tenantID, string(provider))
	if err != nil {
		return fmt.Errorf("onboarding: delete token: %w", err)
	}
	return nil
}

// ListAll returns all (tenantID, provider) pairs. Used on boot to
// restore provider registry entries from stored tokens.
func (s *PgTokenStore) ListAll(ctx context.Context) ([]StoredTokenRef, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT tenant_id, provider FROM oauth_tokens ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("onboarding: list tokens: %w", err)
	}
	defer rows.Close()
	var out []StoredTokenRef
	for rows.Next() {
		var ref StoredTokenRef
		if err := rows.Scan(&ref.TenantID, &ref.Provider); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// StoredTokenRef is a lightweight reference to a stored token row.
type StoredTokenRef struct {
	TenantID string
	Provider string
}
