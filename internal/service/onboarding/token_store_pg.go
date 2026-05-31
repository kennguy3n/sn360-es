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

// bindTenantIfNeeded returns ctx unchanged when an upstream caller has
// already pinned a tenant-bound *sql.Conn (HTTP TenantConnBinder,
// consumer tenantBoundMessageHandler, worker WithTenant scope), and
// acquires a fresh single-tenant binding otherwise.
//
// This is what makes PgTokenStore.{Save,Load,Delete} survive callers
// that have NO upstream binding — most notably the OAuth callback
// flow at `/v1/onboarding/callback`, which is in
// `defaultAuthSkipPaths()` because it receives a redirect from the
// IdP (no Bearer JWT, no JWTAuth-injected tenant_id, no
// TenantConnBinder). Without this self-binding, the INSERT inside
// Save would run on a fresh pool conn whose `sn360.tenant_id` GUC is
// empty, and the RLS WITH CHECK on oauth_tokens — installed by
// `migrations/0018_row_level_security.up.sql` — would reject every
// write once the connect role is rotated to a non-superuser (the
// rotation lands in a follow-up Helm/Terraform PR per Task 5).
//
// Self-binding here also future-proofs background refresh: TokenFor
// calls Save when a stored token has expired, and that path can run
// from a worker / scheduled-job context that never went through HTTP
// middleware and therefore has no bound conn either.
//
// We deliberately reuse the caller's existing binding when present
// rather than acquire a second conn: a JWT-authenticated request that
// already pinned a conn for tenant X should be allowed to call Save
// for tenant X without consuming a second pool slot, and a mismatch
// (Save for tenant Y on a conn bound to X) is already correctly
// blocked by the RLS WITH CHECK clause itself.
func (s *PgTokenStore) bindTenantIfNeeded(ctx context.Context, tenantID string) (context.Context, postgres.ReleaseFunc, error) {
	if postgres.BoundConnFromContext(ctx) != nil {
		return ctx, noopRelease, nil
	}
	return s.db.WithTenant(ctx, tenantID)
}

// noopRelease is the zero-value ReleaseFunc returned when
// bindTenantIfNeeded reuses an existing bound conn. Defining it here
// (rather than importing from package postgres) keeps the helper's
// call-site shape — `defer release()` — uniform between the
// pass-through and acquire branches.
func noopRelease() error { return nil }

// Save encrypts the token and upserts it into oauth_tokens.
func (s *PgTokenStore) Save(ctx context.Context, tenantID string, provider ProviderType, tok Token) error {
	if tenantID == "" {
		return errors.New("onboarding: tenant_id is required")
	}
	boundCtx, release, err := s.bindTenantIfNeeded(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("onboarding: bind tenant for token save: %w", err)
	}
	defer func() { _ = release() }()
	plain, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("onboarding: marshal token: %w", err)
	}
	ct, err := s.encryptor.Encrypt(plain)
	if err != nil {
		return fmt.Errorf("onboarding: encrypt token: %w", err)
	}
	_, err = s.db.ExecContext(boundCtx, `
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
	if tenantID == "" {
		return Token{}, errors.New("onboarding: tenant_id is required")
	}
	boundCtx, release, err := s.bindTenantIfNeeded(ctx, tenantID)
	if err != nil {
		return Token{}, fmt.Errorf("onboarding: bind tenant for token load: %w", err)
	}
	defer func() { _ = release() }()
	var ct []byte
	err = s.db.QueryRowContext(boundCtx, `
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
	if tenantID == "" {
		return errors.New("onboarding: tenant_id is required")
	}
	boundCtx, release, err := s.bindTenantIfNeeded(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("onboarding: bind tenant for token delete: %w", err)
	}
	defer func() { _ = release() }()
	_, err = s.db.ExecContext(boundCtx, `
DELETE FROM oauth_tokens WHERE tenant_id=$1 AND provider=$2`,
		tenantID, string(provider))
	if err != nil {
		return fmt.Errorf("onboarding: delete token: %w", err)
	}
	return nil
}

// ListAll returns all (tenantID, provider) pairs. Used on boot to
// restore provider registry entries from stored tokens. The result
// always echoes tenant_id back to the caller so the provider registry
// can re-key by tenant; one tenant's rows are never surfaced under
// another tenant's identity.
//
// This is one of the small handful of genuinely cross-tenant queries
// in the codebase (boot-time provider registry rebuild). The
// `tenant-lint:cross-tenant` annotation below opts the static
// analyser out of its per-call tenant_id check, and the runtime
// `WithCrossTenant` scope opts the query out of the RLS policy
// installed by `migrations/0018_row_level_security.up.sql`. Both
// opt-outs are deliberate and audited together — without the
// runtime scope the policy would silently return zero rows after
// migration 0018 lands.
func (s *PgTokenStore) ListAll(ctx context.Context) ([]StoredTokenRef, error) {
	crossCtx, release, err := s.db.WithCrossTenant(ctx)
	if err != nil {
		return nil, fmt.Errorf("onboarding: list tokens: cross-tenant scope: %w", err)
	}
	defer func() { _ = release() }()
	// tenant-lint:cross-tenant — boot-time provider registry rebuild;
	// returns (tenant_id, provider) tuples that the registry re-keys
	// per tenant downstream. The runtime WithCrossTenant scope above
	// opts the query out of the RLS policy installed by
	// migrations/0018_row_level_security.up.sql so the unscoped
	// SELECT below is the intentional, audited form of the query.
	rows, err := s.db.QueryContext(crossCtx, `
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
