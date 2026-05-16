package privacy

import (
	"context"
	"errors"
	"log/slog"
)

// Privacy is the top-level facade combining pseudonymisation,
// per-tenant envelope encryption, and the JWT issuer used by the banner
// UX. Most callers depend on this struct rather than the individual
// components so the wiring lives in one place.
type Privacy struct {
	pseudo Pseudonymizer
	enc    Encryptor
	jwt    *JWTIssuer
	san    *Sanitizer

	// keyForTenant returns the tenant-specific Blake2 key used by the
	// pseudonymizer. The default derives a per-tenant 32-byte key from
	// the global master key and the tenant ID; deployments with a
	// hosted KMS may override this to fetch per-tenant keys from KMS.
	keyForTenant func(ctx context.Context, tenantID string) ([]byte, error)
}

// Options bundles the dependencies needed by [New].
type Options struct {
	Pseudonymizer Pseudonymizer
	Encryptor     Encryptor
	JWT           *JWTIssuer
	Sanitizer     *Sanitizer
	KeyForTenant  func(ctx context.Context, tenantID string) ([]byte, error)
	Logger        *slog.Logger
}

// New returns a Privacy facade. Pseudonymizer, Encryptor, and KeyForTenant
// are required.
func New(opts Options) (*Privacy, error) {
	if opts.Pseudonymizer == nil {
		return nil, errors.New("privacy: Pseudonymizer is required")
	}
	if opts.Encryptor == nil {
		return nil, errors.New("privacy: Encryptor is required")
	}
	if opts.KeyForTenant == nil {
		return nil, errors.New("privacy: KeyForTenant is required")
	}
	if opts.Sanitizer == nil {
		opts.Sanitizer = NewSanitizer()
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Privacy{
		pseudo:       opts.Pseudonymizer,
		enc:          opts.Encryptor,
		jwt:          opts.JWT,
		san:          opts.Sanitizer,
		keyForTenant: opts.KeyForTenant,
	}, nil
}

// Pseudonymizer returns the underlying Pseudonymizer.
func (p *Privacy) Pseudonymizer() Pseudonymizer { return p.pseudo }

// Encryptor returns the underlying Encryptor.
func (p *Privacy) Encryptor() Encryptor { return p.enc }

// JWT returns the underlying JWT issuer (may be nil if not configured).
func (p *Privacy) JWT() *JWTIssuer { return p.jwt }

// Sanitizer returns the underlying log Sanitizer.
func (p *Privacy) Sanitizer() *Sanitizer { return p.san }

// HashEmail returns the pseudonym of email under tenantID. It looks up
// the tenant key via the KeyForTenant function provided at construction.
func (p *Privacy) HashEmail(ctx context.Context, tenantID, email string) (string, error) {
	if email == "" {
		return "", nil
	}
	key, err := p.keyForTenant(ctx, tenantID)
	if err != nil {
		return "", err
	}
	return p.pseudo.Hash(key, email)
}

// HashOrEmpty is HashEmail but returns the empty string on error.
func (p *Privacy) HashOrEmpty(ctx context.Context, tenantID, email string) string {
	out, err := p.HashEmail(ctx, tenantID, email)
	if err != nil {
		return ""
	}
	return out
}

// Encrypt encrypts plaintext under tenantID's DEK.
func (p *Privacy) Encrypt(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error) {
	return p.enc.Encrypt(ctx, tenantID, plaintext)
}

// Decrypt decrypts a blob produced by Encrypt.
func (p *Privacy) Decrypt(ctx context.Context, tenantID string, ciphertext []byte) ([]byte, error) {
	return p.enc.Decrypt(ctx, tenantID, ciphertext)
}

// DeriveTenantKeyFromMaster returns a 32-byte tenant key derived from a
// 32-byte master key and the tenant ID via Blake2b-keyed hashing. The
// helper is exported so tests and adapters can plug it into Options.
func DeriveTenantKeyFromMaster(master []byte, tenantID string) ([]byte, error) {
	if len(master) != 32 {
		return nil, errors.New("privacy: master key must be 32 bytes")
	}
	if tenantID == "" {
		return nil, errors.New("privacy: tenant ID is required")
	}
	h, err := blake2bKey(master)
	if err != nil {
		return nil, err
	}
	_, _ = h.Write([]byte("sn360.tenant.key.v1"))
	_, _ = h.Write([]byte(tenantID))
	return h.Sum(nil), nil
}
