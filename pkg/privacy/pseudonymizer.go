package privacy

import (
	"encoding/hex"
	"fmt"
	"hash"
	"reflect"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// blake2bKey returns a Blake2b-256 hasher keyed with the given 32-byte key.
// Exposed inside the package so privacy.go can derive per-tenant keys.
func blake2bKey(key []byte) (hash.Hash, error) {
	h, err := blake2b.New256(key)
	if err != nil {
		return nil, fmt.Errorf("privacy: blake2b: %w", err)
	}
	return h, nil
}

// Pseudonymizer maps PII values to stable, opaque tokens using a keyed
// Blake2b hash. The hashes are deterministic per (tenantKey, input) so
// the same email address always pseudonymises to the same token —
// enabling relationship tracking — but two tenants cannot correlate
// each other's tokens because the keys differ.
type Pseudonymizer interface {
	// Hash returns the hex-encoded pseudonym of input under tenantKey.
	// tenantKey must be 32 bytes. Returns ErrInvalidKey or
	// ErrMissingTenantKey on validation failure.
	Hash(tenantKey []byte, input string) (string, error)
	// HashOrEmpty returns the hex pseudonym, or the empty string on
	// error. Convenience for code paths that prefer "no pseudonym"
	// over an error.
	HashOrEmpty(tenantKey []byte, input string) string
	// Pseudonymize walks v reflectively and replaces every field
	// tagged `privacy:"pii"` with its hash. v must be a pointer to a
	// mutable struct or a slice/map of structs.
	Pseudonymize(tenantKey []byte, v any) error
}

// blakePseudonymizer is the canonical implementation: blake2b-256 keyed.
type blakePseudonymizer struct {
	// Prefix is prepended to every plaintext before hashing. Lets ops
	// rotate pseudonyms by changing the prefix without changing tenant
	// keys.
	prefix string
}

// NewPseudonymizer constructs a Pseudonymizer. prefix may be empty.
func NewPseudonymizer(prefix string) Pseudonymizer {
	return &blakePseudonymizer{prefix: prefix}
}

// Hash returns the blake2b-256(prefix||input) keyed with tenantKey, hex-
// encoded.
func (b *blakePseudonymizer) Hash(tenantKey []byte, input string) (string, error) {
	if len(tenantKey) == 0 {
		return "", ErrMissingTenantKey
	}
	if len(tenantKey) != 32 {
		return "", fmt.Errorf("%w: pseudonymizer expects 32-byte tenant key, got %d", ErrInvalidKey, len(tenantKey))
	}
	h, err := blake2b.New256(tenantKey)
	if err != nil {
		return "", fmt.Errorf("privacy: blake2b: %w", err)
	}
	if b.prefix != "" {
		_, _ = h.Write([]byte(b.prefix))
	}
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(input))))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashOrEmpty is a non-error variant of Hash.
func (b *blakePseudonymizer) HashOrEmpty(tenantKey []byte, input string) string {
	if input == "" {
		return ""
	}
	out, err := b.Hash(tenantKey, input)
	if err != nil {
		return ""
	}
	return out
}

// Pseudonymize walks v's fields and hashes everything tagged
// `privacy:"pii"` in place. Nested structs are recursed into. Slices
// and maps with string keys are also walked.
func (b *blakePseudonymizer) Pseudonymize(tenantKey []byte, v any) error {
	if len(tenantKey) == 0 {
		return ErrMissingTenantKey
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	return b.walk(tenantKey, rv)
}

func (b *blakePseudonymizer) walk(tenantKey []byte, rv reflect.Value) error {
	if !rv.IsValid() {
		return nil
	}
	switch rv.Kind() {
	case reflect.Struct:
		t := rv.Type()
		for i := 0; i < rv.NumField(); i++ {
			field := t.Field(i)
			fv := rv.Field(i)
			tag := field.Tag.Get("privacy")
			if tag == "pii" && fv.Kind() == reflect.String && fv.CanSet() {
				if fv.String() == "" {
					continue
				}
				h, err := b.Hash(tenantKey, fv.String())
				if err != nil {
					return err
				}
				fv.SetString(h)
				continue
			}
			if err := b.walk(tenantKey, fv); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if err := b.walk(tenantKey, rv.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := rv.MapRange()
		for iter.Next() {
			val := iter.Value()
			if val.Kind() == reflect.Ptr {
				val = val.Elem()
			}
			if val.Kind() == reflect.Struct {
				ptr := reflect.New(val.Type())
				ptr.Elem().Set(val)
				if err := b.walk(tenantKey, ptr.Elem()); err != nil {
					return err
				}
				rv.SetMapIndex(iter.Key(), ptr.Elem())
			}
		}
	case reflect.Ptr, reflect.Interface:
		if !rv.IsNil() {
			return b.walk(tenantKey, rv.Elem())
		}
	}
	return nil
}
