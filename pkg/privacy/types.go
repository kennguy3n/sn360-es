// Package privacy provides the SN360-ES privacy primitives: data
// classification labels, deterministic pseudonymisation, per-tenant
// envelope encryption, log sanitisation, and cryptographic erasure.
//
// The package is intentionally self-contained — its only runtime
// dependency outside the standard library is the Blake2 implementation
// from golang.org/x/crypto and the optional AWS KMS client. Mock KMS
// support is built in for tests so privacy code can be exercised
// without AWS access.
package privacy

import "errors"

// DataClass classifies a piece of data by sensitivity. Each class maps
// to specific handling rules (e.g. logging restrictions, encryption-at-
// rest requirements, retention).
type DataClass string

const (
	// ClassCriticalPII covers government identifiers, full SSN, credit
	// card primary account numbers, biometric data, etc. Must always be
	// encrypted at rest, never logged, never sent to AI for training.
	ClassCriticalPII DataClass = "critical_pii"
	// ClassPII covers email addresses, names, phone numbers, IP
	// addresses, message subjects/bodies. Pseudonymised in logs.
	ClassPII DataClass = "pii"
	// ClassInternal covers tenant-internal metadata (org structure,
	// classification rules, business policies). Encrypted at rest.
	ClassInternal DataClass = "internal"
	// ClassSensitive covers vendor lists, business relationships, and
	// detection-rule artefacts.
	ClassSensitive DataClass = "sensitive"
	// ClassTransient covers in-flight pipeline state (correlation IDs,
	// pseudonymised message IDs, tier outputs) — safe to keep in logs
	// because nothing identifies a real human.
	ClassTransient DataClass = "transient"
	// ClassConfidential covers operational artefacts (deployment
	// secrets, API keys, internal configs).
	ClassConfidential DataClass = "confidential"
	// ClassCompliance covers data subject access requests, audit logs,
	// and other compliance evidence — retained per jurisdiction policy.
	ClassCompliance DataClass = "compliance"
)

// AllClasses enumerates every classification.
var AllClasses = []DataClass{
	ClassCriticalPII,
	ClassPII,
	ClassInternal,
	ClassSensitive,
	ClassTransient,
	ClassConfidential,
	ClassCompliance,
}

// Valid reports whether c is a known class.
func (c DataClass) Valid() bool {
	for _, k := range AllClasses {
		if c == k {
			return true
		}
	}
	return false
}

// IsPII reports whether c contains PII (i.e. log sanitisers must
// pseudonymise the value).
func (c DataClass) IsPII() bool {
	return c == ClassCriticalPII || c == ClassPII
}

// RequiresEncryption reports whether c must be encrypted at rest.
func (c DataClass) RequiresEncryption() bool {
	switch c {
	case ClassCriticalPII, ClassPII, ClassInternal, ClassSensitive, ClassConfidential:
		return true
	default:
		return false
	}
}

// ErrInvalidKey is returned when an encryption key has the wrong length.
var ErrInvalidKey = errors.New("privacy: invalid key length")

// ErrMissingTenantKey is returned when a tenant-keyed operation is
// invoked without a tenant key.
var ErrMissingTenantKey = errors.New("privacy: missing tenant key")
