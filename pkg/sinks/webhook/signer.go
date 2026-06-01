package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SignatureHeader is the HTTP header the dispatcher sets and the
// verifier reads. Format: `sha256=<hex>` — same convention GitHub
// and Stripe use so customer-side webhook libraries (e.g.
// stripe-webhook-validator, hmac-validator) can validate without
// any sn360-specific code.
const SignatureHeader = "X-SN360-Signature"

// EventTypeHeader carries the schema identifier so downstream
// consumers can route different event types (today only
// `email.evaluation` exists; future events would not silently
// collide with this one).
const EventTypeHeader = "X-SN360-Event-Type"

// EventTypeEmailEvaluation is the only event type the sink emits
// today.
const EventTypeEmailEvaluation = "email.evaluation"

// SecretBytes is the length of an HMAC secret in bytes. 32 bytes
// = 256 bits of entropy, the same key length as the HMAC algorithm
// (HMAC-SHA256). Anything shorter weakens the signature; anything
// longer is unnecessary.
const SecretBytes = 32

// GenerateSecret returns a 32-byte cryptographically-random secret
// suitable for use as the HMAC key. Uses crypto/rand; the only
// failure mode is the OS RNG being unavailable, which propagates
// directly.
func GenerateSecret() ([]byte, error) {
	buf := make([]byte, SecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("webhook: generate hmac secret: %w", err)
	}
	return buf, nil
}

// Sign returns the HMAC-SHA256 of body keyed with secret, hex-
// encoded with the `sha256=` prefix so the value can be set as
// the X-SN360-Signature header verbatim.
//
// The returned string format is deliberately the same shape as
// GitHub / Stripe / Slack webhook signatures so a customer can
// reuse an existing webhook validator and only needs to know our
// header name and secret.
func Sign(secret []byte, body []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("webhook: hmac secret is required")
	}
	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write(body); err != nil {
		return "", fmt.Errorf("webhook: hmac write: %w", err)
	}
	return "sha256=" + hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify reports whether the value of an X-SN360-Signature header
// matches the HMAC of body under secret.
//
// Comparison is constant-time (subtle.ConstantTimeCompare via
// crypto/hmac.Equal) so a network attacker who can time the
// verifier cannot bisect digits of the expected MAC.
//
// Provided as a helper for receiver-side tests and (eventually) for
// any sn360-es-internal verification path (e.g. a future
// admin-routed re-publish loop that needs to verify its own
// payloads).
func Verify(secret []byte, body []byte, header string) bool {
	if len(secret) == 0 || header == "" {
		return false
	}
	header = strings.TrimSpace(header)
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	expected, err := computeHMAC(secret, body)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, provided)
}

// computeHMAC is the raw HMAC-SHA256 (no hex / no prefix) used by
// Verify. Kept private to keep the public surface to Sign / Verify.
func computeHMAC(secret, body []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write(body); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}
