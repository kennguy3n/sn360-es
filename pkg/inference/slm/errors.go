package slm

import (
	"errors"
	"fmt"
	"time"
)

// ErrProviderNotRegistered is returned by New when the requested
// provider name has no registered factory. Callers can use
// errors.Is to distinguish this from a factory-level construction
// error so a misspelled TIER2_PROVIDER fails the boot loudly
// instead of degrading into "Tier 2 disabled".
var ErrProviderNotRegistered = errors.New("slm: provider not registered")

// ErrEmptyResponse is returned by providers when the model's reply
// contains no usable content (empty choices array, empty content
// field, or whitespace-only content). It is a sentinel so the
// fallback circuit breaker can distinguish a "provider returned
// nothing" failure (potentially retryable on the fallback) from a
// genuine HTTP / network error.
var ErrEmptyResponse = errors.New("slm: empty model response")

// ErrUnparseableVerdict is returned when the model emitted content
// that does not contain a parseable JSON verdict object. Treat it
// the same as ErrEmptyResponse for circuit-breaker purposes — the
// content was non-empty but the structured-output contract was
// broken, which usually indicates the model drifted off task and
// will likely keep drifting.
var ErrUnparseableVerdict = errors.New("slm: unparseable verdict")

// RateLimitedError wraps a 429 response so callers can extract the
// server's Retry-After hint (when present) for adaptive backoff. We
// return it via fmt.Errorf("...: %w", &RateLimitedError{...}) so
// `errors.Is(err, slm.ErrRateLimited)` works AND
// `errors.As(err, &rle)` recovers the RetryAfter duration.
type RateLimitedError struct {
	// RetryAfter is the parsed Retry-After header value, or zero
	// when the server did not advertise one. A non-zero value is
	// always positive.
	RetryAfter time.Duration

	// StatusCode is the HTTP status (always 429 in practice; kept
	// explicit so the field is self-documenting in logs).
	StatusCode int

	// Snippet is a bounded prefix of the response body for
	// operator diagnostics. Empty when the body was empty.
	Snippet string
}

// Error implements the error interface.
func (e *RateLimitedError) Error() string {
	if e.RetryAfter > 0 {
		if e.Snippet != "" {
			return fmt.Sprintf("slm: HTTP %d rate limited (retry after %s): %s",
				e.StatusCode, e.RetryAfter, e.Snippet)
		}
		return fmt.Sprintf("slm: HTTP %d rate limited (retry after %s)",
			e.StatusCode, e.RetryAfter)
	}
	if e.Snippet != "" {
		return fmt.Sprintf("slm: HTTP %d rate limited: %s", e.StatusCode, e.Snippet)
	}
	return fmt.Sprintf("slm: HTTP %d rate limited", e.StatusCode)
}

// Is reports whether err is a RateLimitedError for errors.Is
// dispatch via ErrRateLimited.
func (e *RateLimitedError) Is(target error) bool {
	return target == ErrRateLimited
}

// ErrRateLimited is the sentinel target for
// errors.Is(err, slm.ErrRateLimited). Use RateLimitedError when you
// need the Retry-After value.
var ErrRateLimited = errors.New("slm: rate limited")

// ServerError wraps a 5xx response. Like RateLimitedError it carries
// a Retry-After (some providers send it on 503) so the caller can
// honour backoff hints uniformly across 429 and 5xx.
type ServerError struct {
	StatusCode int
	RetryAfter time.Duration
	Snippet    string
}

// Error implements the error interface.
func (e *ServerError) Error() string {
	if e.RetryAfter > 0 {
		if e.Snippet != "" {
			return fmt.Sprintf("slm: HTTP %d server error (retry after %s): %s",
				e.StatusCode, e.RetryAfter, e.Snippet)
		}
		return fmt.Sprintf("slm: HTTP %d server error (retry after %s)",
			e.StatusCode, e.RetryAfter)
	}
	if e.Snippet != "" {
		return fmt.Sprintf("slm: HTTP %d: %s", e.StatusCode, e.Snippet)
	}
	return fmt.Sprintf("slm: HTTP %d", e.StatusCode)
}

// Is reports whether err is a ServerError for errors.Is dispatch
// via ErrServerError.
func (e *ServerError) Is(target error) bool {
	return target == ErrServerError
}

// ErrServerError is the sentinel target for
// errors.Is(err, slm.ErrServerError).
var ErrServerError = errors.New("slm: server error")
