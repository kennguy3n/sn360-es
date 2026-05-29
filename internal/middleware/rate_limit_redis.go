package middleware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/kennguy3n/sn360-es/pkg/storage/redis"
)

// redisBucketStore adapts the cluster-wide Lua-atomic token-bucket
// in pkg/storage/redis.RateBucketStore into a [BucketStore] the
// middleware can consume directly.
//
// Two responsibilities live here, beyond pure delegation:
//
//  1. Translate Redis-level network / timeout errors into the
//     middleware-level [ErrBucketStoreUnavailable] sentinel so the
//     limiter's FailureMode / FailureModeFallback path can react
//     correctly. Any non-network error (script error, malformed
//     reply, etc.) is returned as-is — those are programmer errors
//     that should not silently fail-open.
//  2. Apply the optional per-call timeout so a Redis stall cannot
//     extend a request beyond the limiter's SLA budget. The default
//     timeout (200 ms) is conservative enough for an HTTP-edge
//     ratelimit hop and small enough that a stuck Redis won't
//     trigger the request-timeout layer above us.
type redisBucketStore struct {
	store   *redis.RateBucketStore
	timeout time.Duration
}

// RedisBucketStoreConfig configures the Redis-backed [BucketStore].
type RedisBucketStoreConfig struct {
	// Store is the underlying RateBucketStore. Required.
	Store *redis.RateBucketStore
	// Timeout caps every Take call. The middleware's primary store
	// must be fast — a slow Redis multiplies onto every request.
	// Defaults to 200 ms; a Redis that cannot answer in that time
	// is treated as hard-down so the limiter can fall back / fail
	// open per its configured policy. Set negative to disable.
	Timeout time.Duration
}

// NewRedisBucketStore wraps a [pkg/storage/redis.RateBucketStore] for
// consumption by the rate-limit middleware. Returns an error when
// the underlying store is nil — callers MUST construct the
// RateBucketStore first (it owns the script-load lifecycle).
func NewRedisBucketStore(cfg RedisBucketStoreConfig) (BucketStore, error) {
	if cfg.Store == nil {
		return nil, errors.New("rate-limit: redis bucket store requires a non-nil RateBucketStore")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 200 * time.Millisecond
	}
	if timeout < 0 {
		timeout = 0
	}
	return &redisBucketStore{
		store:   cfg.Store,
		timeout: timeout,
	}, nil
}

// Take implements [BucketStore]. Wraps the Redis script call with a
// per-request timeout and maps network-class errors to
// [ErrBucketStoreUnavailable].
func (s *redisBucketStore) Take(ctx context.Context, clientKey string, rate float64, burst int) (bool, time.Duration, error) {
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	allowed, retry, err := s.store.Take(ctx, clientKey, rate, burst)
	if err == nil {
		return allowed, retry, nil
	}
	if isRedisUnavailable(err) {
		return false, 0, fmt.Errorf("%w: %v", ErrBucketStoreUnavailable, err)
	}
	return false, 0, err
}

// isRedisUnavailable returns true when err looks like a Redis-level
// availability problem (network, timeout, redis.Nil-after-pipeline,
// etc.) as opposed to a programmer error (script crash, bad reply
// shape). The middleware only translates availability errors so a
// real bug in the script still surfaces.
//
// Detection runs through typed-error checks first (errors.Is /
// errors.As) so a hypothetical Redis reply containing the literal
// substring "eof" cannot be misclassified as transient. The
// substring fan-out only handles the narrow set of
// platform-network errors go-redis surfaces as bare error strings.
func isRedisUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	if errors.Is(err, goredis.ErrClosed) {
		return true
	}
	// io.EOF is the canonical network-EOF sentinel; checking it
	// typed (errors.Is) means a Redis-level error whose text
	// happens to include "eof" (a Lua error referencing
	// `EOF` in script source, a payload-validation error
	// quoting a malformed message body, etc.) is NOT masked as
	// transient. Only an actual io.EOF in the error chain
	// matches.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	// net.Error.Timeout() covers i/o timeouts uniformly (the
	// go-redis package wraps the *net.OpError, so the typed
	// As-check finds the underlying network error). Likewise
	// *net.OpError covers connection refused / reset / EHOSTUNREACH
	// once unwrapped.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	// Network-level errors that come back as bare strings (no
	// typed wrap). Kept very narrow — only substrings that
	// uniquely identify a network condition. "EOF" was removed
	// in favour of the io.EOF / io.ErrUnexpectedEOF typed
	// checks above.
	msg := err.Error()
	for _, needle := range networkErrorSubstrings {
		if containsCaseInsensitive(msg, needle) {
			return true
		}
	}
	return false
}

// networkErrorSubstrings is the curated set of substrings we treat
// as availability errors. Kept small and conservative; widening
// without thought risks masking programmer errors as transient.
// Typed-error sentinels (io.EOF, net.Error, *net.OpError) are
// checked in isRedisUnavailable BEFORE this list, so substrings
// here only catch error texts that don't carry a typed wrap.
var networkErrorSubstrings = []string{
	"connection refused",
	"connection reset",
	"i/o timeout",
	"network is unreachable",
	"no such host",
	"broken pipe",
}

// containsCaseInsensitive performs a case-insensitive substring
// match without allocating. Used by isRedisUnavailable for the
// network-error needle list.
func containsCaseInsensitive(s, needle string) bool {
	if len(needle) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(needle); i++ {
		if equalFoldASCII(s[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

// equalFoldASCII compares two strings under ASCII case-folding,
// which is the regime go-redis network errors live in.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
