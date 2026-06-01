package handler

import "context"

// TenantBinder pins a Postgres connection to a tenant_id session
// GUC for the lifetime of one request, activating the row-level
// security policy installed by migration 0018 (and the per-table
// CREATE POLICY in later migrations like 0022's
// `quarantine_release_audit`).
//
// The QuarantineHandler uses it on the WS-3a self-service path
// because that endpoint sits in the auth-skip list (the recipient
// JWT lives in the POST body, NOT the Authorization header, so the
// generic JWTAuth middleware cannot decode it — and the
// TenantConnBinder middleware which depends on JWTAuth's
// per-request tenant_id ctx value is therefore also bypassed).
// Without a per-request bind, every read from
// `tenant_release_policies` would see zero rows (RLS USING),
// every read from `quarantine_release_audit` for the rate-limit
// count would return zero (silently disabling the cap), and every
// INSERT into `quarantine_release_audit` would be rejected by
// RLS WITH CHECK (silently dropping the audit trail). The handler
// closes this gap by binding the conn itself, AFTER the embedded
// self-release JWT has been cryptographically verified, using the
// `tid` claim as the bind value.
//
// Two release semantics:
//   - On success the returned `ReleaseFunc` MUST be deferred. It
//     RESETs the `sn360.tenant_id` GUC and returns the conn to the
//     pool; callers should `defer release()`.
//   - On error a no-op release is returned so callers can
//     unconditionally `defer release()` without nil-checking.
//
// The constructor REQUIRES a non-nil TenantBinder. Deployments
// that intentionally do not need a per-request bind (in-memory
// test fixtures, dev runs without Postgres) MUST pass an explicit
// NopTenantBinder{} rather than nil. Devin Review round 7 surfaced
// the previous "nil = no-op" rule as a silent-failure shape: a
// future wiring regression that omitted the binder in a Postgres-
// backed deployment would have disabled the rate limiter (COUNT
// returns 0 under unbound RLS) and dropped audit INSERTs (WITH
// CHECK rejects) without surfacing any error. Promoting the
// invariant to the type system makes the "do not bind" decision
// a deliberate, single-line choice at the wire site instead of
// an implicit nil-check buried in the handler. Mirror of the
// `worker.TenantBinder` pattern at internal/service/worker but
// with the no-op case made explicit.
type TenantBinder interface {
	WithTenant(ctx context.Context, tenantID string) (context.Context, TenantBinderReleaseFunc, error)
}

// NopTenantBinder is the explicit no-op TenantBinder used by
// in-memory deployments (unit-test fixtures, dev runs without a
// Postgres handle). It returns the context unchanged and a
// release function that does nothing. Passing this value at the
// wire site is a deliberate "this deployment does not enforce
// RLS" declaration; the previous arrangement let nil silently mean
// the same thing, which masked wiring regressions in Postgres-
// backed deployments. Zero-valued; safe to use as `NopTenantBinder{}`.
type NopTenantBinder struct{}

// WithTenant implements TenantBinder by returning the input
// context and a no-op release. The bindErr return is always nil
// so handler code does not need a special-case branch — the
// uniform `if bindErr != nil { 503 }` shape just becomes dead
// code under the Nop binder, which is fine: tests that exercise
// the 503 path use the stub binder fixture in
// quarantine_selfrelease_test.go instead.
func (NopTenantBinder) WithTenant(ctx context.Context, _ string) (context.Context, TenantBinderReleaseFunc, error) {
	return ctx, func() error { return nil }, nil
}

// TenantBinderReleaseFunc unwinds a WithTenant scope. It RESETs the
// `sn360.tenant_id` GUC and Closes the pinned conn back to the
// pool. The error is non-nil only if the RESET round-trip itself
// failed; production callers usually `defer release()` and ignore
// the return because (a) the conn cleanup also runs on Close and
// (b) Postgres invalidates the session state on disconnect anyway.
// The type exists separately from `postgres.ReleaseFunc` so the
// handler package does not depend on the storage package's
// concrete type — the production adapter at cmd/sn360-es bridges
// the two via a one-line type-conversion call.
type TenantBinderReleaseFunc func() error
