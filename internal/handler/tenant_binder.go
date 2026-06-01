package handler

import "context"

// TenantBinder pins a Postgres connection to a tenant_id session
// GUC for the lifetime of one request, activating the row-level
// security policy installed by migration 0018 (and the per-table
// CREATE POLICY in later migrations like 0021's
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
// A nil TenantBinder is a valid no-op — in-memory test fixtures
// don't enforce RLS, so the handler skips the bind step entirely.
// Production wiring at cmd/sn360-es is responsible for providing
// a real binder when `pgDB != nil`. Mirror of the
// `worker.TenantBinder` pattern at internal/service/worker.
type TenantBinder interface {
	WithTenant(ctx context.Context, tenantID string) (context.Context, TenantBinderReleaseFunc, error)
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
