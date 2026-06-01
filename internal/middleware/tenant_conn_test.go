package middleware

import (
	"context"
	"testing"
)

// TestBindTenant_NilReceiverReturnsNoopRelease pins the contract that
// (*TenantConnBinder).BindTenant returns a non-nil ReleaseFunc on
// every error path — matching the postgres-layer convention used by
// WithTenant / WithCrossTenant / WithTenantInRegion. Callers may
// unconditionally `defer release()` without nil-checking.
//
// Devin Review caught the original implementation returning `nil` on
// the nil-receiver guard, which would panic any caller using the
// standard `defer release()` pattern before checking err. This test
// fences the contract so a future regression fails loudly.
//
// The resolver-error branch in bind() returns noopReleaseFunc by the
// same contract; that branch needs a live RegionalDB to construct a
// non-nil receiver, so it is exercised end-to-end in the integration
// test under internal/repository/multi_region_test.go rather than here.
func TestBindTenant_NilReceiverReturnsNoopRelease(t *testing.T) {
	t.Parallel()

	var b *TenantConnBinder // nil receiver
	ctx, release, err := b.BindTenant(context.Background(), "tenant-1")

	if err == nil {
		t.Fatalf("BindTenant(nil receiver) returned err=nil, want a non-nil error")
	}
	if ctx == nil {
		t.Fatalf("BindTenant(nil receiver) returned ctx=nil, want the input ctx echoed back")
	}
	if release == nil {
		t.Fatalf("BindTenant(nil receiver) returned release=nil; "+
			"callers may unconditionally defer release() — got err=%v", err)
	}
	if relErr := release(); relErr != nil {
		t.Fatalf("noop release() returned err=%v, want nil", relErr)
	}
}
