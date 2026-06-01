package middleware

import (
	"context"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// stubResolver satisfies RegionResolver for the constructor-level
// wiring guard tests; the partial-wiring check fires before any
// resolve call so a zero-value implementation is sufficient.
type stubResolver struct{}

func (stubResolver) ResolveRegion(_ context.Context, _ string) (string, error) {
	return "", nil
}

// stubRegionalDB returns a non-nil *postgres.RegionalDB pointer for
// the wiring-guard check (which only does nil comparison). We can't
// reach the full NewRegionalDB constructor without standing up real
// *postgres.DB pools, so a zero-value sentinel is the right shape
// for a pure boot-time validation test.
func stubRegionalDB() *postgres.RegionalDB { return &postgres.RegionalDB{} }

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

// TestNewTenantConnBinder_RejectsPartialMultiRegionWiring pins the
// boot-time guard: Regional and Resolver must be wired together or
// both nil. A wiring-layer mistake that supplied one without the
// other would silently fall back to the home-region pool for every
// tenant — a data-residency violation. validate-at-construction
// surfaces the error during newApplication, not as a stream of
// misrouted requests at runtime.
func TestNewTenantConnBinder_RejectsPartialMultiRegionWiring(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  TenantConnConfig
	}{
		{
			name: "Regional set without Resolver",
			cfg: TenantConnConfig{
				Regional: stubRegionalDB(),
				Resolver: nil,
			},
		},
		{
			name: "Resolver set without Regional",
			cfg: TenantConnConfig{
				Regional: nil,
				Resolver: stubResolver{},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTenantConnBinder(nil, tc.cfg)
			if err == nil {
				t.Fatalf("NewTenantConnBinder accepted partial multi-region wiring (%s) — must reject to prevent silent fallback to home-region pool", tc.name)
			}
		})
	}
}

// TestNewTenantConnBinder_AcceptsSingleRegion and
// TestNewTenantConnBinder_AcceptsBothSet document the inverse
// contract: a binder with NEITHER multi-region field, or BOTH,
// must construct cleanly.
func TestNewTenantConnBinder_AcceptsSingleRegion(t *testing.T) {
	t.Parallel()
	if _, err := NewTenantConnBinder(nil, TenantConnConfig{}); err != nil {
		t.Fatalf("single-region binder rejected: %v", err)
	}
}

func TestNewTenantConnBinder_AcceptsBothSet(t *testing.T) {
	t.Parallel()
	if _, err := NewTenantConnBinder(nil, TenantConnConfig{
		Regional: stubRegionalDB(),
		Resolver: stubResolver{},
	}); err != nil {
		t.Fatalf("multi-region binder rejected: %v", err)
	}
}

// TestBindTenant_NoDBReturnsMiddlewareError pins the symmetry-with-
// ServeHTTP guard added in round 5: a single-region binder
// constructed without a DB returns a middleware-level error instead
// of relying on (*postgres.DB).WithTenant's nil-receiver handling.
// ServeHTTP passes through unbound on the same misconfig (the right
// behaviour for HTTP middleware in dev / test wiring); BindTenant
// has no "pass through" notion — callers asking for a bound conn
// either get one or a clear, middleware-level error naming the
// missing-DB misconfig.
func TestBindTenant_NoDBReturnsMiddlewareError(t *testing.T) {
	t.Parallel()

	b, err := NewTenantConnBinder(nil, TenantConnConfig{})
	if err != nil {
		t.Fatalf("NewTenantConnBinder(no DB) returned err=%v; want construction to succeed", err)
	}
	ctx, release, berr := b.BindTenant(context.Background(), "tenant-1")
	if berr == nil {
		t.Fatal("BindTenant on no-DB binder returned err=nil; want middleware-level error")
	}
	if !strings.Contains(berr.Error(), "no DB configured") {
		t.Fatalf("err = %q; want middleware-level missing-DB error", berr.Error())
	}
	if ctx == nil {
		t.Fatal("BindTenant returned ctx=nil; want input ctx echoed back")
	}
	if release == nil {
		t.Fatal("BindTenant returned release=nil; release must be non-nil on every error path")
	}
	if relErr := release(); relErr != nil {
		t.Fatalf("noop release() returned err=%v, want nil", relErr)
	}
}
