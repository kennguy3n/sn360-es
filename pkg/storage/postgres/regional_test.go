package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// fakeRegionalDB returns a *DB backed by the fake driver — same
// pattern used by tenant_context_test.go. Suitable for any RegionalDB
// test that only needs sentinel *DB identity (constructor checks,
// Regions ordering, DBForRegion lookup); tests that need real queries
// live in the integration test under the `integration` build tag.
func fakeRegionalDB(t *testing.T) *DB {
	t.Helper()
	sqlDB := sql.OpenDB(fakeConnector{})
	t.Cleanup(func() { _ = sqlDB.Close() })
	return &DB{sqlDB: sqlDB, driver: "fake"}
}

// TestNewRegionalDB_RejectsNilPrimary covers the contract that the
// wiring layer must always supply a primary *DB. A nil primary would
// strand the home region with no pool — silently failing every
// home-region request later.
func TestNewRegionalDB_RejectsNilPrimary(t *testing.T) {
	t.Parallel()
	_, err := NewRegionalDB("ap-southeast-1", nil, nil)
	if err == nil {
		t.Fatal("expected error for nil primary, got nil")
	}
}

// TestNewRegionalDB_RejectsEmptyHomeRegion: an empty home region label
// is unrecoverable — the resolver cannot answer "which pool serves
// tenants flagged home?" and the regional router would silently fail
// closed at every request.
func TestNewRegionalDB_RejectsEmptyHomeRegion(t *testing.T) {
	t.Parallel()
	primary := fakeRegionalDB(t)
	_, err := NewRegionalDB("", primary, nil)
	if err == nil {
		t.Fatal("expected error for empty home region, got nil")
	}
}

// TestNewRegionalDB_RejectsHomeInExtras pins the WS-7a "don't double-
// open the home host" contract. Putting the home region in extras
// would burn a second pool against the same physical Postgres, with
// no upside other than a misleading boot log.
func TestNewRegionalDB_RejectsHomeInExtras(t *testing.T) {
	t.Parallel()
	primary := fakeRegionalDB(t)
	extras := map[string]*DB{
		"ap-southeast-1": fakeRegionalDB(t),
	}
	_, err := NewRegionalDB("ap-southeast-1", primary, extras)
	if err == nil {
		t.Fatal("expected error when extras contains home region, got nil")
	}
	if !strings.Contains(err.Error(), "ap-southeast-1") {
		t.Fatalf("error %q must name the offending region", err)
	}
}

// TestNewRegionalDB_RejectsNilExtraDB: a nil regional *DB means the
// wiring layer skipped (or failed to detect) a failed pool open.
// NewRegionalDB MUST refuse rather than register a nil pool that
// would crash on first use.
func TestNewRegionalDB_RejectsNilExtraDB(t *testing.T) {
	t.Parallel()
	primary := fakeRegionalDB(t)
	_, err := NewRegionalDB("ap-southeast-1", primary, map[string]*DB{
		"us-east-1": nil,
	})
	if err == nil {
		t.Fatal("expected error for nil regional *DB, got nil")
	}
	if !strings.Contains(err.Error(), "us-east-1") {
		t.Fatalf("error %q must name the offending region", err)
	}
}

// TestRegionalDB_RegionsAndDBForRegion: the happy-path API surface
// (Regions / DBForRegion / HasRegion / HomeRegion). Regions must
// return a lexicographically sorted slice for stable boot logs.
func TestRegionalDB_RegionsAndDBForRegion(t *testing.T) {
	t.Parallel()
	primary := fakeRegionalDB(t)
	use1 := fakeRegionalDB(t)
	euw1 := fakeRegionalDB(t)
	r, err := NewRegionalDB("ap-southeast-1", primary, map[string]*DB{
		"us-east-1": use1,
		"eu-west-1": euw1,
	})
	if err != nil {
		t.Fatalf("NewRegionalDB: %v", err)
	}
	if r.HomeRegion() != "ap-southeast-1" {
		t.Fatalf("HomeRegion = %q, want ap-southeast-1", r.HomeRegion())
	}
	got := r.Regions()
	want := []string{"ap-southeast-1", "eu-west-1", "us-east-1"}
	if len(got) != len(want) {
		t.Fatalf("Regions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Regions[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if r.DBForRegion("us-east-1") != use1 {
		t.Fatal("DBForRegion(us-east-1) should return the us-east-1 *DB")
	}
	if r.DBForRegion("ap-southeast-1") != primary {
		t.Fatal("DBForRegion(home) should return the primary *DB (no double open)")
	}
	if r.DBForRegion("nowhere-1") != nil {
		t.Fatal("DBForRegion(unknown) must return nil so callers fail closed")
	}
	if !r.HasRegion("eu-west-1") {
		t.Fatal("HasRegion(eu-west-1) = false, want true")
	}
	if r.HasRegion("nowhere-1") {
		t.Fatal("HasRegion(unknown) = true, want false")
	}
}

// TestRegionalDB_WithTenantInRegion_UnknownRegion exercises the fail-
// closed path: WithTenantInRegion for an unknown region must error
// without acquiring a connection. Silently falling back to the home
// pool here would defeat the data-residency contract the region map
// encodes.
func TestRegionalDB_WithTenantInRegion_UnknownRegion(t *testing.T) {
	t.Parallel()
	primary := fakeRegionalDB(t)
	r, err := NewRegionalDB("ap-southeast-1", primary, nil)
	if err != nil {
		t.Fatalf("NewRegionalDB: %v", err)
	}
	_, release, err := r.WithTenantInRegion(context.Background(), "us-east-1", "tnt-1")
	if err == nil {
		t.Fatal("expected error for unknown region, got nil")
	}
	if release == nil {
		t.Fatal("release must be non-nil even on error so callers can defer release()")
	}
	if !strings.Contains(err.Error(), "us-east-1") {
		t.Fatalf("error %q must name the requested region", err)
	}
}

// TestRegionalDB_WithTenantInRegion_EmptyRegion guards the programmer-
// bug case where the resolver returned an empty region string. The
// router must refuse rather than route to the home region (the empty
// string would otherwise hash to no entry in byRegion and produce a
// misleading "unknown region" error).
func TestRegionalDB_WithTenantInRegion_EmptyRegion(t *testing.T) {
	t.Parallel()
	primary := fakeRegionalDB(t)
	r, err := NewRegionalDB("ap-southeast-1", primary, nil)
	if err != nil {
		t.Fatalf("NewRegionalDB: %v", err)
	}
	_, _, err = r.WithTenantInRegion(context.Background(), "", "tnt-1")
	if err == nil {
		t.Fatal("expected error for empty region, got nil")
	}
}

// TestRegionalDB_Close_DoesNotClosePrimary pins the lifecycle
// contract: Close MUST NOT close the primary *DB (its lifecycle is
// owned by the wiring layer). Closing it here would prematurely
// invalidate the primary pool the rest of the application still
// holds — every subsequent unbound query would fail.
func TestRegionalDB_Close_DoesNotClosePrimary(t *testing.T) {
	t.Parallel()
	primary := fakeRegionalDB(t)
	use1 := fakeRegionalDB(t)
	r, err := NewRegionalDB("ap-southeast-1", primary, map[string]*DB{
		"us-east-1": use1,
	})
	if err != nil {
		t.Fatalf("NewRegionalDB: %v", err)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
	// After Close the primary's underlying *sql.DB must still be
	// usable (PingContext returns the fake driver's error but
	// does NOT return sql.ErrConnDone — that's the marker we'd
	// see if the pool had been closed).
	if err := primary.sqlDB.PingContext(context.Background()); err != nil {
		if strings.Contains(err.Error(), "closed") {
			t.Fatalf("Close prematurely closed the primary pool: %v", err)
		}
	}
}
