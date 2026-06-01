package config

import (
	"strings"
	"testing"
	"time"
)

// TestParsePostgresRegionMap_EmptyReturnsNil is the WS-7a backward
// compatibility contract: when PG_REGION_MAP is unset / empty /
// whitespace-only, parsePostgresRegionMap MUST return a nil map (not
// an empty map) so the downstream consumer in cmd/sn360-es/app.go
// skips the multi-region open loop entirely. A regression here
// would force every existing single-region deployment to also set
// PG_REGION_MAP just to keep booting — exactly what backward
// compatibility forbids.
func TestParsePostgresRegionMap_EmptyReturnsNil(t *testing.T) {
	t.Parallel()

	base := Postgres{MaxOpenConns: 25, MaxIdleConns: 5}
	for _, raw := range []string{"", "   ", "\n\t"} {
		got, err := parsePostgresRegionMap(raw, base)
		if err != nil {
			t.Fatalf("raw=%q: got error %v, want nil", raw, err)
		}
		if got != nil {
			t.Fatalf("raw=%q: got non-nil map %v, want nil", raw, got)
		}
	}
}

// TestParsePostgresRegionMap_InvalidJSON checks the fail-loud contract
// on malformed JSON. The boot must stop with a clear error rather
// than silently fall back to single-region (which would route every
// non-home tenant to the wrong pool).
func TestParsePostgresRegionMap_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := parsePostgresRegionMap(`not-json`, Postgres{})
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "PG_REGION_MAP") {
		t.Fatalf("error %q must namespace itself under PG_REGION_MAP", err)
	}
}

// TestParsePostgresRegionMap_EmptyJSONObject rejects `{}`: an
// operator who explicitly opted into multi-region routing but then
// declared no regions almost certainly made a mistake — we'd rather
// the boot fail loudly than silently route everything through pgDB.
func TestParsePostgresRegionMap_EmptyJSONObject(t *testing.T) {
	t.Parallel()

	_, err := parsePostgresRegionMap(`{}`, Postgres{})
	if err == nil {
		t.Fatal("expected error for empty JSON object, got nil")
	}
	if !strings.Contains(err.Error(), "at least one region") {
		t.Fatalf("error %q should explain the empty-map rejection", err)
	}
}

// TestParsePostgresRegionMap_HappyPath covers the canonical
// multi-region wiring: two regions, each fully populated from its
// URL, both inheriting pool-shape fields from the primary Postgres
// struct.
func TestParsePostgresRegionMap_HappyPath(t *testing.T) {
	t.Parallel()

	base := Postgres{
		Host:            "primary-host",
		Port:            5432,
		User:            "fallback-user",
		Password:        "fallback-pw",
		SSLMode:         "require",
		MaxOpenConns:    37,
		MaxIdleConns:    7,
		ConnMaxLifetime: 11 * time.Minute,
	}
	raw := `{
		"ap-southeast-1": "postgres://ap-user:ap-pw@ap-host:5432/sn360?sslmode=require",
		"us-east-1":      "postgres://use1-user:use1-pw@use1-host:6543/sn360?sslmode=verify-full"
	}`
	got, err := parsePostgresRegionMap(raw, base)
	if err != nil {
		t.Fatalf("parsePostgresRegionMap: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 regions, got %d", len(got))
	}

	ap, ok := got["ap-southeast-1"]
	if !ok {
		t.Fatal("missing ap-southeast-1 entry")
	}
	if ap.Host != "ap-host" || ap.Port != 5432 || ap.User != "ap-user" ||
		ap.Password != "ap-pw" || ap.Database != "sn360" || ap.SSLMode != "require" {
		t.Fatalf("ap-southeast-1: bad connection fields: %+v", ap)
	}
	if ap.MaxOpenConns != base.MaxOpenConns ||
		ap.MaxIdleConns != base.MaxIdleConns ||
		ap.ConnMaxLifetime != base.ConnMaxLifetime {
		t.Fatalf("ap-southeast-1: pool-shape fields not inherited from base: %+v", ap)
	}

	us, ok := got["us-east-1"]
	if !ok {
		t.Fatal("missing us-east-1 entry")
	}
	if us.Port != 6543 || us.SSLMode != "verify-full" {
		t.Fatalf("us-east-1: bad URL decomposition: %+v", us)
	}
}

// TestParsePostgresRegionMap_FallsBackToBase verifies the
// pool-shape-inheritance contract: when the URL omits port, user,
// password, or sslmode the entry must inherit from the base
// (primary) Postgres struct. Operators only have to declare the
// per-region wiring; tuning continues to flow through the existing
// PG_MAX_OPEN_CONNS / PG_PORT / … env vars.
func TestParsePostgresRegionMap_FallsBackToBase(t *testing.T) {
	t.Parallel()

	base := Postgres{
		Host:     "primary-host",
		Port:     5433,
		User:     "fallback-user",
		Password: "fallback-pw",
		SSLMode:  "verify-ca",
	}
	raw := `{"ap-southeast-1": "postgres://ap-host/sn360"}`
	got, err := parsePostgresRegionMap(raw, base)
	if err != nil {
		t.Fatalf("parsePostgresRegionMap: %v", err)
	}
	ap := got["ap-southeast-1"]
	if ap.Port != 5433 || ap.User != "fallback-user" || ap.Password != "fallback-pw" || ap.SSLMode != "verify-ca" {
		t.Fatalf("inheritance failed: %+v", ap)
	}
}

// TestParsePostgresRegionMap_RejectsBadEntries enumerates the
// per-entry failure modes that must be rejected at boot rather than
// at first query. Each case checks both that the error fires and
// that it names the offending region so operators can grep their
// rolling deploy log.
func TestParsePostgresRegionMap_RejectsBadEntries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "non-postgres scheme",
			raw:  `{"ap-southeast-1": "mysql://x@h/db"}`,
			want: "scheme must be postgres",
		},
		{
			name: "missing host",
			raw:  `{"ap-southeast-1": "postgres:///db"}`,
			want: "host must not be empty",
		},
		{
			name: "missing database path",
			raw:  `{"ap-southeast-1": "postgres://host:5432"}`,
			want: "database name",
		},
		{
			name: "port out of range",
			raw:  `{"ap-southeast-1": "postgres://host:99999/db"}`,
			want: "port",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePostgresRegionMap(tc.raw, Postgres{})
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "ap-southeast-1") {
				t.Fatalf("error %q must name the offending region", err)
			}
		})
	}
}

// TestSortedRegionKeys is a tiny but load-bearing assertion: a number
// of error messages and the multi-region open loop rely on
// sortedRegionKeys producing a stable lexicographic order, so this
// guarantee is worth pinning explicitly.
func TestSortedRegionKeys(t *testing.T) {
	t.Parallel()

	got := sortedRegionKeys(map[string]Postgres{
		"us-east-1":      {},
		"ap-southeast-1": {},
		"eu-west-1":      {},
	})
	want := []string{"ap-southeast-1", "eu-west-1", "us-east-1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

// TestParsePostgresRegionMap_RejectsDuplicateAfterTrim pins the
// fail-loud contract on whitespace-padded duplicate region keys.
// Without the guard, the parser would silently overwrite one entry
// with the other (Go's map iteration order is randomised — the
// surviving DSN is non-deterministic), so the operator's intent
// is ambiguous. The right call is to fail boot.
func TestParsePostgresRegionMap_RejectsDuplicateAfterTrim(t *testing.T) {
	t.Parallel()

	const dsn = "postgres://user:pw@host:5432/db?sslmode=require"
	raw := `{"ap-southeast-1": "` + dsn + `", " ap-southeast-1": "` + dsn + `"}`
	_, err := parsePostgresRegionMap(raw, Postgres{})
	if err == nil {
		t.Fatalf("parsePostgresRegionMap() err = nil; want duplicate-region error")
	}
	wantSubstr := `duplicate region key "ap-southeast-1"`
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("error = %q; want substring %q", err.Error(), wantSubstr)
	}
}

// TestValidate_NATSSuperclusterRequiresHomeRegionEntry pins the
// boot-time guard that mirrors the PG_REGION_MAP/PG_HOME_REGION
// invariant: when NATS_SUPERCLUSTER is configured, it must
// contain an entry for the deployment's home region (NATS
// HomeRegion is sourced from Postgres.HomeRegion in
// cmd/sn360-es/wire_infra.go, so the same label drives both
// guards). The check ran inside the NATS client before but is
// now centralised in validate() so the operator catches the
// misconfig before any infrastructure connection is attempted.
func TestValidate_NATSSuperclusterRequiresHomeRegionEntry(t *testing.T) {
	cfg := validProdConfig()
	cfg.Postgres.HomeRegion = "ap-southeast-1"
	cfg.NATS.Supercluster = map[string]string{
		"us-east-1": "nats://us-1:4222",
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("validate() must reject NATS_SUPERCLUSTER without home-region entry")
	}
	if !strings.Contains(err.Error(), "NATS_SUPERCLUSTER must contain an entry for PG_HOME_REGION") {
		t.Fatalf("error = %q; want NATS supercluster home-region complaint", err.Error())
	}
}

// TestValidate_NATSSuperclusterEmptyIsOK confirms the guard is a
// no-op for single-region deployments (the default). Without
// this test a future tightening could accidentally make the
// validator demand an empty-NATS_SUPERCLUSTER deployment carry
// a home-region entry it does not need.
func TestValidate_NATSSuperclusterEmptyIsOK(t *testing.T) {
	cfg := validProdConfig()
	cfg.Postgres.HomeRegion = "ap-southeast-1"
	cfg.NATS.Supercluster = nil
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate() must accept empty NATS_SUPERCLUSTER; got %v", err)
	}
}
