//go:build integration
// +build integration

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

// applyMigrationsThrough0018 loads every migrations/<NNNN>_*.up.sql
// in numeric order up to and including 0018 and executes them in one
// transaction-per-file. The integration suite previously only applied
// 0001_init; once the RLS policy lands in 0018 we have to layer all
// schema-evolution migrations in between or the FKs / tables /
// columns the policy references don't exist yet.
//
// Migration 0017 partitions some append-only tables; we apply it as
// well so the RLS policies attach to the *partitioned* parents
// (which is the form they'll have in production).
//
// rlsTestRole is the non-superuser login role we create for the RLS
// integration tests. Postgres BYPASSes RLS for superusers and for
// the table owner *unless* FORCE is set — FORCE handles the owner
// case but NOT the superuser case. The testcontainer's default
// user is a superuser, so an end-to-end RLS test must use a
// dedicated non-superuser role; that mirrors the production
// topology where the app connects as a login role that inherits
// `sn360_app` (NOLOGIN, non-superuser) and the policy is the only
// thing standing between one tenant and another's rows.
const (
	rlsTestRole     = "rls_test_user"
	rlsTestPassword = "rls_test_user"
)

// provisionRLSTestRole runs as the superuser pg conn `admin` and
// creates the non-superuser login role used by every subsequent
// RLS query in this file. The role is granted enough privilege to
// SELECT/INSERT/UPDATE every public table (matching the production
// connect role's effective grants) so the only thing constraining
// what it can read is the RLS policy itself. Returns a postgres.Config
// pointing at the same database, but with the new role's
// credentials substituted in.
func provisionRLSTestRole(t *testing.T, admin *postgres.DB, base postgres.Config) postgres.Config {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stmts := []string{
		fmt.Sprintf(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN CREATE ROLE %s LOGIN PASSWORD '%s'; END IF; END $$;`,
			rlsTestRole, rlsTestRole, rlsTestPassword),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, rlsTestRole),
		fmt.Sprintf(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s`, rlsTestRole),
		fmt.Sprintf(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %s`, rlsTestRole),
		fmt.Sprintf(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s`, rlsTestRole),
	}
	for _, s := range stmts {
		if _, err := admin.ExecContext(ctx, s); err != nil {
			t.Fatalf("provision rls role (%q): %v", s, err)
		}
	}
	out := base
	out.User = rlsTestRole
	out.Password = rlsTestPassword
	return out
}

// openRLSTestDB starts a fresh Postgres, applies migrations 0001-0018
// as the superuser, provisions a non-superuser login, and opens a
// second handle as that login. Returns the non-superuser handle and
// a cleanup func that closes both handles. RLS tests must use this
// rather than `startPG` + `postgres.Open` directly because Postgres
// silently bypasses RLS for superusers.
func openRLSTestDB(t *testing.T) (appDB *postgres.DB, cleanup func()) {
	t.Helper()
	cfg := startPG(t)
	admin, err := postgres.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	applyMigrationsThrough0018(t, admin)
	appCfg := provisionRLSTestRole(t, admin, cfg)
	appDB, err = postgres.Open(context.Background(), appCfg)
	if err != nil {
		_ = admin.Close()
		t.Fatalf("open as rls role: %v", err)
	}
	return appDB, func() {
		_ = appDB.Close()
		_ = admin.Close()
	}
}

func applyMigrationsThrough0018(t *testing.T, db *postgres.DB) {
	t.Helper()
	wd, _ := os.Getwd()
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	migDir := filepath.Join(root, "migrations")
	entries, err := os.ReadDir(migDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var ups []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		// Only apply 0001 through 0018; later migrations may
		// not yet exist on a feature branch and shouldn't gate
		// this RLS test.
		if name < "0001" || name > "0018_zzzz.up.sql" {
			continue
		}
		ups = append(ups, name)
	}
	sort.Strings(ups)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, name := range ups {
		body, err := os.ReadFile(filepath.Join(migDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := db.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

// insertTenant directly inserts a row into tenants (which is NOT
// itself RLS-protected — tenants is the per-tenant registry). The
// caller is responsible for the UUID.
func insertTenant(t *testing.T, db *postgres.DB, ctx context.Context, name string) string {
	t.Helper()
	id := uuid.NewString()
	_, err := db.ExecContext(ctx, `
		INSERT INTO tenants (
			id, name, display_name, provider, primary_domain,
			region, kms_key_arn, status, created_at
		)
		VALUES (
			$1, $2, $2, 'gws', $2 || '.example.com',
			'us-east-1', 'arn:aws:kms:test:000000000000:key/rls-test', 'active', now()
		)`,
		id, name)
	if err != nil {
		t.Fatalf("insert tenant %q: %v", name, err)
	}
	return id
}

// insertEvaluation directly inserts a row into evaluation_results.
// Used here as the canonical "tenant-scoped table" because it has
// the minimum-FK shape (only requires tenant_id + message_id_hash).
// Test runs while a tenant binding is active so the WITH CHECK
// clause of the RLS policy accepts the insert.
func insertEvaluation(t *testing.T, db *postgres.DB, ctx context.Context, tenantID, messageTag string) {
	t.Helper()
	_, err := db.ExecContext(ctx, `
		INSERT INTO evaluation_results (
			tenant_id, message_id_hash, correlation_id,
			score, tier, primary_category, secondary_categories,
			reason_codes, evaluated_at
		)
		VALUES ($1, $2::bytea, $3, 50, 'warning', 'likely_phishing',
			ARRAY['impersonation']::text[],
			ARRAY['lookalike_domain']::text[],
			now())`,
		tenantID, []byte(messageTag), fmt.Sprintf("corr-%s", messageTag))
	if err != nil {
		t.Fatalf("insert evaluation: %v", err)
	}
}

// countEvaluations counts visible evaluation_results rows under the
// current session's RLS scope. We deliberately do NOT pass a
// tenant_id predicate — the policy is the only thing filtering.
func countEvaluations(t *testing.T, db *postgres.DB, ctx context.Context) int {
	t.Helper()
	var n int
	row := db.QueryRowContext(ctx, `SELECT count(*) FROM evaluation_results`)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count evaluations: %v", err)
	}
	return n
}

// TestRLS_BlocksCrossTenantReads is the load-bearing RLS test. It
// proves three properties of the 0018 migration end-to-end:
//
//  1. A session with `sn360.tenant_id = $TENANT_A` sees only tenant
//     A's rows when SELECTing from a tenant-scoped table — even
//     when the SQL itself has no tenant_id predicate.
//  2. The cross-tenant escape hatch (`WithCrossTenant`) makes both
//     tenants visible in the same SELECT.
//  3. A session with no tenant binding at all sees zero rows
//     (fail closed) — the GUC defaults to NULL and the policy's
//     OR-clause does not match.
func TestRLS_BlocksCrossTenantReads(t *testing.T) {
	db, cleanup := openRLSTestDB(t)
	defer cleanup()

	rootCtx := context.Background()

	// Seed two tenants with one evaluation each. Seeding has to
	// happen inside the appropriate tenant binding so the
	// WITH CHECK predicate accepts the INSERT.
	tenantA := insertTenant(t, db, rootCtx, "tenant-a")
	tenantB := insertTenant(t, db, rootCtx, "tenant-b")

	ctxA, releaseA, err := db.WithTenant(rootCtx, tenantA)
	if err != nil {
		t.Fatalf("with tenant A: %v", err)
	}
	insertEvaluation(t, db, ctxA, tenantA, "hashAAAAAAAAAAAAAAAA")
	if err := releaseA(); err != nil {
		t.Fatalf("release A: %v", err)
	}

	ctxB, releaseB, err := db.WithTenant(rootCtx, tenantB)
	if err != nil {
		t.Fatalf("with tenant B: %v", err)
	}
	insertEvaluation(t, db, ctxB, tenantB, "hashBBBBBBBBBBBBBBBB")
	if err := releaseB(); err != nil {
		t.Fatalf("release B: %v", err)
	}

	// Property 1: tenant A scope sees one row.
	ctxA2, releaseA2, err := db.WithTenant(rootCtx, tenantA)
	if err != nil {
		t.Fatalf("with tenant A: %v", err)
	}
	if n := countEvaluations(t, db, ctxA2); n != 1 {
		t.Errorf("tenant A scope expected 1 visible row, got %d", n)
	}
	if err := releaseA2(); err != nil {
		t.Fatalf("release A2: %v", err)
	}

	// Property 1 (parity): tenant B scope sees one row.
	ctxB2, releaseB2, err := db.WithTenant(rootCtx, tenantB)
	if err != nil {
		t.Fatalf("with tenant B: %v", err)
	}
	if n := countEvaluations(t, db, ctxB2); n != 1 {
		t.Errorf("tenant B scope expected 1 visible row, got %d", n)
	}
	if err := releaseB2(); err != nil {
		t.Fatalf("release B2: %v", err)
	}

	// Property 2: cross-tenant scope sees both rows.
	crossCtx, releaseCross, err := db.WithCrossTenant(rootCtx)
	if err != nil {
		t.Fatalf("with cross tenant: %v", err)
	}
	if n := countEvaluations(t, db, crossCtx); n != 2 {
		t.Errorf("cross-tenant scope expected 2 visible rows, got %d", n)
	}
	if err := releaseCross(); err != nil {
		t.Fatalf("release cross: %v", err)
	}

	// Property 3: unbound session sees zero rows (fail closed).
	// We use the pool conn directly via QueryRowContext with no
	// WithTenant / WithCrossTenant binding.
	if n := countEvaluations(t, db, rootCtx); n != 0 {
		t.Errorf("unbound scope expected 0 visible rows (RLS fail-closed); got %d", n)
	}
}

// TestRLS_BlocksCrossTenantWrites verifies the WITH CHECK half of
// the policy: an INSERT or UPDATE that would plant a row under a
// different tenant's UUID must be rejected. This catches a class of
// bug where the app accidentally constructs the tenant_id from
// user-supplied input.
func TestRLS_BlocksCrossTenantWrites(t *testing.T) {
	db, cleanup := openRLSTestDB(t)
	defer cleanup()

	rootCtx := context.Background()
	tenantA := insertTenant(t, db, rootCtx, "tenant-a")
	tenantB := insertTenant(t, db, rootCtx, "tenant-b")

	// Bind tenant A and try to insert under tenant B's ID. The
	// row's tenant_id ($1) does not match the session's GUC, so
	// WITH CHECK rejects the row.
	ctxA, release, err := db.WithTenant(rootCtx, tenantA)
	if err != nil {
		t.Fatalf("with tenant A: %v", err)
	}
	defer func() { _ = release() }()

	_, err = db.ExecContext(ctxA, `
		INSERT INTO evaluation_results (
			tenant_id, message_id_hash, correlation_id,
			score, tier, primary_category, secondary_categories,
			reason_codes, evaluated_at
		)
		VALUES ($1, $2::bytea, 'corr-x', 50, 'warning', 'likely_phishing',
			ARRAY['impersonation']::text[],
			ARRAY['lookalike_domain']::text[],
			now())`,
		tenantB, []byte("cross-tenant-write-probe"))
	if err == nil {
		t.Fatal("expected RLS WITH CHECK to reject cross-tenant insert; got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "row-level security") &&
		!strings.Contains(strings.ToLower(err.Error()), "row level security") {
		t.Fatalf("expected RLS rejection message, got: %v", err)
	}
}

// TestRLS_UnboundSessionFailsClosed is the most important guarantee
// of the policy: a Postgres session that never called WithTenant or
// WithCrossTenant returns zero rows from a tenant-scoped table, not
// every row. A regression here would silently expose data.
func TestRLS_UnboundSessionFailsClosed(t *testing.T) {
	db, cleanup := openRLSTestDB(t)
	defer cleanup()

	rootCtx := context.Background()
	tenantA := insertTenant(t, db, rootCtx, "tenant-a")
	ctxA, release, err := db.WithTenant(rootCtx, tenantA)
	if err != nil {
		t.Fatalf("with tenant A: %v", err)
	}
	insertEvaluation(t, db, ctxA, tenantA, "hashAAAAAAAAAAAAAAAA")
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	// Unbound SELECT directly via the pool conn — no
	// WithTenant / WithCrossTenant. The policy's NULL-safe
	// `current_setting(name, true)` returns NULL, the equality
	// check returns NULL (which is not TRUE), and the OR-clause
	// for cross-tenant also returns NULL. The policy never
	// admits the row.
	var n int
	if err := db.QueryRowContext(rootCtx, `SELECT count(*) FROM evaluation_results`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("unbound SELECT must fail closed; got %d row(s)", n)
	}
}
