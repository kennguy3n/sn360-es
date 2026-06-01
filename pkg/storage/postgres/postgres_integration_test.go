//go:build integration
// +build integration

package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/pkg/storage/postgres"
)

func startPG(t *testing.T) postgres.Config {
	t.Helper()
	ctx := context.Background()
	c, err := tcpg.Run(ctx, "postgres:16-alpine",
		tcpg.WithDatabase("sn360es"),
		tcpg.WithUsername("sn360es"),
		tcpg.WithPassword("sn360es"),
		tcpg.BasicWaitStrategies(),
	)
	if err != nil {
		if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "docker") {
			t.Skipf("docker not available, skipping: %v", err)
		}
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "5432/tcp")
	portNum, err := strconv.Atoi(port.Port())
	if err != nil {
		t.Fatalf("parse port %q: %v", port.Port(), err)
	}
	return postgres.Config{
		Host:     host,
		Port:     portNum,
		User:     "sn360es",
		Password: "sn360es",
		Database: "sn360es",
		SSLMode:  "disable",
	}
}

// applyMigrations loads every migrations/NNNN_*.up.sql file in
// lexicographic order and executes it against the live database. We
// deliberately do not depend on golang-migrate here so this test
// stays decoupled from the migration runner; integration coverage of
// the runner itself lives in cmd/sn360-es-migrate. Applying the full
// chain (not just 0001) keeps the in-test schema in lockstep with the
// pgEvalResults / pgCommHistories backends, both of which evolve
// across migrations (e.g. 0020 adds sender_hash / recipient_hash and
// the column is referenced unconditionally by the INSERT path).
func applyMigrations(t *testing.T, db *postgres.DB) {
	t.Helper()
	wd, _ := os.Getwd()
	// repo root is two levels above pkg/storage/postgres.
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	matches, err := filepath.Glob(filepath.Join(root, "migrations", "*.up.sql"))
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no migrations found under %s", filepath.Join(root, "migrations"))
	}
	// Filenames are NNNN_<slug>.up.sql; lexicographic sort gives
	// the same ordering as the migration runner.
	sort.Strings(matches)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for _, path := range matches {
		bytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read migration %s: %v", filepath.Base(path), err)
		}
		if _, err := db.ExecContext(ctx, string(bytes)); err != nil {
			t.Fatalf("apply migration %s: %v", filepath.Base(path), err)
		}
	}
}

func TestPostgresIntegration_OpenAndPing(t *testing.T) {
	cfg := startPG(t)
	db, err := postgres.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if db.Driver() != "pgx" {
		t.Fatalf("driver = %s", db.Driver())
	}
}

func TestPostgresIntegration_MigrationsCreateSchema(t *testing.T) {
	cfg := startPG(t)
	db, err := postgres.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	applyMigrations(t, db)

	// Sanity: every table the audit references should be present.
	for _, tbl := range []string{
		"tenants", "users", "groups", "labels", "score_engine",
		"email_classifications", "vendors", "evaluation_results",
		"communication_histories", "campaigns", "simulation_results",
		"escalation_tickets", "audit_logs",
	} {
		var n int
		if err := db.QueryRowContext(context.Background(),
			"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=$1",
			tbl,
		).Scan(&n); err != nil {
			t.Fatalf("query %s: %v", tbl, err)
		}
		if n != 1 {
			t.Fatalf("table %q missing after migrations", tbl)
		}
	}
}

func TestPostgresIntegration_TenantRepositoryCRUD(t *testing.T) {
	cfg := startPG(t)
	db, err := postgres.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	applyMigrations(t, db)

	reg := repository.NewPostgresRegistry(db)
	ctx := context.Background()

	tenant := &repository.Tenant{
		Name:          "acme",
		DisplayName:   "Acme",
		Provider:      "gws",
		PrimaryDomain: "acme.test",
		Region:        "ap-southeast-1",
		KMSKeyARN:     "arn:aws:kms:ap-southeast-1:000:key/test",
		ScoreBase:     100,
		RetentionDays: 30,
		Locale:        "en",
		Status:        "active",
		Metadata:      map[string]string{"sla": "gold"},
	}
	if err := reg.Tenants.Create(ctx, tenant); err != nil {
		t.Fatalf("create: %v", err)
	}
	if tenant.ID == "" {
		t.Fatal("expected Create to populate ID")
	}

	got, err := reg.Tenants.GetByID(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.Name != "acme" || got.DisplayName != "Acme" || got.Provider != "gws" {
		t.Fatalf("unexpected tenant: %+v", got)
	}
	if got.Metadata["sla"] != "gold" {
		t.Fatalf("metadata round-trip failed: %+v", got.Metadata)
	}

	byName, err := reg.Tenants.GetByName(ctx, "acme")
	if err != nil || byName.ID != tenant.ID {
		t.Fatalf("get by name: %+v err=%v", byName, err)
	}

	// Conflict path: re-creating with same name must yield ErrConflict.
	dup := *tenant
	dup.ID = ""
	if err := reg.Tenants.Create(ctx, &dup); err != repository.ErrConflict {
		t.Fatalf("expected ErrConflict for duplicate name, got %v", err)
	}

	if err := reg.Tenants.UpdateStatus(ctx, tenant.ID, "suspended"); err != nil {
		t.Fatalf("update status: %v", err)
	}
	got, _ = reg.Tenants.GetByID(ctx, tenant.ID)
	if got.Status != "suspended" {
		t.Fatalf("status did not persist: %s", got.Status)
	}

	tenants, err := reg.Tenants.List(ctx, 10)
	if err != nil || len(tenants) != 1 {
		t.Fatalf("list: %v len=%d", err, len(tenants))
	}
}

// TestPostgresIntegration_EvaluationResultCreate exercises the
// evaluation_results table through the repository.
func TestPostgresIntegration_EvaluationResultCreate(t *testing.T) {
	cfg := startPG(t)
	db, err := postgres.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	applyMigrations(t, db)

	reg := repository.NewPostgresRegistry(db)
	ctx := context.Background()

	tenant := &repository.Tenant{
		Name: "tenant-eval", DisplayName: "Eval", Provider: "gws",
		PrimaryDomain: "eval.test", Region: "ap-southeast-1",
		KMSKeyARN: "arn", ScoreBase: 100, RetentionDays: 30, Locale: "en", Status: "active",
	}
	if err := reg.Tenants.Create(ctx, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	hash := []byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")
	now := time.Now().UTC().Truncate(time.Millisecond)
	rec := &repository.EvaluationResult{
		TenantID:      tenant.ID,
		MessageIDHash: hash,
		CorrelationID: "corr-1",
		Score:         77,
		Tier:          "warning",
		Primary:       "likely_phishing",
		Secondary:     []string{"impersonation"},
		ReasonCodes:   []string{"lookalike_domain"},
		EvaluatedAt:   now,
	}
	if err := reg.EvaluationResults.Create(ctx, rec); err != nil {
		t.Fatalf("create eval: %v", err)
	}
	got, err := reg.EvaluationResults.GetByMessageHash(ctx, tenant.ID, hash)
	if err != nil || got == nil {
		t.Fatalf("get eval: %+v err=%v", got, err)
	}
	if got.Score != 77 || got.Tier != "warning" || got.Primary != "likely_phishing" {
		t.Fatalf("unexpected eval result: %+v", got)
	}
}

// TestPostgresIntegration_EvaluationResultCreate_HashColumnVariants pins
// the three SenderHash / RecipientHash input shapes that the producer
// path can hand to the repository through the bytea NULLIF dance in
// pgEvalResults.Create:
//
//	nil       — legacy / pre-WS-3b path; pq sends untyped NULL, but
//	            the `::bytea` cast pins the planner type so OCTET_LENGTH
//	            doesn't fall back to text.
//	[]byte{}  — explicit zero-length; same NULL collapse, different
//	            wire encoding from nil.
//	populated — happy path; round-trips through the partial index.
//
// Without the explicit `::bytea` cast this test fails with SQLSTATE
// 42804 ("column 'sender_hash' is of type bytea but expression is of
// type text") on the nil variant — the planner-inference regression
// caught by Devin Review round 1 / CI integration job 78779842851.
func TestPostgresIntegration_EvaluationResultCreate_HashColumnVariants(t *testing.T) {
	cfg := startPG(t)
	db, err := postgres.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	applyMigrations(t, db)
	reg := repository.NewPostgresRegistry(db)
	ctx := context.Background()
	tenant := &repository.Tenant{
		Name: "tenant-hash-variants", DisplayName: "HashVar", Provider: "gws",
		PrimaryDomain: "hashvar.test", Region: "ap-southeast-1",
		KMSKeyARN: "arn", ScoreBase: 100, RetentionDays: 30, Locale: "en", Status: "active",
	}
	if err := reg.Tenants.Create(ctx, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	cases := []struct {
		name string
		send []byte
		recp []byte
	}{
		{"nil_hashes", nil, nil},
		{"empty_hashes", []byte{}, []byte{}},
		{"populated_hashes",
			[]byte("\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"),
			[]byte("\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00\xff\xee\xdd\xcc\xbb\xaa")},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgHash := []byte{byte(i + 1)}
			rec := &repository.EvaluationResult{
				TenantID:      tenant.ID,
				MessageIDHash: msgHash,
				SenderHash:    tc.send,
				RecipientHash: tc.recp,
				CorrelationID: "corr-" + tc.name,
				Score:         50,
				Tier:          "info",
				Primary:       "neutral",
				Secondary:     []string{},
				ReasonCodes:   []string{},
				EvaluatedAt:   now,
			}
			if err := reg.EvaluationResults.Create(ctx, rec); err != nil {
				t.Fatalf("create %s: %v", tc.name, err)
			}
			got, err := reg.EvaluationResults.GetByMessageHash(ctx, tenant.ID, msgHash)
			if err != nil || got == nil {
				t.Fatalf("get %s: %+v err=%v", tc.name, got, err)
			}
			// Both nil and []byte{} variants persist as SQL NULL, so the
			// read path surfaces them as nil. Only the populated variant
			// echoes back exact bytes — assert that and the empty-collapse
			// invariant separately.
			if len(tc.send) > 0 {
				if string(got.SenderHash) != string(tc.send) {
					t.Errorf("%s: SenderHash round-trip mismatch: got=%x want=%x", tc.name, got.SenderHash, tc.send)
				}
				if string(got.RecipientHash) != string(tc.recp) {
					t.Errorf("%s: RecipientHash round-trip mismatch: got=%x want=%x", tc.name, got.RecipientHash, tc.recp)
				}
			} else {
				if len(got.SenderHash) != 0 {
					t.Errorf("%s: SenderHash should collapse to empty/NULL, got=%x", tc.name, got.SenderHash)
				}
				if len(got.RecipientHash) != 0 {
					t.Errorf("%s: RecipientHash should collapse to empty/NULL, got=%x", tc.name, got.RecipientHash)
				}
			}
		})
	}
}
