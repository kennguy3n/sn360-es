package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMigration(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestCheckMigrations_OK(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0001_init.up.sql", "BEGIN;\nCREATE TABLE t (id INT);\nCOMMIT;\n")
	writeMigration(t, dir, "0001_init.down.sql", "BEGIN;\nDROP TABLE t;\nCOMMIT;\n")
	if err := checkMigrations(dir); err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
}

func TestCheckMigrations_MissingDown(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0001_init.up.sql", "BEGIN;\nCREATE TABLE t (id INT);\nCOMMIT;\n")
	err := checkMigrations(dir)
	if err == nil || !strings.Contains(err.Error(), "missing .down.sql") {
		t.Fatalf("expected missing-down error, got: %v", err)
	}
}

func TestCheckMigrations_BadFilename(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "init.sql", "SELECT 1;\n")
	err := checkMigrations(dir)
	if err == nil || !strings.Contains(err.Error(), "filename does not match") {
		t.Fatalf("expected filename error, got: %v", err)
	}
}

func TestCheckMigrations_NonContiguous(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0001_a.up.sql", "SELECT 1;\n")
	writeMigration(t, dir, "0001_a.down.sql", "SELECT 1;\n")
	writeMigration(t, dir, "0003_c.up.sql", "SELECT 1;\n")
	writeMigration(t, dir, "0003_c.down.sql", "SELECT 1;\n")
	err := checkMigrations(dir)
	if err == nil || !strings.Contains(err.Error(), "non-contiguous version") {
		t.Fatalf("expected non-contiguous error, got: %v", err)
	}
}

func TestCheckMigrations_UnbalancedTransaction(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0001_init.up.sql", "BEGIN;\nCREATE TABLE t (id INT);\n")
	writeMigration(t, dir, "0001_init.down.sql", "BEGIN;\nDROP TABLE t;\nCOMMIT;\n")
	err := checkMigrations(dir)
	if err == nil || !strings.Contains(err.Error(), "unbalanced BEGIN/COMMIT") {
		t.Fatalf("expected unbalanced error, got: %v", err)
	}
}

// TestCheckMigrations_TransactionTokensInCommentsAndStrings ensures the
// BEGIN/COMMIT balance check ignores tokens that live inside line
// comments, block comments, or single-quoted string literals. The
// previous implementation counted naively against the upper-cased
// source and would flag this file as unbalanced even though the only
// real transaction is the outer BEGIN; … COMMIT;.
func TestCheckMigrations_TransactionTokensInCommentsAndStrings(t *testing.T) {
	dir := t.TempDir()
	body := `-- This comment mentions BEGIN; and COMMIT; which must be ignored.
/* Block comment also says BEGIN; / COMMIT; */
BEGIN;
INSERT INTO log (msg) VALUES ('a message that contains BEGIN; and COMMIT;');
INSERT INTO log (msg) VALUES ('escaped '' single quote, still inside string BEGIN;');
COMMIT;
`
	writeMigration(t, dir, "0001_init.up.sql", body)
	writeMigration(t, dir, "0001_init.down.sql", "BEGIN;\nDROP TABLE log;\nCOMMIT;\n")
	if err := checkMigrations(dir); err != nil {
		t.Fatalf("expected ok with tokens in comments/strings, got: %v", err)
	}
}

// TestStripSQLNoise_KillsCommentsAndStrings is a unit test for the
// helper that powers TestCheckMigrations_TransactionTokensInCommentsAndStrings.
// It pins the exact stripping rules so future changes to the helper
// cannot silently re-introduce the false-positive regression.
func TestStripSQLNoise_KillsCommentsAndStrings(t *testing.T) {
	input := `-- BEGIN; COMMIT;
SELECT 1; /* BEGIN; */ INSERT INTO t (x) VALUES ('BEGIN;');
COMMIT;`
	got := stripSQLNoise(input)
	if strings.Contains(strings.ToUpper(got), "BEGIN;") {
		// Find which BEGIN; survived to help debugging.
		idx := strings.Index(strings.ToUpper(got), "BEGIN;")
		t.Fatalf("BEGIN; should not survive stripping; index=%d stripped=%q", idx, got)
	}
	if !strings.Contains(strings.ToUpper(got), "COMMIT;") {
		t.Fatalf("the real COMMIT; on the last line must survive; stripped=%q", got)
	}
}

func TestCheckMigrations_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := checkMigrations(dir)
	if err == nil || !strings.Contains(err.Error(), "no migration files") {
		t.Fatalf("expected empty-dir error, got: %v", err)
	}
}

func TestCheckMigrations_RepoFixturePasses(t *testing.T) {
	// The repository's own migrations directory should always pass
	// `make migrate-check`. Locate it relative to this file so the
	// test works whether invoked from the package or the repo root.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := wd
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(root, "migrations", "0001_init.up.sql")); err == nil {
			break
		}
		root = filepath.Dir(root)
	}
	if _, err := os.Stat(filepath.Join(root, "migrations", "0001_init.up.sql")); err != nil {
		t.Skipf("could not locate repo migrations directory from %q", wd)
	}
	if err := checkMigrations(filepath.Join(root, "migrations")); err != nil {
		t.Fatalf("repo migrations failed check: %v", err)
	}
}
