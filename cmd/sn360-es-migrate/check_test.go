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
