package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestViolates exercises the predicate-presence logic in isolation,
// independent of the AST walker. Each case is a (sql, table) pair plus
// the expected result. The cases double as the canonical specification
// of what the analyser will and will not flag — adding a new case is
// the right way to encode a new permitted SQL shape.
func TestViolates(t *testing.T) {
	cases := []struct {
		name   string
		sql    string
		table  string
		expect bool // true = violates
	}{
		{
			name:   "SELECT with tenant_id passes",
			sql:    "SELECT id FROM users WHERE tenant_id = $1",
			table:  "users",
			expect: false,
		},
		{
			name:   "SELECT without tenant_id violates",
			sql:    "SELECT id FROM users WHERE email = $1",
			table:  "users",
			expect: true,
		},
		{
			name:   "UPDATE with tenant_id passes",
			sql:    "UPDATE vendors SET display_name = $1 WHERE tenant_id = $2 AND id = $3",
			table:  "vendors",
			expect: false,
		},
		{
			name:   "UPDATE without tenant_id violates",
			sql:    "UPDATE vendors SET display_name = $1 WHERE id = $2",
			table:  "vendors",
			expect: true,
		},
		{
			name:   "DELETE with tenant_id passes",
			sql:    "DELETE FROM oauth_tokens WHERE tenant_id = $1 AND provider = $2",
			table:  "oauth_tokens",
			expect: false,
		},
		{
			name:   "DELETE without tenant_id violates",
			sql:    "DELETE FROM oauth_tokens WHERE provider = $1",
			table:  "oauth_tokens",
			expect: true,
		},
		{
			name:   "INSERT with tenant_id in col list passes",
			sql:    "INSERT INTO audit_logs (tenant_id, action, actor) VALUES ($1, $2, $3)",
			table:  "audit_logs",
			expect: false,
		},
		{
			name:   "INSERT missing tenant_id col violates",
			sql:    "INSERT INTO audit_logs (action, actor) VALUES ($1, $2)",
			table:  "audit_logs",
			expect: true,
		},
		{
			name:   "INSERT INTO non-scoped table is not checked",
			sql:    "INSERT INTO email_classifications (domain, classification) VALUES ($1, $2)",
			table:  "users", // SELECT against users would still flag but this is INSERT
			expect: false,   // INSERT target is email_classifications (not scoped)
		},
		{
			// Regression: INSERT INTO <non-scoped> SELECT FROM <scoped>
			// without a tenant filter was the blind spot Devin Review
			// flagged. Rows from every tenant would flow into a
			// shared table — exactly what tenant-lint is meant to
			// prevent.
			name:   "INSERT...SELECT FROM scoped table without tenant_id violates",
			sql:    "INSERT INTO email_classifications (domain) SELECT email FROM users",
			table:  "users",
			expect: true,
		},
		{
			name:   "INSERT...SELECT FROM scoped table with tenant_id passes",
			sql:    "INSERT INTO export_jobs (domain) SELECT email FROM users WHERE tenant_id = $1",
			table:  "users",
			expect: false,
		},
		{
			name:   "INSERT...SELECT FROM scoped into scoped with tenant_id col passes",
			sql:    "INSERT INTO audit_logs (tenant_id, action) SELECT tenant_id, 'export' FROM users WHERE tenant_id = $1",
			table:  "users",
			expect: false,
		},
		{
			name:   "tenant_id IN clause is accepted",
			sql:    "SELECT * FROM groups WHERE tenant_id IN ($1, $2)",
			table:  "groups",
			expect: false,
		},
		{
			name:   "tenant_id with cast accepted",
			sql:    "SELECT * FROM groups WHERE tenant_id::text = $1",
			table:  "groups",
			expect: false,
		},
		{
			name:   "JOIN inheriting tenant_id from outer query",
			sql:    "SELECT u.id FROM users u JOIN groups g ON u.tenant_id = g.tenant_id WHERE u.tenant_id = $1",
			table:  "groups",
			expect: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, got := violates(tc.sql, tc.table)
			if got != tc.expect {
				t.Fatalf("violates(%q,%q) = (%v,%q) want %v", tc.sql, tc.table, got, reason, tc.expect)
			}
		})
	}
}

// TestScanFile_DetectsAndExempts builds a tiny in-memory Go source
// file containing both a deliberately-bad query (missing predicate)
// and a deliberately-cross-tenant query annotated with the exemption.
// The analyser must flag exactly one violation: the bad query.
func TestScanFile_DetectsAndExempts(t *testing.T) {
	src := `package x

import "context"

type DB interface {
	ExecContext(context.Context, string, ...any) (any, error)
}

func bad(db DB, ctx context.Context) {
	_, _ = db.ExecContext(ctx, ` + "`SELECT id FROM users WHERE email = $1`" + `, "a")
}

func ok(db DB, ctx context.Context) {
	_, _ = db.ExecContext(ctx, ` + "`SELECT id FROM users WHERE tenant_id = $1`" + `, "t")
}

func crossTenantOK(db DB, ctx context.Context) {
	// tenant-lint:cross-tenant — boot-time enumeration of every tenant's tokens.
	_, _ = db.ExecContext(ctx, ` + "`SELECT tenant_id, provider FROM oauth_tokens ORDER BY created_at`" + `)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := scanFile(fset, f)
	if len(got) != 1 {
		for _, v := range got {
			t.Logf("violation: %s:%d table=%s stmt=%s reason=%s",
				v.pos.Filename, v.pos.Line, v.table, v.stmt, v.reason)
		}
		t.Fatalf("expected exactly 1 violation, got %d", len(got))
	}
	if got[0].table != "users" || !strings.Contains(got[0].sql, "email = $1") {
		t.Fatalf("wrong violation: table=%s sql=%s", got[0].table, got[0].sql)
	}
}

// TestCollectExemptionLines_OnlyHonoursAnnotatedComments verifies that
// a regular doc-comment without the marker does NOT exempt the line.
func TestCollectExemptionLines_OnlyHonoursAnnotatedComments(t *testing.T) {
	src := `package x

import "context"

type DB interface {
	ExecContext(context.Context, string, ...any) (any, error)
}

func notExempt(db DB, ctx context.Context) {
	// This comment is just a regular doc comment; it does NOT exempt the SQL.
	_, _ = db.ExecContext(ctx, ` + "`SELECT id FROM users WHERE email = $1`" + `, "a")
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := scanFile(fset, f)
	if len(got) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(got))
	}
}

// TestCollectExemptionLines_RequiresJustification rejects an
// annotation that is missing its trailing justification text.
func TestCollectExemptionLines_RequiresJustification(t *testing.T) {
	if crossTenantAnnotation.MatchString("// tenant-lint:cross-tenant") {
		t.Fatal("bare annotation must require justification text")
	}
	if !crossTenantAnnotation.MatchString("// tenant-lint:cross-tenant — boot-time enumeration") {
		t.Fatal("annotation with em-dash justification must match")
	}
	if !crossTenantAnnotation.MatchString("// tenant-lint:cross-tenant - hyphen justification") {
		t.Fatal("annotation with hyphen justification must match")
	}
	if !crossTenantAnnotation.MatchString("// tenant-lint:cross-tenant: colon justification") {
		t.Fatal("annotation with colon justification must match")
	}
}
